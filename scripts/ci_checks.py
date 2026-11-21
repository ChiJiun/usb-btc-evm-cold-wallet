"""CI change-scope selection and required-status checks.

Keep these rules testable independently of GitHub Actions. All errors in
comparison result in full validation rather than skipping a security check.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Scope:
    code: bool
    deps: bool
    metadata: bool
    node: bool


FULL = Scope(code=True, deps=True, metadata=False, node=True)
SCHEDULED = Scope(code=False, deps=True, metadata=False, node=True)


def is_document(path: str) -> bool:
    return (
        path == "README"
        or path == "SECURITY.md"
        or path.startswith("README.")
        or path.startswith("docs/")
        or path == "LICENSE"
        or path.startswith("LICENSE.")
        or path == "NOTICE"
        or path.startswith("NOTICE.")
        or path.startswith("CHANGELOG")
        or path.startswith("CONTRIBUTING")
        or path.startswith(".github/ISSUE_TEMPLATE/")
        or path.startswith(".github/PULL_REQUEST_TEMPLATE")
    )


# A package manifest/lockfile is a dependency change wherever it lives,
# including nested Node apps and GitHub Actions used by other workflows.
NODE_INPUT_NAMES = frozenset({
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
})
DEPENDENCY_INPUT_NAMES = NODE_INPUT_NAMES | frozenset({
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "poetry.lock",
    "uv.lock",
    "Pipfile",
    "Pipfile.lock",
    "requirements.txt",
    "requirements.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "packages.lock.json",
})


def is_node_input(path: str) -> bool:
    return path == ".github/workflows/ci.yml" or path.rsplit("/", 1)[-1] in NODE_INPUT_NAMES


def is_dependency_input(path: str) -> bool:
    basename = path.rsplit("/", 1)[-1]
    return (
        (path.startswith(".github/workflows/") and
         basename.endswith((".yml", ".yaml")))
        or basename in DEPENDENCY_INPUT_NAMES
        or (basename.startswith(("requirements-", "requirements_")) and
            basename.endswith((".txt", ".lock")))
        or path.startswith("requirements/")
        or path.startswith("infra/wheelhouse")
    )


def classify_paths(paths: list[str]) -> Scope:
    """Unknown files require all normal code checks (fail closed)."""
    return Scope(
        code=any(not is_document(path) for path in paths),
        deps=any(is_dependency_input(path) for path in paths),
        # pyproject.toml embeds README.md in the distribution's METADATA.
        metadata="README.md" in paths,
        node=any(is_node_input(path) for path in paths),
    )


def select_scope(
    event: str, pr_base_sha: str = "", push_before_sha: str = ""
) -> Scope:
    if event == "schedule":
        # Daily main-branch scan, even when no dependency files have changed.
        return SCHEDULED
    if event == "workflow_dispatch":
        return FULL
    if event not in {"pull_request", "push"}:
        print(f"::warning::Unknown event {event!r}; running full validation")
        return FULL

    base = pr_base_sha if event == "pull_request" else push_before_sha
    if not re.fullmatch(r"[0-9a-fA-F]{40}", base or "") or int(base, 16) == 0:
        print("::warning::Invalid comparison commit; running full validation")
        return FULL

    try:
        subprocess.run(
            ["git", "cat-file", "-e", f"{base}^{{commit}}"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        raw = subprocess.check_output(
            # Keep both old and new paths of a rename. With rename detection,
            # moving src/signer.py -> docs/signer.py reports only the docs
            # destination, incorrectly skipping all executable-code checks.
            ["git", "diff", "--name-only", "-z", "--no-renames", base, "HEAD", "--"],
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        print("::warning::Git comparison failed; running full validation")
        return FULL

    if not raw:
        print("::warning::No changed files found; running full validation")
        return FULL

    paths = [
        part.decode("utf-8", errors="surrogateescape")
        for part in raw.split(b"\0")
        if part
    ]
    for path in paths:
        print(f"Changed: {path!r}")
    return classify_paths(paths)


def gate_errors(env: dict[str, str]) -> list[str]:
    """Validate skipped jobs as strictly as jobs that were required to run."""
    errors: list[str] = []

    def require(name: str, expected: str) -> None:
        actual = env.get(name, "")
        if actual != expected:
            errors.append(f"{name}: expected {expected!r}, got {actual!r}")

    require("SCOPE", "success")
    require("SECRET_SCAN", "success")

    code = env.get("CODE")
    deps = env.get("DEPS")
    metadata = env.get("METADATA")
    node = env.get("NODE")
    if node not in {"true", "false"}:
        errors.append(f"Invalid NODE scope: {node!r}")
    if node == "true" and deps != "true":
        errors.append("NODE scope requires DEPS scope")
    if code not in {"true", "false"}:
        errors.append(f"Invalid CODE scope: {code!r}")
    if deps not in {"true", "false"}:
        errors.append(f"Invalid DEPS scope: {deps!r}")
    if metadata not in {"true", "false"}:
        errors.append(f"Invalid METADATA scope: {metadata!r}")

    require("TESTS", "success" if code == "true" else "skipped")
    require("REPRODUCIBLE_BUILD", "success" if code == "true" else "skipped")
    require("AUDIT", "success" if deps == "true" else "skipped")
    require("NODE_AUDIT", "success" if node == "true" else "skipped")
    # Executable QR/bridge changes MUST run the actual JS + Python interop job.
    require("QR_TRANSPORT", "success" if code == "true" else "skipped")
    # Native MetaMask QR browser, Keyring, and Python-signer interop are mandatory
    # whenever executable code is changed, never a silently skippable CI job.
    require("NATIVE_QR", "success" if code == "true" else "skipped")

    require(
        "WHEEL_SMOKE",
        "success" if metadata == "true" and code == "false" else "skipped",
    )
    require(
        "DEPENDENCY_REVIEW",
        "success"
        if env.get("EVENT_NAME") == "pull_request" and deps == "true"
        else "skipped",
    )
    return errors


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"scope", "required"}:
        print("usage: ci_checks.py {scope|required}", file=sys.stderr)
        return 2
    if sys.argv[1] == "required":
        errors = gate_errors(dict(os.environ))
        for message in errors:
            print(f"::error::{message}", file=sys.stderr)
        if errors:
            return 1
        print("All required CI results match selected scope")
        return 0

    scope = select_scope(
        os.environ.get("EVENT_NAME", ""),
        os.environ.get("PR_BASE_SHA", ""),
        os.environ.get("PUSH_BEFORE_SHA", ""),
    )
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        print("::error::GITHUB_OUTPUT is missing", file=sys.stderr)
        return 2
    with open(output_path, "a", encoding="utf-8") as output:
        output.write(f"code={str(scope.code).lower()}\n")
        output.write(f"deps={str(scope.deps).lower()}\n")
        output.write(f"metadata={str(scope.metadata).lower()}\n")
        output.write(f"node={str(scope.node).lower()}\n")
    print(f"CI scope: code={scope.code}, deps={scope.deps}, metadata={scope.metadata}, node={scope.node}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
