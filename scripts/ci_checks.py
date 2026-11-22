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

if __package__:
    from .ci_workloads import FULL as FULL_WORKLOADS, NONE as NONE_WORKLOADS, classify_workloads
else:
    from ci_workloads import FULL as FULL_WORKLOADS, NONE as NONE_WORKLOADS, classify_workloads


@dataclass(frozen=True)
class Scope:
    code: bool
    deps: bool
    metadata: bool
    node: bool
    snap: bool = False


FULL = Scope(code=True, deps=True, metadata=False, node=True, snap=True)
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
        snap=any(path.startswith('metamask-snap/') or path in {
            '.github/workflows/ci.yml', '.github/workflows/metamask-snap.yml',
            'scripts/ci_checks.py',
        } for path in paths),
    )


def select_scopes(
    event: str, pr_base_sha: str = "", push_before_sha: str = ""
):
    if event == "schedule":
        # Daily main-branch scan, even when no dependency files have changed.
        return SCHEDULED, NONE_WORKLOADS
    if event == "workflow_dispatch":
        return FULL, FULL_WORKLOADS
    if event not in {"pull_request", "push"}:
        print(f"::warning::Unknown event {event!r}; running full validation")
        return FULL, FULL_WORKLOADS

    base = pr_base_sha if event == "pull_request" else push_before_sha
    if not re.fullmatch(r"[0-9a-fA-F]{40}", base or "") or int(base, 16) == 0:
        print("::warning::Invalid comparison commit; running full validation")
        return FULL, FULL_WORKLOADS

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
        return FULL, FULL_WORKLOADS

    if not raw:
        print("::warning::No changed files found; running full validation")
        return FULL, FULL_WORKLOADS

    paths = [
        part.decode("utf-8", errors="surrogateescape")
        for part in raw.split(b"\0")
        if part
    ]
    for path in paths:
        print(f"Changed: {path!r}")
    return classify_paths(paths), classify_workloads(paths)


def select_scope(event: str, pr_base_sha: str = "", push_before_sha: str = "") -> Scope:
    """Legacy classification retained for public API and its regression tests."""
    return select_scopes(event, pr_base_sha, push_before_sha)[0]


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
    snap = env.get("SNAP")
    if snap not in {'true', 'false'}:
        errors.append(f'Invalid SNAP scope: {snap!r}')
    if snap == 'true' and code != 'true':
        errors.append('SNAP scope requires CODE scope')
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
    # Workload selection is independent of the coarse CODE gate.
    require("QR_TRANSPORT", "success" if env.get("QR_REQUIRED") == "true" else "skipped")
    # Native MetaMask QR browser, Keyring, and Python-signer interop are mandatory
    # whenever executable code is changed, never a silently skippable CI job.
    require("NATIVE_QR", "success" if env.get("NATIVE_REQUIRED") == "true" else "skipped")
    # An optional Snap must pass real SES, browser and Python interop tests.
    # A separate workflow cannot satisfy the required aggregate gate.
    require("SNAP_VERIFY", "success" if snap == "true" else "skipped")
    # Real Windows EXE smoke is required for cross-platform code changes.
    require("WINDOWS_PORTABLE", "success" if env.get("WINDOWS_REQUIRED") == "true" else "skipped")
    for selected, result in (
        ("LIVE_USB_REQUIRED", "LIVE_USB"),
        ("BTC_CORE_REQUIRED", "BTC_CORE"),
        ("BTC_FUZZ_REQUIRED", "BTC_FUZZ"),
        ("VFAT_REQUIRED", "VFAT"),
    ):
        require(result, "success" if env.get(selected) == "true" else "skipped")
    for flag in ("QR_REQUIRED", "NATIVE_REQUIRED", "WINDOWS_REQUIRED",
                 "LIVE_USB_REQUIRED", "BTC_CORE_REQUIRED", "BTC_FUZZ_REQUIRED",
                 "VFAT_REQUIRED"):
        if env.get(flag) not in {"true", "false"}:
            errors.append(f"Invalid workload scope {flag}: {env.get(flag)!r}")
        if env.get(flag) == "true" and code != "true":
            errors.append(f"{flag} requires CODE scope")

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

    scope, workloads = select_scopes(
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
        output.write(f"snap={str(scope.snap or workloads.snap).lower()}\n")
        for key, value in (
            ("qr", workloads.qr), ("native_qr", workloads.native_qr),
            ("windows", workloads.windows), ("live_usb", workloads.live_usb),
            ("btc_core", workloads.btc_core), ("btc_fuzz", workloads.btc_fuzz),
            ("vfat", workloads.vfat),
        ):
            output.write(f"{key}={str(value).lower()}\n")
    print(f"CI scope: {scope}; workloads: {workloads}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
