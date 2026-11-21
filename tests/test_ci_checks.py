"""Regression coverage for PR/doc-only/scheduled CI scope and status gate."""
from __future__ import annotations

import subprocess

import pytest

from scripts import ci_checks


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        (["README.md"], ci_checks.Scope(False, False, True, False)),
        (["README.en.md"], ci_checks.Scope(False, False, False, False)),
        (["SECURITY.md"], ci_checks.Scope(False, False, False, False)),
        (["SECURITY.md", "docs/CI_SECURITY.md"], ci_checks.Scope(False, False, False, False)),
        (["docs/USB_SETUP.md"], ci_checks.Scope(False, False, False, False)),
        (["LICENSE", "docs/CI_SECURITY.md"], ci_checks.Scope(False, False, False, False)),
        (["README.md", "src/usb_cold_wallet/cli.py"], ci_checks.Scope(True, False, True, False)),
        (["src/usb_cold_wallet/cli.py"], ci_checks.Scope(True, False, False, False)),
        (["requirements/ci.lock"], ci_checks.Scope(True, True, False, False)),
        (["pyproject.toml"], ci_checks.Scope(True, True, False, False)),
        ([".github/workflows/ci.yml"], ci_checks.Scope(True, True, False, True)),
        (["infra/wheelhouse.sha256"], ci_checks.Scope(True, True, False, False)),
        (["scripts/ci_checks.py"], ci_checks.Scope(True, False, False, False)),
        ([".github/workflows/live-usb-build.yml"], ci_checks.Scope(True, True, False, False)),
        (["src/new feature.py", "docs/plan.md"], ci_checks.Scope(True, False, False, False)),
        ([".github/workflows/metamask-snap.yml"], ci_checks.Scope(True, True, False, False)),
        ([".github/workflows/live-usb-fast.yaml"], ci_checks.Scope(True, True, False, False)),
        (["qr-metamask/package-lock.json"], ci_checks.Scope(True, True, False, True)),
        (["metamask-snap/package.json"], ci_checks.Scope(True, True, False, True)),
        (["tools/npm-shrinkwrap.json"], ci_checks.Scope(True, True, False, True)),
        (["frontend/pnpm-lock.yaml"], ci_checks.Scope(True, True, False, True)),
        (["frontend/yarn.lock"], ci_checks.Scope(True, True, False, True)),
        (["services/go.mod"], ci_checks.Scope(True, True, False, False)),
        (["service/Cargo.lock"], ci_checks.Scope(True, True, False, False)),
        (["nested/pyproject.toml"], ci_checks.Scope(True, True, False, False)),
        (["scripts/any.py"], ci_checks.Scope(True, False, False, False)),
    ],
)
def test_classify_paths(paths, expected):
    assert ci_checks.classify_paths(paths) == expected


def test_scheduled_scan_requires_dependency_audit():
    assert ci_checks.select_scope("schedule") == ci_checks.SCHEDULED
    assert ci_checks.SCHEDULED.node and ci_checks.SCHEDULED.deps



def test_scheduled_node_audit_checks_production_and_build_dependencies():
    """The daily code=false scope must still audit dev/build dependencies."""
    from pathlib import Path

    assert ci_checks.select_scope("schedule") == ci_checks.Scope(
        code=False, deps=True, metadata=False, node=True
    )
    workflow = (
        Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    ).read_text(encoding="utf-8")
    node_job = workflow.split("\n  node_audit:", 1)[1].split("\n  secret_scan:", 1)[0]
    assert "if: needs.changes.outputs.node == 'true'" in node_job
    assert 'npm ci --prefix "$dir" --ignore-scripts --omit=dev' in node_job
    assert 'npm audit --prefix "$dir" --omit=dev --audit-level=high' in node_job
    assert 'npm audit --prefix "$dir" --audit-level=high' in node_job

    env = required_env(
        EVENT_NAME="schedule", DEPS="true", NODE="true",
        AUDIT="success", NODE_AUDIT="skipped"
    )
    assert any("NODE_AUDIT" in error for error in ci_checks.gate_errors(env))
    env["NODE_AUDIT"] = "success"
    assert ci_checks.gate_errors(env) == []

def test_manual_dispatch_runs_full_suite():
    assert ci_checks.select_scope("workflow_dispatch") == ci_checks.FULL


@pytest.mark.parametrize("event", ["push", "pull_request", "unknown"])
def test_missing_comparison_fails_closed(event):
    assert ci_checks.select_scope(event) == ci_checks.FULL


def test_git_diff_files_are_classified(monkeypatch):
    sha = "a" * 40
    seen = []

    def fake_run(args, **kwargs):
        seen.append(args)
        return None

    def fake_diff(args, **kwargs):
        seen.append(args)
        return b"README.md\0docs/USB_SETUP.md\0"

    monkeypatch.setattr(ci_checks.subprocess, "run", fake_run)
    monkeypatch.setattr(ci_checks.subprocess, "check_output", fake_diff)
    assert ci_checks.select_scope("pull_request", pr_base_sha=sha) == ci_checks.Scope(
        False, False, True, False
    )
    assert seen[0][2] == "-e"
    assert seen[1][1:4] == ["diff", "--name-only", "-z"]


def test_git_diff_failure_fails_closed(monkeypatch):
    monkeypatch.setattr(ci_checks.subprocess, "run", lambda *a, **kw: None)

    def broken(*args, **kwargs):
        raise subprocess.CalledProcessError(128, "git diff")

    monkeypatch.setattr(ci_checks.subprocess, "check_output", broken)
    assert ci_checks.select_scope("pull_request", pr_base_sha="f" * 40) == ci_checks.FULL


def test_empty_diff_fails_closed(monkeypatch):
    monkeypatch.setattr(ci_checks.subprocess, "run", lambda *a, **kw: None)
    monkeypatch.setattr(ci_checks.subprocess, "check_output", lambda *a, **kw: b"")
    assert ci_checks.select_scope("push", push_before_sha="e" * 40) == ci_checks.FULL


def required_env(**overrides):
    env = {
        "SCOPE": "success",
        "SECRET_SCAN": "success",
        "CODE": "false",
        "DEPS": "false",
        "METADATA": "false",
        "NODE": "false",
        "NODE_AUDIT": "skipped",
        "QR_TRANSPORT": "skipped",
        "EVENT_NAME": "pull_request",
        "TESTS": "skipped",
        "REPRODUCIBLE_BUILD": "skipped",
        "AUDIT": "skipped",
        "WHEEL_SMOKE": "skipped",
        "DEPENDENCY_REVIEW": "skipped",
    }
    env.update(overrides)
    return env


@pytest.mark.parametrize(
    "env",
    [
        required_env(),  # docs-only
        required_env(METADATA="true", WHEEL_SMOKE="success"),  # README.md
        required_env(
            CODE="true", QR_TRANSPORT="success", TESTS="success", REPRODUCIBLE_BUILD="success"
        ),  # Python-only
        required_env(
            CODE="true", QR_TRANSPORT="success",
            DEPS="true",
            TESTS="success",
            REPRODUCIBLE_BUILD="success",
            AUDIT="success",
            DEPENDENCY_REVIEW="success",
        ),  # full CI
        required_env(
            EVENT_NAME="pull_request",
            CODE="true", QR_TRANSPORT="success", DEPS="true", NODE="true",
            TESTS="success", REPRODUCIBLE_BUILD="success",
            AUDIT="success", NODE_AUDIT="success",
            DEPENDENCY_REVIEW="success",
        ),  # Node lock or action dependency
        required_env(EVENT_NAME="schedule", DEPS="true", NODE="true",
                     AUDIT="success", NODE_AUDIT="success"),  # daily
        required_env(
            EVENT_NAME="workflow_dispatch",
            CODE="true", QR_TRANSPORT="success",
            DEPS="true", NODE="true",
            TESTS="success",
            REPRODUCIBLE_BUILD="success",
            AUDIT="success", NODE_AUDIT="success",
        ),
    ],
)
def test_required_gate_accepts_expected_results(env):
    assert ci_checks.gate_errors(env) == []


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"SCOPE": "failure"}, "SCOPE"),
        ({"SECRET_SCAN": "skipped"}, "SECRET_SCAN"),
        ({"TESTS": "success"}, "TESTS"),  # docs-only expected skipped
        ({"CODE": "true"}, "TESTS"),  # code-only expected success
        ({"CODE": "true", "TESTS": "success", "REPRODUCIBLE_BUILD": "success"}, "QR_TRANSPORT"),
        ({"CODE": "true", "TESTS": "success", "REPRODUCIBLE_BUILD": "success",
          "QR_TRANSPORT": "failure"}, "QR_TRANSPORT"),
        ({"CODE": "true", "TESTS": "success", "REPRODUCIBLE_BUILD": "success",
          "QR_TRANSPORT": "cancelled"}, "QR_TRANSPORT"),
        ({"DEPS": "true"}, "AUDIT"),
        ({"AUDIT": "success"}, "AUDIT"),
        ({"METADATA": "true"}, "WHEEL_SMOKE"),
        ({"EVENT_NAME": "schedule", "DEPS": "true"}, "AUDIT"),
        ({"DEPENDENCY_REVIEW": "success"}, "DEPENDENCY_REVIEW"),
        ({"NODE": "true", "DEPS": "true", "AUDIT": "success",
          "DEPENDENCY_REVIEW": "success"}, "NODE_AUDIT"),
        ({"NODE_AUDIT": "success"}, "NODE_AUDIT"),
        ({"NODE": "true"}, "NODE scope requires DEPS"),
        ({"NODE": "broken"}, "NODE"),
        ({"DEPS": "true", "AUDIT": "success", "NODE": "true",
          "NODE_AUDIT": "success"}, "DEPENDENCY_REVIEW"),
        ({"CODE": "invalid"}, "CODE"),
    ],
)
def test_required_gate_rejects_wrong_results(overrides, expected):
    assert any(expected in error for error in ci_checks.gate_errors(required_env(**overrides)))


def test_closed_pr_cancels_only_its_automatic_live_usb_runs():
    from pathlib import Path

    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/live-usb-pr-close.yml"
    ).read_text(encoding="utf-8")

    assert "pull_request_target:" in workflow
    assert "types: [closed]" in workflow
    assert "actions: write" in workflow
    assert "pull-requests: read" in workflow
    assert "PR_HEAD_SHA:" in workflow
    assert "unique_owner_filter=" in workflow
    assert 'head="${source_owner}:${PR_BRANCH}"' in workflow
    assert ".head.sha == $sha" in workflow
    assert "actions/checkout" not in workflow
    assert "event=pull_request" in workflow
    assert 'branch="$PR_BRANCH"' in workflow
    assert ".head_repository.full_name == $source" in workflow
    assert ".head_branch == $branch" in workflow
    assert ".number == $number" in workflow
    assert "pull_requests | length) == 0 or any" not in workflow
    assert "Live USB image verification" in workflow
    assert "Live USB fast boot diagnostics" in workflow
    assert "gh api --method POST" in workflow


def test_pr_close_jq_filter_requires_positive_pr_identity():
    """Execute BOTH jq programs used by the actual trusted PR-close workflow."""
    import json
    import re
    from pathlib import Path

    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/live-usb-pr-close.yml"
    ).read_text(encoding="utf-8")

    def extract(name):
        match = re.search(
            rf"(?ms)^          {name}='\\n(.*?)^          '$", workflow
        )
        assert match, f"Could not find real workflow jq expression: {name}"
        return match.group(1)

    owner_program = extract("unique_owner_filter")
    run_program = extract("filter")
    source = "ChiJiun/usb-btc-evm-cold-wallet"
    sha = "a" * 40
    old_sha = "b" * 40

    def pull(number, *, commit=sha, branch="shared-feature", repo=source):
        return {
            "number": number,
            "head": {"sha": commit, "ref": branch, "repo": {"full_name": repo}},
        }

    def unique_owner(pages):
        result = subprocess.run(
            ["jq", "-sr", "--arg", "sha", sha,
             "--arg", "branch", "shared-feature", "--arg", "source", source,
             owner_program],
            input="\\n".join(json.dumps(page) for page in pages) + "\\n",
            check=True, capture_output=True, text=True,
        )
        return result.stdout.strip()

    # A closed PR with one exact branch/repo/SHA match is identifiable even
    # after run.pull_requests becomes [] (as observed for PR #9).
    assert unique_owner([[pull(38), pull(7, commit=old_sha)]]) == "38"
    # Same branch + same commit can target two different base branches:
    # the fallback MUST fail closed, even after both PRs close.
    assert unique_owner([[pull(38)], [pull(7)]]) == ""
    assert unique_owner([[pull(38, repo="other/repo")]]) == ""
    assert unique_owner([[pull(38, commit=old_sha)]]) == ""
    assert unique_owner([[]]) == ""

    def run_item(number, *, associations, name="Live USB image verification",
                 event="pull_request", branch="shared-feature", repo=source,
                 commit=sha):
        return {
            "id": number,
            "name": name, "event": event,
            "head_branch": branch, "head_repository": (
                None if repo is None else {"full_name": repo}),
            "head_sha": commit,
            "pull_requests": (
                None if associations is None
                else [{"number": pr} for pr in associations]),
        }

    runs = {"workflow_runs": [
        run_item(101, associations=[38]),       # explicit correct PR
        run_item(102, associations=[7]),        # wrong PR, same repo/branch/SHA
        run_item(103, associations=[]),         # closed PR: empty association
        run_item(104, associations=None),       # closed PR: null association
        run_item(105, associations=[38], repo="other/repo"),
        run_item(106, associations=[38], branch="other-feature"),
        run_item(107, associations=[38], event="workflow_dispatch"),
        run_item(108, associations=[38], name="CI"),
        run_item(109, associations=[38], name="Live USB fast boot diagnostics"),
        run_item(110, associations=[7, 38]),    # ambiguous; DO NOT cancel
        run_item(111, associations=[], branch="other-feature"),
        run_item(112, associations=[], repo=None),
        run_item(113, associations=[], commit=old_sha),
        run_item(114, associations=[7], commit=sha),
        run_item(115, associations=[], name="Live USB fast boot diagnostics"),
        run_item(116, associations=[], event="workflow_dispatch"),
        run_item(117, associations=[38], commit=old_sha),  # explicit identity
    ]}

    def select_runs(owner):
        result = subprocess.run(
            ["jq", "-r", "--arg", "branch", "shared-feature",
             "--arg", "source", source, "--argjson", "number", "38",
             "--arg", "sha", sha, "--arg", "unique_owner", owner,
             run_program],
            input=json.dumps(runs),
            check=True, capture_output=True, text=True,
        )
        return result.stdout.splitlines()

    assert select_runs("38") == ["101", "103", "104", "109", "115", "117"]
    # If the PR list is ambiguous or API is unavailable, do not cancel runs
    # whose PR association vanished. Positive one-to-one links still work.
    assert select_runs("") == ["101", "109", "117"]
    assert select_runs("7") == ["101", "109", "117"]


@pytest.mark.parametrize("path", [
    ".github/workflows/live-usb-build.yml",
    ".github/workflows/metamask-snap.yml",
    ".github/workflows/other.yaml",
    "qr-metamask/package-lock.json",
    "metamask-snap/package-lock.json",
])
def test_dependency_review_cannot_be_skipped_on_action_or_node_lock_change(path):
    scope = ci_checks.classify_paths([path])
    assert scope.deps is True
    assert scope.code is True
    env = required_env(
        CODE="true", QR_TRANSPORT="success", DEPS="true",
        NODE="true" if scope.node else "false",
        NODE_AUDIT="success" if scope.node else "skipped",
        TESTS="success", REPRODUCIBLE_BUILD="success", AUDIT="success",
        DEPENDENCY_REVIEW="skipped",
    )
    assert any("DEPENDENCY_REVIEW" in error
               for error in ci_checks.gate_errors(env))
    env["DEPENDENCY_REVIEW"] = "success"
    assert ci_checks.gate_errors(env) == []


@pytest.mark.parametrize("path", [
    "qr-transport/src/ur_transport.mjs",
    "qr-transport/tests/ur_transport.test.mjs",
    "src/usb_cold_wallet/qr_cli.py",
    "src/usb_cold_wallet/qr_workflow.py",
    "src/usb_cold_wallet/qr_session.py",
    "src/usb_cold_wallet/exchange.py",
])
def test_qr_js_and_python_bridge_changes_must_run_qr_integration(path):
    scope = ci_checks.classify_paths([path])
    assert scope.code is True
    env = required_env(
        CODE="true", TESTS="success", REPRODUCIBLE_BUILD="success",
        QR_TRANSPORT="skipped",
        AUDIT="success" if scope.deps else "skipped",
        DEPENDENCY_REVIEW="success" if scope.deps else "skipped",
        DEPS="true" if scope.deps else "false",
    )
    assert any("QR_TRANSPORT" in error for error in ci_checks.gate_errors(env))
    env["QR_TRANSPORT"] = "success"
    assert ci_checks.gate_errors(env) == []


def test_dependency_review_calls_the_actual_diff_action_without_sbom_preflight():
    from pathlib import Path

    content = (
        Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    ).read_text(encoding="utf-8")
    assert "uses: actions/dependency-review-action@" in content
    assert "Review dependency changes (required)" in content
    assert "fail-on-severity: moderate" in content
    assert "dependency-graph/sbom" not in content
    assert "dependency_review_guard.py" not in content
    assert "if: steps.dependency-graph.outputs.available" not in content


def test_required_security_review_must_not_accept_skipped_on_dependency_change():
    env = required_env(
        CODE="true", QR_TRANSPORT="success",
        DEPS="true", AUDIT="success",
        NODE="true", NODE_AUDIT="success",
        TESTS="success", REPRODUCIBLE_BUILD="success",
        DEPENDENCY_REVIEW="skipped",
    )
    assert any("DEPENDENCY_REVIEW" in error for error in ci_checks.gate_errors(env))
    env["DEPENDENCY_REVIEW"] = "success"
    assert ci_checks.gate_errors(env) == []


def test_required_workflow_wires_real_qr_gate_and_unconditional_dependency_review():
    from pathlib import Path
    content = (
        Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    ).read_text(encoding="utf-8")
    assert "QR_INTEROP=1 python -m pytest -q tests/test_qr_interop.py" in content
    assert "npm run build" in content
    assert "npm audit --audit-level=high" in content
    assert "QR_TRANSPORT: ${{ needs.qr_transport.result }}" in content
    assert "uses: actions/dependency-review-action@" in content
    assert "dependency-graph/sbom" not in content
    assert "if: steps.dependency-graph.outputs.available" not in content
