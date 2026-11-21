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
    assert "actions/checkout" not in workflow
    assert "event=pull_request" in workflow
    assert 'branch="$PR_BRANCH"' in workflow
    assert ".head_repository.full_name == $source" in workflow
    assert ".head_branch == $branch" in workflow
    assert ".number == $number" in workflow
    assert "pull_requests | length" not in workflow
    assert "Live USB image verification" in workflow
    assert "Live USB fast boot diagnostics" in workflow
    assert "gh api --method POST" in workflow


def test_pr_close_jq_filter_requires_positive_pr_identity():
    """Run the exact checked-in jq expression against conflicting API records."""
    import json
    import re
    from pathlib import Path

    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/live-usb-pr-close.yml"
    ).read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^          filter='\n(.*?)^          '$", workflow
    )
    assert match, "The workflow's actual jq program was not found"
    expression = match.group(1)
    same_repo = {"full_name": "ChiJiun/usb-btc-evm-cold-wallet"}
    other_repo = {"full_name": "another-user/usb-btc-evm-cold-wallet"}

    def run_item(id, *, pr_numbers, name="Live USB image verification",
                 event="pull_request", branch="shared-feature",
                 source=same_repo):
        return {
            "id": id,
            "name": name,
            "event": event,
            "head_branch": branch,
            "head_repository": source,
            "pull_requests": (
                None if pr_numbers is None
                else [{"number": number} for number in pr_numbers]
            ),
        }

    fixture = {
        "workflow_runs": [
            run_item(101, pr_numbers=[38]),  # only correct PR
            run_item(102, pr_numbers=[7]),  # same branch and repo, different PR
            run_item(103, pr_numbers=[]),  # closed PR association disappeared
            run_item(104, pr_numbers=None),  # API omits PR association
            run_item(105, pr_numbers=[38], source=other_repo),
            run_item(106, pr_numbers=[38], branch="different-feature"),
            run_item(107, pr_numbers=[38], event="workflow_dispatch"),
            run_item(108, pr_numbers=[38], name="CI"),
            run_item(109, pr_numbers=[38], name="Live USB fast boot diagnostics"),
            run_item(110, pr_numbers=[7, 38]),  # explicit positive match
            run_item(111, pr_numbers=[], branch="different-feature"),
            run_item(112, pr_numbers=[38], source=None),
        ]
    }
    output = subprocess.run(
        [
            "jq", "-r",
            "--arg", "branch", "shared-feature",
            "--arg", "source", "ChiJiun/usb-btc-evm-cold-wallet",
            "--argjson", "number", "38",
            expression,
        ],
        input=json.dumps(fixture),
        check=True,
        capture_output=True,
        text=True,
    )
    assert output.stdout.splitlines() == ["101", "109", "110"]


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
