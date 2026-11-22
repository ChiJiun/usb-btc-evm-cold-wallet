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
        ([".github/workflows/ci.yml"], ci_checks.Scope(True, True, False, True, True)),
        (["infra/wheelhouse.sha256"], ci_checks.Scope(True, True, False, False)),
        (["scripts/ci_checks.py"], ci_checks.Scope(True, False, False, False, True)),
        ([".github/workflows/live-usb-build.yml"], ci_checks.Scope(True, True, False, False)),
        (["src/new feature.py", "docs/plan.md"], ci_checks.Scope(True, False, False, False)),
        ([".github/workflows/metamask-snap.yml"], ci_checks.Scope(True, True, False, False, True)),
        ([".github/workflows/live-usb-fast.yaml"], ci_checks.Scope(True, True, False, False)),
        (["qr-metamask/package-lock.json"], ci_checks.Scope(True, True, False, True)),
        (["metamask-snap/package.json"], ci_checks.Scope(True, True, False, True, True)),
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
        "SNAP": "false",
        "SNAP_VERIFY": "skipped",
        "NODE_AUDIT": "skipped",
        "QR_TRANSPORT": "skipped",
        "NATIVE_QR": "skipped",
        "WINDOWS_PORTABLE": "skipped",
        "EVENT_NAME": "pull_request",
        "TESTS": "skipped",
        "REPRODUCIBLE_BUILD": "skipped",
        "AUDIT": "skipped",
        "WHEEL_SMOKE": "skipped",
        "DEPENDENCY_REVIEW": "skipped",
    }
    env.update(overrides)
    # Previous tests model the original all-platform CODE scope. Explicit
    # workload flags are necessary so omitted scope outputs fail closed.
    for scope in ("QR_REQUIRED", "NATIVE_REQUIRED", "WINDOWS_REQUIRED"):
        env.setdefault(scope, "true" if env.get("CODE") == "true" else "false")
    for scope, result in (
        ("LIVE_USB_REQUIRED", "LIVE_USB"),
        ("BTC_CORE_REQUIRED", "BTC_CORE"),
        ("BTC_FUZZ_REQUIRED", "BTC_FUZZ"),
        ("VFAT_REQUIRED", "VFAT"),
    ):
        env.setdefault(scope, "false")
        env.setdefault(result, "skipped")
    if "SNAP_VERIFY" not in overrides:
        env["SNAP_VERIFY"] = "success" if env.get("SNAP") == "true" else "skipped"
    if "NATIVE_QR" not in overrides:
        env["NATIVE_QR"] = "success" if env.get("CODE") == "true" else "skipped"
    if "WINDOWS_PORTABLE" not in overrides:
        env["WINDOWS_PORTABLE"] = "success" if env.get("CODE") == "true" else "skipped"
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
            DEPS="true", NODE="true", SNAP="true",
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
        ({"CODE": "true", "TESTS": "success", "REPRODUCIBLE_BUILD": "success",
          "QR_TRANSPORT": "success", "NATIVE_QR": "skipped"}, "NATIVE_QR"),
        ({"CODE": "true", "TESTS": "success", "REPRODUCIBLE_BUILD": "success",
          "QR_TRANSPORT": "success", "NATIVE_QR": "failure"}, "NATIVE_QR"),
        ({"CODE": "true", "TESTS": "success", "REPRODUCIBLE_BUILD": "success",
          "QR_TRANSPORT": "success", "WINDOWS_PORTABLE": "skipped"}, "WINDOWS_PORTABLE"),
        ({"CODE": "true", "TESTS": "success", "REPRODUCIBLE_BUILD": "success",
          "QR_TRANSPORT": "success", "WINDOWS_PORTABLE": "failure"}, "WINDOWS_PORTABLE"),
        ({"CODE": "true", "TESTS": "success", "REPRODUCIBLE_BUILD": "success",
          "QR_TRANSPORT": "success", "WINDOWS_PORTABLE": "cancelled"}, "WINDOWS_PORTABLE"),
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
        ({"SNAP": "broken"}, "SNAP"),
        ({"SNAP": "true", "SNAP_VERIFY": "failure", "CODE": "true", "TESTS": "success",
          "QR_TRANSPORT": "success", "NATIVE_QR": "success",
          "REPRODUCIBLE_BUILD": "success"}, "SNAP_VERIFY"),
        ({"SNAP": "true", "SNAP_VERIFY": "skipped", "CODE": "true", "TESTS": "success",
          "QR_TRANSPORT": "success", "NATIVE_QR": "success",
          "REPRODUCIBLE_BUILD": "success"}, "SNAP_VERIFY"),
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
            rf"(?ms)^          {name}='\n(.*?)^          '$", workflow
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
            input="\n".join(json.dumps(page) for page in pages) + "\n",
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


def test_windows_portable_reusable_job_is_in_required_gate():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    windows = (root / ".github/workflows/windows-companion.yml").read_text(encoding="utf-8")
    assert "  windows_portable:" in ci
    assert "uses: ./.github/workflows/windows-companion.yml" in ci
    assert "      - windows_portable" in ci.split("\n  required:", 1)[1]
    assert "WINDOWS_PORTABLE: ${{ needs.windows_portable.result }}" in ci
    assert "workflow_call:" in windows
    assert "pull_request:" not in windows
    for status in ("failure", "skipped", "cancelled"):
        env = required_env(
            CODE="true", TESTS="success",
            QR_TRANSPORT="success", REPRODUCIBLE_BUILD="success",
            WINDOWS_PORTABLE=status
        )
        assert any("WINDOWS_PORTABLE" in error for error in ci_checks.gate_errors(env))

def test_only_pull_request_runs_are_superseded_and_required_stays_fail_closed():
    """Main pushes must not cancel each other or weaken the Required gate."""
    from pathlib import Path

    workflow = (
        Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
    ).read_text(encoding="utf-8")
    required = workflow.split("\n  required:", 1)[1]
    concurrency = workflow.split("\nconcurrency:\n", 1)[1].split("\nenv:\n", 1)[0]

    assert "github.event.pull_request.number || github.run_id" in concurrency
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in concurrency
    assert "github.ref" not in concurrency
    assert "if: always()" in required
    assert "!cancelled()" not in required

    # Unexpected/manual cancellation on an active run must still fail closed.
    env = required_env(
        EVENT_NAME="push", CODE="true", TESTS="success",
        REPRODUCIBLE_BUILD="success", QR_TRANSPORT="success",
        WINDOWS_PORTABLE="cancelled",
    )
    assert any("WINDOWS_PORTABLE" in error for error in ci_checks.gate_errors(env))
    env["WINDOWS_PORTABLE"] = "failure"
    assert any("WINDOWS_PORTABLE" in error for error in ci_checks.gate_errors(env))
    env["WINDOWS_PORTABLE"] = "success"
    assert ci_checks.gate_errors(env) == []


def test_workload_classifier_tracks_exact_offline_installer_allowlist():
    from scripts.build_offline_wheel import ALLOWED_OFFLINE_MODULES, ONLINE_MODULES
    from scripts.ci_workloads import (
        OFFLINE_MODULES, ONLINE_MODULES as CI_ONLINE, classify_workloads,
    )
    assert OFFLINE_MODULES == ALLOWED_OFFLINE_MODULES
    assert CI_ONLINE == ONLINE_MODULES
    for name in OFFLINE_MODULES:
        assert classify_workloads(["src/usb_cold_wallet/" + name]).live_usb
    for name in ONLINE_MODULES:
        selected = classify_workloads(["src/usb_cold_wallet/" + name])
        assert selected.windows
        assert not selected.live_usb
    assert not classify_workloads([
        "src/usb_cold_wallet/companion_static/index.html",
    ]).live_usb


@pytest.mark.parametrize(("path", "expected"), [
    ("src/usb_cold_wallet/btc.py", ("live_usb", "btc_core", "btc_fuzz", "qr")),
    ("src/usb_cold_wallet/gui.py", ("live_usb", "windows", "vfat")),
    ("src/usb_cold_wallet/cross_boot.py", ("live_usb", "windows")),
    ("scripts/install_target_python.py", ("live_usb",)),
    ("buildroot-external/board/usb-wallet/linux.config", ("live_usb",)),
    ("infra/wheelhouse.sha256", ("live_usb",)),
    ("pyproject.toml", ("windows", "qr", "native_qr")),
    ("src/usb_cold_wallet/companion_web.py", ("windows",)),
    ("scripts/windows_companion.py", ("windows",)),
    ("src/usb_cold_wallet/companion_static/companion.js", ("windows",)),
    ("qr-transport/src/typed_registry.mjs", ("qr",)),
    ("qr-metamask/src/main.js", ("native_qr",)),
    ("metamask-snap/src/protocol.ts", ("snap",)),
    ("scripts/verify_usb_vfat_atomic.py", ("vfat",)),
    ("tools/generate_core_bip84_psbt_e2e.py", ("btc_core",)),
    ("tools/fuzz_btc_psbt.py", ("btc_fuzz",)),
    (".github/workflows/ci.yml", ("live_usb", "qr", "windows")),
    (".github/workflows/live-usb-build.yml", ("live_usb",)),
    ("src/usb_cold_wallet/new_secret_module.py", ("live_usb", "windows")),
    ("scripts/unrecognized.sh", ("live_usb", "windows")),
    (".github/workflows/unknown.yml", ("live_usb", "windows")),
])
def test_workload_positive_scope(path, expected):
    from scripts.ci_workloads import classify_workloads
    chosen = classify_workloads([path])
    for key in expected:
        assert getattr(chosen, key), (path, key)


@pytest.mark.parametrize("path", [
    "docs/CI_SECURITY.md",
    "README.md",
    "README.en.md",
    "tests/test_boot_media.py",
    "tests/test_live_appliance_runtime.py",
    "tests/test_ci_checks.py",
    "tests/test_companion_ui.mjs",
    "scripts/verify_release_assets.py",
    "scripts/smoke_windows_companion.py",
    "qr-transport/tests/ur_transport.test.mjs",
    "qr-metamask/src/adapter.mjs",
    "metamask-snap/src/index.ts",
    "src/usb_cold_wallet/companion_core.py",
    "requirements/ci.lock",
])
def test_unrelated_change_does_not_rebuild_offline_image(path):
    from scripts.ci_workloads import classify_workloads
    assert not classify_workloads([path]).live_usb


def test_multiple_paths_union_and_unknown_fail_closed():
    from scripts.ci_workloads import FULL, classify_workloads
    chosen = classify_workloads([
        "src/usb_cold_wallet/companion_web.py",
        "src/usb_cold_wallet/btc.py",
    ])
    assert chosen.windows and chosen.live_usb and chosen.btc_core
    assert classify_workloads(["unclassified/new-tool.rs"]) == FULL


def test_required_gate_rejects_skipping_necessary_live_and_specialized_jobs():
    for required, result in (
        ("LIVE_USB_REQUIRED", "LIVE_USB"),
        ("BTC_CORE_REQUIRED", "BTC_CORE"),
        ("BTC_FUZZ_REQUIRED", "BTC_FUZZ"),
        ("VFAT_REQUIRED", "VFAT"),
    ):
        env = required_env(
            CODE="true", TESTS="success", REPRODUCIBLE_BUILD="success",
            QR_TRANSPORT="success", **{required: "true"}
        )
        assert any(result in error for error in ci_checks.gate_errors(env))
        env[result] = "success"
        assert ci_checks.gate_errors(env) == []
        env[result] = "cancelled"
        assert any(result in error for error in ci_checks.gate_errors(env))


def test_full_live_usb_is_called_and_gated_with_no_path_filtered_bypass():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    live = (root / ".github/workflows/live-usb-build.yml").read_text(encoding="utf-8")
    required = ci.split("\n  required:", 1)[1]
    assert "  live_usb:" in ci
    assert "uses: ./.github/workflows/live-usb-build.yml" in ci
    assert "      - live_usb" in required
    assert "LIVE_USB_REQUIRED: ${{ needs.changes.outputs.live_usb }}" in required
    assert "LIVE_USB: ${{ needs.live_usb.result }}" in required
    assert "workflow_call:" in live
    assert "  pull_request:" not in live
    for job in ("btc_core", "btc_fuzz", "vfat", "windows_portable"):
        assert "      - " + job in required
