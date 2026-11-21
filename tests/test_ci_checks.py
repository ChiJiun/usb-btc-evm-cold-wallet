"""Regression coverage for PR/doc-only/scheduled CI scope and status gate."""
from __future__ import annotations

import subprocess

import pytest

from scripts import ci_checks


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        (["README.md"], ci_checks.Scope(False, False, True)),
        (["README.en.md"], ci_checks.Scope(False, False, False)),
        (["docs/USB_SETUP.md"], ci_checks.Scope(False, False, False)),
        (["LICENSE", "docs/CI_SECURITY.md"], ci_checks.Scope(False, False, False)),
        (["README.md", "src/usb_cold_wallet/cli.py"], ci_checks.Scope(True, False, True)),
        (["src/usb_cold_wallet/cli.py"], ci_checks.Scope(True, False, False)),
        (["requirements/ci.lock"], ci_checks.Scope(True, True, False)),
        (["pyproject.toml"], ci_checks.Scope(True, True, False)),
        ([".github/workflows/ci.yml"], ci_checks.Scope(True, True, False)),
        (["infra/wheelhouse.sha256"], ci_checks.Scope(True, True, False)),
        (["scripts/ci_checks.py"], ci_checks.Scope(True, False, False)),
        ([".github/workflows/live-usb-build.yml"], ci_checks.Scope(True, False, False)),
        (["src/new feature.py", "docs/plan.md"], ci_checks.Scope(True, False, False)),
    ],
)
def test_classify_paths(paths, expected):
    assert ci_checks.classify_paths(paths) == expected


def test_scheduled_scan_requires_dependency_audit():
    assert ci_checks.select_scope("schedule") == ci_checks.SCHEDULED


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
        False, False, True
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
            CODE="true", TESTS="success", REPRODUCIBLE_BUILD="success"
        ),  # Python-only
        required_env(
            CODE="true",
            DEPS="true",
            TESTS="success",
            REPRODUCIBLE_BUILD="success",
            AUDIT="success",
            DEPENDENCY_REVIEW="success",
        ),  # full CI
        required_env(EVENT_NAME="schedule", DEPS="true", AUDIT="success"),  # daily
        required_env(
            EVENT_NAME="workflow_dispatch",
            CODE="true",
            DEPS="true",
            TESTS="success",
            REPRODUCIBLE_BUILD="success",
            AUDIT="success",
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
        ({"DEPS": "true"}, "AUDIT"),
        ({"AUDIT": "success"}, "AUDIT"),
        ({"METADATA": "true"}, "WHEEL_SMOKE"),
        ({"EVENT_NAME": "schedule", "DEPS": "true"}, "AUDIT"),
        ({"DEPENDENCY_REVIEW": "success"}, "DEPENDENCY_REVIEW"),
        ({"CODE": "invalid"}, "CODE"),
    ],
)
def test_required_gate_rejects_wrong_results(overrides, expected):
    assert any(expected in error for error in ci_checks.gate_errors(required_env(**overrides)))
