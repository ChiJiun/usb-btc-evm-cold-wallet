"""Live USB console and CLI must refuse changed mounts even after boot success.

These are synthetic tests; no actual USB or secrets are involved.
"""
from types import SimpleNamespace

import pytest

from usb_cold_wallet import appliance, cli, gui


def test_console_ready_marker_contains_no_wallet_data(monkeypatch):
    calls = []
    monkeypatch.setattr(appliance.subprocess, "run", lambda args, **kwargs: calls.append((args, kwargs)))
    appliance._signal_console_ready()
    appliance._signal_console_ready(locked=True)
    assert [args[-2:] for args, _ in calls] == [
        ["--serial", "console-ready"], ["--serial", "lockdown-ready"],
    ]
    assert all(kwargs["timeout"] == 4 for _, kwargs in calls)


def test_appliance_live_audit_failure_is_visible_and_blocks_menu(monkeypatch, tmp_path):
    boot = tmp_path / "boot-checks.txt"
    boot.write_text("PASS: synthetic boot checks recorded\n", encoding="utf-8")
    monkeypatch.setattr(appliance, "BOOT_CHECKS", boot)
    observed = []
    monkeypatch.setattr(
        gui, "runtime_audit",
        lambda: (observed.append(True) or False, ("FAIL: COLD_VAULT remounted",)),
    )
    status = appliance.security_status()
    assert observed == [True]
    assert "FAIL: COLD_VAULT remounted" in status
    assert "FAIL: live appliance runtime audit rejected signing" in status
    assert appliance._security_locked(status)


def test_appliance_runtime_audit_exception_fails_closed(monkeypatch, tmp_path):
    boot = tmp_path / "boot-checks.txt"
    boot.write_text("PASS: synthetic boot checks recorded\n", encoding="utf-8")
    monkeypatch.setattr(appliance, "BOOT_CHECKS", boot)
    monkeypatch.setattr(
        gui, "runtime_audit",
        lambda: (_ for _ in ()).throw(OSError("device vanished")),
    )
    assert "FAIL: unable to complete live appliance runtime audit" in appliance.security_status()


def test_appliance_does_not_invoke_cli_after_remount(monkeypatch):
    monkeypatch.setattr(
        appliance, "security_status", lambda: ["FAIL: vault source changed"],
    )
    monkeypatch.setattr(
        appliance.subprocess, "run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("No CLI allowed")),
    )
    appliance._run_cli(["sign-evm"])


def test_appliance_child_cli_receives_live_audit_requirement(monkeypatch):
    monkeypatch.setattr(appliance, "security_status", lambda: ["PASS: all safe"])
    captured = []
    monkeypatch.setattr(
        appliance.subprocess, "run",
        lambda *args, **kwargs: captured.append((args, kwargs)) or SimpleNamespace(returncode=0),
    )
    appliance._run_cli(["addresses"])
    assert captured and captured[0][0][0][-1] == "addresses"
    assert captured[0][1]["env"]["USB_WALLET_APPLIANCE"] == "1"


def test_child_cli_audit_refuses_unsafe_environment_before_vault_access(monkeypatch, tmp_path):
    monkeypatch.setenv("USB_WALLET_APPLIANCE", "1")
    monkeypatch.setattr(gui, "runtime_audit", lambda: (False, ("FAIL: vault changed",)))
    monkeypatch.setattr(
        cli, "_wallet_root",
        lambda _args: (_ for _ in ()).throw(AssertionError("Must reject before unlocking")),
    )
    assert cli.main(["--vault", str(tmp_path / "missing.vault"), "addresses"]) == 1


def test_cli_never_calls_signer_without_exact_attended_confirmation(monkeypatch, tmp_path):
    monkeypatch.delenv("USB_WALLET_APPLIANCE", raising=False)
    reviewed = {
        "recipient": "0x000000000000000000000000000000000000dEaD",
        "value_wei": 1,
    }
    monkeypatch.setattr(cli, "read_exchange", lambda *a: {"fake": True})
    monkeypatch.setattr(cli, "review_evm_transaction", lambda *a: reviewed)
    monkeypatch.setattr(cli, "_signing_policy_snapshot", lambda *a: b"trusted snapshot")
    monkeypatch.setattr(cli, "_wallet_root", lambda *a: object())
    monkeypatch.setattr(cli, "_password", lambda *a: "test")
    monkeypatch.setattr(cli, "load_policy_snapshot", lambda *a: {})
    monkeypatch.setattr(cli, "_display_policy_and_confirm", lambda *a, **k: None)
    monkeypatch.setattr("builtins.input", lambda _prompt: "WRONG CONFIRMATION")
    monkeypatch.setattr(
        cli,
        "sign_evm",
        lambda *a: pytest.fail("signer must not run before exact typed confirmation"),
    )
    result = cli.main([
        "--vault", str(tmp_path / "fake.vault"), "sign-evm",
        "--request", str(tmp_path / "req.json"),
        "--to", reviewed["recipient"], "--wei", "1",
        "--out", str(tmp_path / "signed.json"),
        "--expected-policy-sha256", "a" * 64,
    ])
    assert result == 1
    assert not (tmp_path / "signed.json").exists()


def test_cli_rechecks_before_and_after_signing_and_never_writes_on_failed_audit(monkeypatch, tmp_path):
    monkeypatch.setenv("USB_WALLET_APPLIANCE", "1")
    calls = []
    def audit():
        calls.append("audit")
        return len(calls) < 3, ()
    monkeypatch.setattr(gui, "runtime_audit", audit)
    monkeypatch.setattr(cli, "read_exchange", lambda *a: {"fake": True})
    monkeypatch.setattr(cli, "review_evm_transaction",
                        lambda *a: {"recipient": "0x000000000000000000000000000000000000dEaD", "value_wei": 1})
    monkeypatch.setattr(cli, "_signing_policy_snapshot", lambda *a: b"trusted snapshot")
    monkeypatch.setattr(cli, "_wallet_root", lambda *a: object())
    monkeypatch.setattr(cli, "_password", lambda *a: "test")
    monkeypatch.setattr(cli, "load_policy_snapshot", lambda *a: {})
    monkeypatch.setattr(cli, "_display_policy_and_confirm", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_approve", lambda *a: None)
    monkeypatch.setattr(cli, "sign_evm", lambda *a: calls.append("sign") or {})
    monkeypatch.setattr(
        cli, "write_exchange",
        lambda *a: (_ for _ in ()).throw(AssertionError("Must not export after safety failure")),
    )
    result = cli.main([
        "--vault", str(tmp_path / "fake.vault"), "sign-evm",
        "--request", str(tmp_path / "req.json"),
        "--to", "0x000000000000000000000000000000000000dEaD",
        "--wei", "1", "--out", str(tmp_path / "signed.json"),
        "--expected-policy-sha256", "a" * 64,
    ])
    assert result == 1
    assert calls == ["audit", "audit", "sign", "audit"]
    assert not (tmp_path / "signed.json").exists()


def test_stage_diagnostics_do_not_make_empty_boot_audit_pass(monkeypatch, tmp_path):
    boot = tmp_path / "checks"
    boot.write_text("INFO: [1.00] INIT_STARTED\n")
    monkeypatch.setattr(appliance, "BOOT_CHECKS", boot)
    status = appliance.security_status()
    assert "FAIL: boot security audit contained no checks" in status
    assert appliance._security_locked(status)


@pytest.mark.parametrize("failure", ["transfer", "vault", "sync", "poweroff", None])
def test_attended_shutdown_requires_unmount_sync_and_poweroff(monkeypatch, tmp_path, failure):
    lock = tmp_path / "lockdown"
    monkeypatch.setattr(appliance, "LOCKDOWN", lock)
    calls = []
    monkeypatch.setattr(appliance, "unmount_transfer", lambda: calls.append("transfer") or failure != "transfer")
    monkeypatch.setattr(appliance, "_unmount_path", lambda _: calls.append("vault") or failure != "vault")
    monkeypatch.setattr(appliance.subprocess, "run", lambda args, **kw:
                        calls.append(args[0]) or SimpleNamespace(returncode=int(args[0] == failure)))
    assert appliance._poweroff() is (failure is None)
    assert lock.exists()
    expected = ["transfer", "vault", "sync", "poweroff"]
    assert calls == (expected if failure is None else expected[:expected.index(failure) + 1])


@pytest.mark.parametrize("after_ok", [True, False])
def test_attended_transfer_rescan_requires_live_post_mount_audit(monkeypatch, tmp_path, capsys, after_ok):
    lock = tmp_path / "lockdown"
    monkeypatch.setattr(appliance, "LOCKDOWN", lock)
    audit_results = iter([["PASS: boot"], ["PASS: live"] if after_ok else ["FAIL: changed"]])
    monkeypatch.setattr(appliance, "security_status", lambda: next(audit_results))
    calls = []
    monkeypatch.setattr(appliance, "unmount_transfer", lambda: calls.append("unmount") or True)
    monkeypatch.setattr(appliance, "mount_transfer", lambda: calls.append("mount") or True)
    monkeypatch.setattr(appliance, "_signal_diagnostic", lambda mode: calls.append(mode))
    assert appliance._rescan_transfer() is after_ok
    assert calls == (["unmount", "mount", "transfer-ready"] if after_ok
                     else ["unmount", "mount", "unmount"])
    assert lock.exists() is (not after_ok)
    assert ("TX_TRANSFER mounted." in capsys.readouterr().out) is after_ok
