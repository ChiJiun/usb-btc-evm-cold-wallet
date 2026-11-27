"""Live USB console and CLI must refuse changed mounts even after boot success.

These are synthetic tests; no actual USB or secrets are involved.
"""
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest

from usb_cold_wallet import appliance, cli, gui


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="Linux USB appliance only")
def test_rescan_returns_to_locked_menu_when_fat_probe_blocks(monkeypatch, tmp_path, capsys):
    fifo = tmp_path / "blocked-fat-read"
    os.mkfifo(fifo)
    monkeypatch.setattr(appliance, "LOCKDOWN", tmp_path / "lockdown")
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path / "transfer")
    monkeypatch.setattr(appliance, "MEDIA_PROBE_TIMEOUT", 1)
    monkeypatch.setattr(appliance, "security_status", lambda: ["PASS: synthetic audit"])
    monkeypatch.setattr(appliance, "unmount_transfer", lambda: True)
    monkeypatch.setattr(appliance, "_run_media_command", lambda _: pytest.fail("unexpected mount"))
    monkeypatch.setattr(appliance, "_signal_diagnostic", lambda _: pytest.fail("unexpected ready marker"))

    output = tmp_path / "worker-entered"
    popen = appliance.subprocess.Popen

    def stalled_probe(args, **kwargs):
        assert args[:3] == [sys.executable, "-I", "-c"]
        prefix = (
            "import sys\n"
            f"sys.path.insert(0, {str(Path(appliance.__file__).resolve().parents[1])!r})\n"
            "from pathlib import Path\n"
            "from usb_cold_wallet import appliance\n"
            f"Path({str(output)!r}).touch()\n"
            f"appliance._unique_transfer_device = lambda: appliance._fat_label(Path({str(fifo)!r}))\n"
        )
        return popen([*args[:3], prefix + args[3]], **kwargs)

    monkeypatch.setattr(appliance.subprocess, "Popen", stalled_probe)
    start = time.monotonic()
    assert not appliance._rescan_transfer()
    assert time.monotonic() - start < 5
    assert output.exists()
    assert appliance._security_locked(appliance.security_status())
    assert "probe timed out" in capsys.readouterr().out


def test_probe_accepts_only_successful_device_result(monkeypatch):
    for output, code, expected in [
        (b"/dev/sda3\n", 0, "/dev/sda3"),
        (b"/dev/sda3\n", 1, None),
        (b"/dev/sda3\n/dev/sdb1\n", 0, None),
        (b"", 0, None),
    ]:
        worker = SimpleNamespace(
            communicate=lambda **kwargs: (output, None),
            stdout=SimpleNamespace(close=lambda: None),
            returncode=code,
        )
        monkeypatch.setattr(appliance.subprocess, "Popen", lambda *a, **kw: worker)
        assert appliance._bounded_transfer_device() == expected


def test_late_mount_completion_requires_reinspection_on_shutdown(monkeypatch, tmp_path, capsys):
    lock = tmp_path / "lockdown"
    transfer = tmp_path / "transfer"
    vault = tmp_path / "vault"
    monkeypatch.setattr(appliance, "LOCKDOWN", lock)
    monkeypatch.setattr(appliance, "_pending_media_command", None)
    monkeypatch.setattr(appliance, "TRANSFER", transfer)
    monkeypatch.setattr(appliance, "VAULT", vault / "wallet.vault")
    monkeypatch.setattr(appliance, "_bounded_transfer_device", lambda: "/dev/sda3")
    monkeypatch.setattr(appliance, "security_status", lambda: ["PASS: synthetic audit"])
    monkeypatch.setattr(appliance, "_signal_diagnostic", lambda _: pytest.fail("unexpected ready marker"))
    calls = []
    pending = True
    alive = set()

    def read_mounts(path, **kwargs):
        assert path == Path("/proc/mounts")
        return "ramfs / ramfs rw 0 0\n" + "".join(
            f"/dev/sda3 {target} vfat rw 0 0\n" for target in alive
        )

    def command(args, **kwargs):
        calls.append(args)
        if args[0] == "mount":
            def time_out(timeout):
                raise appliance.subprocess.TimeoutExpired(args, timeout)
            return SimpleNamespace(
                wait=time_out, kill=lambda: None, poll=lambda: None if pending else -9,
            )
        if args[0] == "umount":
            alive.remove(Path(args[1]))
        return SimpleNamespace(wait=lambda timeout: 0, poll=lambda: 0)

    monkeypatch.setattr(Path, "read_text", read_mounts)
    monkeypatch.setattr(appliance.subprocess, "Popen", command)
    assert not appliance._rescan_transfer()
    assert appliance._media_command_marker().exists()
    assert not appliance.mount_transfer()
    assert not appliance._poweroff()
    assert [args[0] for args in calls] == ["mount"]
    assert "mounted." not in capsys.readouterr().out

    pending = False
    alive.update((transfer, vault))
    assert appliance._poweroff()
    assert not alive
    assert [args[0] for args in calls] == ["mount", "umount", "umount", "sync", "poweroff"]
    assert lock.exists()
    assert not appliance._media_command_marker().exists()


def test_pending_marker_survives_console_respawn(monkeypatch, tmp_path):
    lock = tmp_path / "lockdown"
    monkeypatch.setattr(appliance, "LOCKDOWN", lock)
    monkeypatch.setattr(appliance, "_pending_media_command", None)
    appliance._media_command_marker().touch()
    monkeypatch.setattr(appliance.subprocess, "Popen", lambda *a, **kw: pytest.fail("unexpected command"))
    assert not appliance.mount_transfer()
    assert not appliance._poweroff()
    safe, findings = gui.runtime_audit(lockdown=lock)
    assert not safe
    assert "FAIL: removable filesystem command completion is unconfirmed" in findings


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
    monkeypatch.setattr(appliance, "_run_media_command", lambda args: calls.append(args[0]) or args[0] != failure)
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
