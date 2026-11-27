"""Host-side regressions for the QEMU boot evidence deadline."""

from types import SimpleNamespace

import pytest

from scripts import verify_delayed_usb as harness


@pytest.fixture
def guest(monkeypatch):
    elapsed = 0.0
    guest = SimpleNamespace(log="", exit_code=None, pending=[])

    def advance(seconds):
        nonlocal elapsed
        elapsed += seconds
        while guest.pending and guest.pending[0][0] <= elapsed:
            _, marker = guest.pending.pop(0)
            guest.log += marker + "\n"

    monkeypatch.setattr(harness, "time", SimpleNamespace(monotonic=lambda: elapsed, sleep=advance))
    guest.serial = SimpleNamespace(exists=lambda: True, read_text=lambda **_: guest.log)
    guest.process = SimpleNamespace(poll=lambda: guest.exit_code)
    guest.elapsed = lambda: elapsed
    return guest


def test_wait_reads_serial_on_deadline(guest):
    guest.pending = [(1.0, "ready")]
    assert harness.wait_for(guest.serial, guest.process, lambda log: "ready" in log, 1.0) == "ready\n"
    assert guest.elapsed() == 1.0


def test_lockdown_console_shares_the_original_boot_deadline(guest):
    guest.pending = [(60.0, harness.AUDIT_LOCKDOWN), (72.0, harness.LOCKDOWN_READY)]
    assert harness.LOCKDOWN_READY in harness.wait_for_boot_console(guest.serial, guest.process, attach=False)
    assert 72.0 <= guest.elapsed() <= 72.2


def test_lockdown_audit_without_console_is_not_success(guest):
    guest.pending = [(60.0, harness.AUDIT_LOCKDOWN)]
    with pytest.raises(RuntimeError, match="deadline expired"):
        harness.wait_for_boot_console(guest.serial, guest.process, attach=False)
    assert guest.elapsed() == 100.0


@pytest.mark.parametrize("attach,marker", [(True, harness.AUDIT_LOCKDOWN), (False, harness.AUDIT_OK)])
def test_wrong_audit_mode_fails_immediately(guest, attach, marker):
    guest.log = marker
    with pytest.raises(RuntimeError, match="contradictory"):
        harness.wait_for_boot_console(guest.serial, guest.process, attach=attach)
    assert guest.elapsed() == 0


def test_console_readiness_must_follow_audit(guest):
    guest.log = f"{harness.LOCKDOWN_READY}\n{harness.AUDIT_LOCKDOWN}\n"
    with pytest.raises(RuntimeError, match="before startup audit"):
        harness.wait_for_boot_console(guest.serial, guest.process, attach=False)


def test_qemu_exit_without_evidence_fails(guest):
    guest.exit_code = 1
    with pytest.raises(RuntimeError, match="QEMU exited"):
        harness.wait_for_boot_console(guest.serial, guest.process, attach=False)
