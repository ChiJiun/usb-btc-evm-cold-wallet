"""No secrets: deterministic fake clock and public transaction digests only."""
import pytest

from usb_cold_wallet.signer_session import SignerSession, State


@pytest.fixture
def setup():
    data = {"time": 1000.0, "audit": True, "clears": 0}

    def clear():
        data["clears"] += 1

    machine = SignerSession(audit=lambda: data["audit"], on_lock=clear,
                            clock=lambda: data["time"], idle_seconds=600,
                            max_transactions=3)
    return machine, data


def unlock(machine):
    machine.begin_unlock()
    assert machine.state == State.UNLOCKING
    machine.unlock_succeeded()
    assert machine.state == State.REVIEWING


def test_locked_start_and_full_signing_sequence(setup):
    machine, data = setup
    assert machine.state == State.LOCKED
    with pytest.raises(ValueError):
        machine.start_review("a" * 64)
    unlock(machine)
    digest = "a" * 64
    machine.start_review(digest)
    with pytest.raises(ValueError):
        machine.signing(digest)
    assert machine.state == State.LOCKED
    unlock(machine)
    machine.start_review(digest)
    machine.approve(digest)
    assert machine.state == State.APPROVED
    machine.signing(digest)
    machine.signed(digest)
    assert machine.state == State.SIGNED
    assert machine.transaction_count == 1
    # Every additional transaction starts from its own review and approval.
    machine.start_review("b" * 64)
    machine.approve("b" * 64)
    machine.signing("b" * 64)
    machine.signed("b" * 64)
    assert machine.transaction_count == 2
    machine.start_review("c" * 64)
    machine.approve("c" * 64)
    machine.signing("c" * 64)
    machine.signed("c" * 64)
    assert machine.state == State.LOCKED
    assert data["clears"] >= 1


def test_second_transaction_cannot_skip_approval(setup):
    machine, _ = setup
    unlock(machine)
    machine.start_review("a" * 64)
    machine.approve("a" * 64)
    machine.signing("a" * 64)
    machine.signed("a" * 64)
    machine.start_review("b" * 64)
    with pytest.raises(ValueError):
        machine.signing("b" * 64)
    assert machine.state == State.LOCKED


def test_idle_deadline_and_sign_after_lock_denied(setup):
    machine, data = setup
    unlock(machine)
    machine.start_review("a" * 64)
    data["time"] += 599
    assert not machine.tick()
    data["time"] += 1
    assert machine.tick()
    assert machine.state == State.LOCKED
    with pytest.raises(ValueError):
        machine.approve("a" * 64)


def test_absolute_deadline_cannot_be_extended_by_activity(setup):
    machine, data = setup
    unlock(machine)
    for _ in range(4):
        data["time"] += 200
        machine.activity()
    data["time"] += 100
    assert machine.tick()
    assert machine.state == State.LOCKED


def test_unlock_prompt_can_take_time_but_has_hard_deadline(setup):
    machine, data = setup
    machine.begin_unlock()
    data["time"] += 100
    assert not machine.tick()
    machine.unlock_succeeded()
    assert machine.state == State.REVIEWING
    machine.lock("manual")
    machine.begin_unlock()
    data["time"] += 120
    assert machine.tick()
    assert machine.state == State.LOCKED
    with pytest.raises(ValueError):
        machine.unlock_succeeded()


def test_failed_unlock_backoff_and_reset(setup):
    machine, data = setup
    for attempt in range(5):
        machine.begin_unlock()
        machine.unlock_failed()
        assert machine.state == State.LOCKED
        assert machine.failed_attempts == attempt + 1
        with pytest.raises(ValueError, match="rate limited"):
            machine.begin_unlock()
        data["time"] += machine.remaining_backoff
    unlock(machine)
    assert machine.failed_attempts == 0


def test_audit_failure_locks_before_signing(setup):
    machine, data = setup
    unlock(machine)
    machine.start_review("a" * 64)
    machine.approve("a" * 64)
    data["audit"] = False
    with pytest.raises(ValueError, match="audit"):
        machine.signing("a" * 64)
    assert machine.state == State.LOCKED


def test_audit_exception_fails_closed(setup):
    machine, data = setup
    data["audit"] = False
    with pytest.raises(ValueError, match="audit"):
        machine.begin_unlock()
    assert machine.state == State.LOCKED


def test_changed_transaction_digest_aborts(setup):
    machine, data = setup
    unlock(machine)
    machine.start_review("a" * 64)
    with pytest.raises(ValueError, match="changed"):
        machine.approve("b" * 64)
    assert machine.state == State.LOCKED


def test_cancel_usb_removal_scan_timeout_and_error_lock(setup):
    machine, data = setup
    for reason in ("cancel", "usb_removed", "scan_timeout", "exception", "powerdown"):
        unlock(machine)
        machine.start_review("f" * 64)
        machine.lock(reason)
        assert machine.state == State.LOCKED
        assert data["clears"] > 0
        with pytest.raises(ValueError):
            machine.signing("f" * 64)


def test_unlocking_denies_sign_and_manual_lock(setup):
    machine, _ = setup
    machine.begin_unlock()
    with pytest.raises(ValueError):
        machine.approve("a" * 64)
    machine.lock("manual")
    assert machine.state == State.LOCKED


def test_non_hex_review_digest_fails_closed(setup):
    machine, data = setup
    unlock(machine)
    with pytest.raises(ValueError, match="digest"):
        machine.start_review("z" * 64)
    assert machine.state == State.LOCKED
    assert data["clears"] >= 1


def test_nonfinite_or_broken_monotonic_clock_always_locks(setup):
    import math
    machine, data = setup
    unlock(machine)
    machine.start_review("a" * 64)
    machine.approve("a" * 64)
    data["time"] = float("nan")
    assert machine.tick()
    assert machine.state == State.LOCKED
    with pytest.raises(ValueError, match="clock"):
        machine.begin_unlock()

    def crashed_clock():
        raise RuntimeError("clock unavailable")
    other = SignerSession(audit=lambda: True, on_lock=lambda: None, clock=crashed_clock)
    with pytest.raises(ValueError, match="clock"):
        other.begin_unlock()
    assert other.state == State.LOCKED


def test_invalid_configuration_rejected():
    for opts in ({"idle_seconds": 0}, {"idle_seconds": 601},
                 {"max_transactions": 6}, {"max_session_seconds": 901}):
        with pytest.raises(ValueError):
            SignerSession(audit=lambda: True, on_lock=lambda: None, **opts)
