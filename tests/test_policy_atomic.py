"""Issue #21: encrypted policy publication under interrupted writes and path swaps."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from usb_cold_wallet import policy
from usb_cold_wallet.keys import root_from_mnemonic

ROOT = root_from_mnemonic("abandon " * 11 + "about")
PASSWORD = "test-only-policy-backup-passphrase"


def test_create_only_cannot_replace_existing_policy(tmp_path):
    path = tmp_path / "wallet.policy"
    old = policy.default_profile(ROOT)
    policy.save_profile(path, old, ROOT, PASSWORD)
    original = path.read_bytes()
    with pytest.raises((OSError, ValueError)):
        policy.save_profile(path, old, ROOT, PASSWORD, replace=False)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".policy-*.partial"))


def test_policy_replace_syncs_file_and_directory_and_updates_anchor(tmp_path, monkeypatch):
    path = tmp_path / "wallet.policy"
    old = policy.default_profile(ROOT)
    policy.save_profile(path, old, ROOT, PASSWORD)
    original_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    newer = policy.set_limit(old, ROOT, "evm_max_fee_wei", 100)
    fsync_real = policy.os.fsync
    targets = []

    def recording_fsync(fd):
        targets.append("dir" if os.fstat(fd).st_mode & 0o170000 == 0o040000 else "file")
        return fsync_real(fd)

    monkeypatch.setattr(policy.os, "fsync", recording_fsync)
    policy.save_profile(path, newer, ROOT, PASSWORD, replace=True,
                        expected_sha256=original_digest)
    assert targets == ["file", "dir"]
    latest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert latest != original_digest
    assert policy.load_profile(path, ROOT, PASSWORD, expected_sha256=latest) == newer
    with pytest.raises(ValueError, match="mismatched"):
        policy.load_profile(path, ROOT, PASSWORD, expected_sha256=original_digest)


def test_failed_staged_file_fsync_preserves_original_and_cleans_partial(tmp_path, monkeypatch):
    path = tmp_path / "wallet.policy"
    old = policy.default_profile(ROOT)
    policy.save_profile(path, old, ROOT, PASSWORD)
    original = path.read_bytes()
    next_profile = policy.set_limit(old, ROOT, "btc_max_fee_sats", 10)
    real_fsync = policy.os.fsync

    def failing_file_fsync(fd):
        if os.fstat(fd).st_mode & 0o170000 == 0o100000:
            raise OSError("injected file fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(policy.os, "fsync", failing_file_fsync)
    with pytest.raises(OSError, match="injected"):
        policy.save_profile(path, next_profile, ROOT, PASSWORD, replace=True,
                            expected_sha256=hashlib.sha256(original).hexdigest())
    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".policy-*.partial"))


def test_failed_replace_preserves_original_and_cleans_partial(tmp_path, monkeypatch):
    path = tmp_path / "wallet.policy"
    old = policy.default_profile(ROOT)
    policy.save_profile(path, old, ROOT, PASSWORD)
    original = path.read_bytes()

    def fail_replace(*_args, **_kwargs):
        raise OSError("injected rename failure")

    monkeypatch.setattr(policy.os, "replace", fail_replace)
    with pytest.raises(OSError, match="injected"):
        policy.save_profile(path, old, ROOT, PASSWORD, replace=True,
                            expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".policy-*.partial"))


@pytest.mark.parametrize("destination", ["symlink", "directory", "fifo"])
def test_refuses_nonregular_policy_target(tmp_path, destination):
    path = tmp_path / "wallet.policy"
    if destination == "symlink":
        target = tmp_path / "other"
        target.write_bytes(b"unrelated")
        path.symlink_to(target)
    elif destination == "directory":
        path.mkdir()
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("POSIX fifo only")
        os.mkfifo(path)
    with pytest.raises(ValueError, match="symlink|regular"):
        policy.save_profile(path, policy.default_profile(ROOT), ROOT, PASSWORD, replace=True)
    assert not list(tmp_path.glob(".policy-*.partial"))


def test_parent_symlink_rejected_before_writing(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    link = tmp_path / "redirect"
    link.symlink_to(actual, target_is_directory=True)
    with pytest.raises(OSError):
        policy.save_profile(link / "wallet.policy", policy.default_profile(ROOT), ROOT, PASSWORD)
    assert not list(actual.iterdir())


def test_stage_replacement_detected_and_unrelated_file_preserved(tmp_path, monkeypatch):
    path = tmp_path / "wallet.policy"
    old = policy.default_profile(ROOT)
    policy.save_profile(path, old, ROOT, PASSWORD)
    prior = path.read_bytes()
    # Pre-create a distinct inode: unlink + recreate can reuse the exact
    # original inode on some filesystems, making this test nondeterministic.
    attacker = tmp_path / "attacker"
    attacker.write_bytes(b"attacker-stage")
    real_stat = policy.os.stat
    switched = False

    def swap_stage(path_arg, *args, **kwargs):
        nonlocal switched
        if not switched and isinstance(path_arg, str) and path_arg.startswith(".policy-") and kwargs.get("dir_fd") is not None:
            switched = True
            os.replace(attacker, tmp_path / path_arg)
        return real_stat(path_arg, *args, **kwargs)

    monkeypatch.setattr(policy.os, "stat", swap_stage)
    with pytest.raises(ValueError, match="staging file changed"):
        policy.save_profile(path, old, ROOT, PASSWORD, replace=True,
                            expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    assert path.read_bytes() == prior
    assert len(list(tmp_path.glob(".policy-*.partial"))) == 1  # preserve attacker's replacement


def test_directory_fsync_failure_reports_uncertain_publication(tmp_path, monkeypatch):
    path = tmp_path / "wallet.policy"
    old = policy.default_profile(ROOT)
    policy.save_profile(path, old, ROOT, PASSWORD)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    changed = policy.set_limit(old, ROOT, "btc_max_fee_sats", 99)
    actual_fsync = policy.os.fsync

    def fail_directory_sync(fd):
        if os.fstat(fd).st_mode & 0o170000 == 0o040000:
            raise OSError("injected directory fsync failure")
        return actual_fsync(fd)

    monkeypatch.setattr(policy.os, "fsync", fail_directory_sync)
    with pytest.raises(OSError, match="directory fsync"):
        policy.save_profile(path, changed, ROOT, PASSWORD, replace=True,
                            expected_sha256=digest)
    # Rename succeeded, though crash durability remains unproven.
    new_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert new_digest != digest
    assert policy.load_profile(path, ROOT, PASSWORD, expected_sha256=new_digest) == changed
    assert not list(tmp_path.glob(".policy-*.partial"))


def test_stale_policy_editor_denied_and_first_update_preserved(tmp_path):
    path = tmp_path / "wallet.policy"
    original = policy.default_profile(ROOT)
    policy.save_profile(path, original, ROOT, PASSWORD)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    first = policy.set_limit(original, ROOT, "btc_max_fee_sats", 100)
    second = policy.set_limit(original, ROOT, "btc_max_fee_sats", 200)
    policy.save_profile(path, first, ROOT, PASSWORD, replace=True,
                        expected_sha256=digest)
    with pytest.raises(ValueError, match="Stale policy"):
        policy.save_profile(path, second, ROOT, PASSWORD, replace=True,
                            expected_sha256=digest)
    assert policy.load_profile(path, ROOT, PASSWORD) == first


def test_policy_replace_requires_expected_digest(tmp_path):
    path = tmp_path / "wallet.policy"
    profile = policy.default_profile(ROOT)
    policy.save_profile(path, profile, ROOT, PASSWORD)
    with pytest.raises(ValueError, match="current policy SHA-256"):
        policy.save_profile(path, profile, ROOT, PASSWORD, replace=True)


def test_untrusted_writable_policy_directory_rejected(tmp_path):
    folder = tmp_path / "untrusted"
    folder.mkdir(mode=0o700)
    folder.chmod(0o777)
    try:
        with pytest.raises(ValueError, match="signer-private"):
            policy.save_profile(folder / "wallet.policy", policy.default_profile(ROOT),
                                ROOT, PASSWORD)
        assert not list(folder.iterdir())
    finally:
        folder.chmod(0o700)


def test_simultaneous_editors_cannot_both_publish_stale_version(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    import threading

    path = tmp_path / "wallet.policy"
    original = policy.default_profile(ROOT)
    policy.save_profile(path, original, ROOT, PASSWORD)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    barrier = threading.Barrier(2)

    def update(amount):
        profile = policy.set_limit(original, ROOT, "btc_max_fee_sats", amount)
        barrier.wait(timeout=10)
        try:
            policy.save_profile(path, profile, ROOT, PASSWORD, replace=True,
                                expected_sha256=digest)
            return "saved"
        except ValueError as exc:
            assert "Stale policy" in str(exc)
            return "stale"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(update, (10, 20)))
    assert sorted(outcomes) == ["saved", "stale"]
    assert policy.load_profile(path, ROOT, PASSWORD)["limits"]["btc_max_fee_sats"] in (10, 20)


def test_create_only_racing_destination_rename_never_clobbers(tmp_path, monkeypatch):
    from usb_cold_wallet import vault

    path = tmp_path / "wallet.policy"
    real_publish = vault._atomic_rename_noreplace

    def competing_writer(parent_fd, stage, name):
        # Race: destination is created after target preflight but immediately
        # before Linux renameat2(RENAME_NOREPLACE).
        with os.fdopen(os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                               0o600, dir_fd=parent_fd), "wb") as stream:
            stream.write(b"another-writer")
            stream.flush()
            os.fsync(stream.fileno())
        real_publish(parent_fd, stage, name)

    monkeypatch.setattr(vault, "_atomic_rename_noreplace", competing_writer)
    with pytest.raises(FileExistsError):
        policy.save_profile(path, policy.default_profile(ROOT), ROOT, PASSWORD)
    assert path.read_bytes() == b"another-writer"
    assert not list(tmp_path.glob(".policy-*.partial"))


def test_policy_stage_swapped_during_publish_is_detected(tmp_path, monkeypatch):
    """Post-rename descriptor identity check exposes a same-UID swap.

    This is detection, not a defense against same-UID/root malware. The attack
    can leave a suspicious final entry, which must be manually reconciled.
    """
    path = tmp_path / "wallet.policy"
    old = policy.default_profile(ROOT)
    policy.save_profile(path, old, ROOT, PASSWORD)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    foreign = tmp_path / "malicious-staged"
    foreign.write_bytes(b"ATTACKER CIPHERTEXT SUBSTITUTE")
    real_replace = policy.os.replace
    injected = False

    def substitute_source(src, dst, *args, **kwargs):
        nonlocal injected
        if not injected and isinstance(src, str) and src.startswith(".policy-") and dst == path.name:
            injected = True
            # Replace the validated staging name just before the real rename.
            real_replace(foreign, tmp_path / src)
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(policy.os, "replace", substitute_source)
    changed = policy.set_limit(old, ROOT, "btc_max_fee_sats", 125)
    with pytest.raises(OSError, match="published file differs"):
        policy.save_profile(path, changed, ROOT, PASSWORD,
                            replace=True, expected_sha256=digest)
    assert injected
    assert path.read_bytes() == b"ATTACKER CIPHERTEXT SUBSTITUTE"
    assert not list(tmp_path.glob(".policy-*.partial"))


def test_policy_create_only_racing_destination_cannot_be_replaced(tmp_path, monkeypatch):
    """RENAME_NOREPLACE must fail even if destination appears during publish."""
    from usb_cold_wallet import vault

    path = tmp_path / "wallet.policy"
    original_rename = vault._atomic_rename_noreplace
    injected = False

    def competing_create(parent_fd, stage, final):
        nonlocal injected
        injected = True
        fd = os.open(final, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                     0o600, dir_fd=parent_fd)
        try:
            os.write(fd, b"EXISTING POLICY")
        finally:
            os.close(fd)
        return original_rename(parent_fd, stage, final)

    monkeypatch.setattr(vault, "_atomic_rename_noreplace", competing_create)
    with pytest.raises(FileExistsError):
        policy.save_profile(path, policy.default_profile(ROOT), ROOT, PASSWORD)
    assert injected
    assert path.read_bytes() == b"EXISTING POLICY"
    assert not list(tmp_path.glob(".policy-*.partial"))
