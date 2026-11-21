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
    policy.save_profile(path, newer, ROOT, PASSWORD, replace=True)
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
        policy.save_profile(path, next_profile, ROOT, PASSWORD, replace=True)
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
        policy.save_profile(path, old, ROOT, PASSWORD, replace=True)
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
        policy.save_profile(path, old, ROOT, PASSWORD, replace=True)
    assert path.read_bytes() == prior
    assert len(list(tmp_path.glob(".policy-*.partial"))) == 1  # preserve attacker's replacement
