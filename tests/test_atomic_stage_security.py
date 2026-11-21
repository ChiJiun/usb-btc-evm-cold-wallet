"""Post-review #49: trusted directory and publish identity security boundaries.

No private keys, actual USB or destructive filesystem operations.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from usb_cold_wallet import vault


def _publish(tmp_path: Path, filename="signed.json", payload=b'{"test":true}\n'):
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        vault.atomic_create_at(parent, filename, payload)
    finally:
        os.close(parent)


@pytest.mark.parametrize("mode", [0o720, 0o707, 0o750, 0o755, 0o777])
def test_atomic_export_refuses_other_writers_before_creating_stage(tmp_path, mode):
    original_mode = tmp_path.stat().st_mode & 0o777
    tmp_path.chmod(mode)
    try:
        with pytest.raises(PermissionError, match="signer-private directory"):
            _publish(tmp_path)
        assert not (tmp_path / "signed.json").exists()
        assert not list(tmp_path.glob(".usbwallet-*.partial"))
    finally:
        tmp_path.chmod(original_mode)


def test_private_directory_normal_export_keeps_published_inode(tmp_path):
    _publish(tmp_path)
    assert (tmp_path / "signed.json").read_bytes() == b'{"test":true}\n'
    assert not list(tmp_path.glob(".usbwallet-*.partial"))


def test_swapped_stage_between_identity_check_and_publish_is_reported(monkeypatch, tmp_path):
    real_rename = vault._atomic_rename_noreplace
    payload = b"foreign injected data"

    def replace_before_rename(parent_fd, stage, final):
        # Simulates a compromised *same-UID* process, which violates the
        # private-directory single-writer requirement even with mode 0700.
        os.unlink(stage, dir_fd=parent_fd)
        attack_fd = os.open(stage, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600,
                            dir_fd=parent_fd)
        try:
            os.write(attack_fd, payload)
        finally:
            os.close(attack_fd)
        real_rename(parent_fd, stage, final)

    monkeypatch.setattr(vault, "_atomic_rename_noreplace", replace_before_rename)
    with pytest.raises(OSError, match="does not match staged descriptor"):
        _publish(tmp_path)
    # Our code refuses to report success; a privileged attacker can still
    # publish a foreign file. Do not blindly delete an unrelated final entry.
    assert (tmp_path / "signed.json").read_bytes() == payload


def test_cleanup_does_not_delete_stage_swapped_before_identity_check(monkeypatch, tmp_path):
    real_fsync = vault.os.fsync
    injected = b"other-owned-stage"

    def inject_and_fail(fd):
        if os.path.isdir(f"/proc/self/fd/{fd}"):
            return real_fsync(fd)
        stages = list(tmp_path.glob(".usbwallet-*.partial"))
        assert len(stages) == 1
        stage = stages[0]
        stage.unlink()
        stage.write_bytes(injected)
        raise OSError(errno.EIO, "simulated stage writeback failure")

    monkeypatch.setattr(vault.os, "fsync", inject_and_fail)
    with pytest.raises(OSError, match="writeback failure"):
        _publish(tmp_path)
    assert not (tmp_path / "signed.json").exists()
    stages = list(tmp_path.glob(".usbwallet-*.partial"))
    assert len(stages) == 1
    assert stages[0].read_bytes() == injected, "Unrelated substituted inode must not be removed"
