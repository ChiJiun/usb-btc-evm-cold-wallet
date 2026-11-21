"""Real Linux VFAT/FAT32 mount integration checks for atomic USB exchange.

Runs only on an explicitly mounted VFAT test filesystem. All contents are
synthetic public test strings; never run against a user's actual USB volume.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

from usb_cold_wallet import vault, policy
from usb_cold_wallet.keys import root_from_mnemonic


PAYLOAD = b'{"kind":"evm-signed","public_test_only":true}\n'
VAULT = {"format": "PUBLIC INTEGRATION TEST", "ciphertext": "non-secret"}


def assert_vfat(mount: Path) -> None:
    fs = subprocess.check_output(
        ["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(mount)],
        text=True,
    ).strip()
    if fs != "vfat":
        raise AssertionError(f"Refusing non-VFAT test mount: {fs!r}")
    if not mount.is_dir() or mount.is_symlink():
        raise AssertionError("Unsafe integration mountpoint")


def assert_no_partial(mount: Path) -> None:
    pending = list(mount.glob(".usbwallet-*.partial"))
    if pending:
        raise AssertionError(f"Staging files unexpectedly retained: {pending}")


def export(mount: Path, name: str, payload: bytes = PAYLOAD) -> None:
    parent = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        vault.atomic_create_at(parent, name, payload)
    finally:
        os.close(parent)


def validate(mount: Path) -> None:
    assert_vfat(mount)
    print("Verified mounted Linux VFAT FAT32 filesystem:", mount, flush=True)

    # A real VFAT renameat2(NO_REPLACE) must succeed without a fallback.
    with patch.object(vault, "_atomic_rename_noreplace",
                      wraps=vault._atomic_rename_noreplace) as rename:
        export(mount, "Signed.JSON")
        assert rename.call_count == 1
    assert (mount / "Signed.JSON").read_bytes() == PAYLOAD
    assert_no_partial(mount)

    # FAT names are case-insensitive. Existing output cannot be replaced
    # even when the spelling has different ASCII case.
    for name in ("Signed.JSON", "signed.json"):
        try:
            export(mount, name, b"SHOULD NEVER OVERWRITE")
        except FileExistsError:
            pass
        else:
            raise AssertionError("renameat2 incorrectly replaced a FAT32 file")
    assert (mount / "Signed.JSON").read_bytes() == PAYLOAD
    assert_no_partial(mount)

    # A short write must be finished before the final .json is published.
    real_write = vault.os.write
    writes = 0
    def short_write(fd: int, data: bytes) -> int:
        nonlocal writes
        writes += 1
        return real_write(fd, data[:5] if writes == 1 else data)
    with patch.object(vault.os, "write", side_effect=short_write):
        export(mount, "short.json")
    assert writes >= 2
    assert (mount / "short.json").read_bytes() == PAYLOAD
    assert_no_partial(mount)

    # A failed write must not publish partially-written output.
    def disk_full(fd: int, data: bytes) -> int:
        real_write(fd, data[:7])
        raise OSError(errno.ENOSPC, "synthetic ENOSPC on VFAT")
    with patch.object(vault.os, "write", side_effect=disk_full):
        try:
            export(mount, "recovery.json")
        except OSError as exc:
            assert exc.errno == errno.ENOSPC
        else:
            raise AssertionError("Injected ENOSPC was swallowed")
    assert not (mount / "recovery.json").exists()
    assert_no_partial(mount)
    export(mount, "recovery.json")
    assert (mount / "recovery.json").read_bytes() == PAYLOAD

    # A file fsync error is fatal before publication.
    def sync_fail(_fd: int) -> None:
        raise OSError(errno.EIO, "synthetic fsync failure")
    with patch.object(vault.os, "fsync", side_effect=sync_fail):
        try:
            export(mount, "unsynced.json")
        except OSError as exc:
            assert exc.errno == errno.EIO
        else:
            raise AssertionError("Injected fsync failure was swallowed")
    assert not (mount / "unsynced.json").exists()
    assert_no_partial(mount)

    # The *actual* VFAT directory fd is fsynced successfully here.
    vault.save_vault(mount / "wallet.vault", VAULT)
    assert json.loads((mount / "wallet.vault").read_text()) == VAULT
    assert_no_partial(mount)

    # Exercise the production encrypted Policy writer on this exact VFAT
    # mount, including Linux flock(), create-only, digest CAS and replace().
    # This widely known BIP39 test fixture must NEVER be used with funds.
    root = root_from_mnemonic("abandon " * 11 + "about")
    password = "public-test-policy-passphrase-only"
    profile_path = mount / "wallet.policy"
    initial = policy.default_profile(root)
    policy.save_profile(profile_path, initial, root, password)
    first_hash = hashlib.sha256(profile_path.read_bytes()).hexdigest()
    updated = policy.set_limit(initial, root, "btc_max_fee_sats", 123)
    policy.save_profile(profile_path, updated, root, password,
                        replace=True, expected_sha256=first_hash)
    second_hash = hashlib.sha256(profile_path.read_bytes()).hexdigest()
    assert second_hash != first_hash
    assert policy.load_profile(profile_path, root, password,
                               expected_sha256=second_hash) == updated
    try:
        policy.save_profile(profile_path, initial, root, password,
                            replace=True, expected_sha256=first_hash)
    except ValueError as exc:
        assert "Stale policy" in str(exc)
    else:
        raise AssertionError("Stale policy overwrote FAT32 profile")
    assert not list(mount.glob(".policy-*.partial"))

    # Record a checksum for verification after an actual unmount/remount.
    fingerprints = {
        filename: hashlib.sha256((mount / filename).read_bytes()).hexdigest()
        for filename in ("Signed.JSON", "short.json", "recovery.json", "wallet.vault", "wallet.policy")
    }
    (mount / ".verification-sha256.json").write_text(
        json.dumps(fingerprints, sort_keys=True), encoding="ascii")
    fd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print("FAT32 atomic export, case collision, ENOSPC, fsync and vault checks PASSED", flush=True)


def validate_insecure_mount(mount: Path) -> None:
    """A VFAT mount with relaxed masks must fail BEFORE staging anything."""
    assert_vfat(mount)
    if not (mount.stat().st_mode & 0o077):
        raise AssertionError("Expected a VFAT mount exposed to other users")
    path = mount / "reject-insecure-mount.json"
    assert not path.exists()
    try:
        export(mount, path.name)
    except PermissionError as exc:
        assert "signer-private directory" in str(exc), exc
    else:
        raise AssertionError("Unsafe VFAT mount allowed a signed export")
    assert not path.exists()
    assert_no_partial(mount)
    # Policy staging must share the same strict mount security invariant.
    root = root_from_mnemonic("abandon " * 11 + "about")
    try:
        policy.save_profile(mount / "deny-policy.profile",
                            policy.default_profile(root), root,
                            "public-test-policy-passphrase-only")
    except ValueError as exc:
        assert "signer-private" in str(exc), exc
    else:
        raise AssertionError("Unsafe FAT32 directory allowed encrypted policy")
    assert not (mount / "deny-policy.profile").exists()
    assert not list(mount.glob(".policy-*.partial"))
    print("VFAT insecure umask=0022 rejected for signed export and policy", flush=True)


def validate_remount(mount: Path) -> None:
    assert_vfat(mount)
    fingerprints = json.loads((mount / ".verification-sha256.json").read_text())
    for filename, expected in fingerprints.items():
        actual = hashlib.sha256((mount / filename).read_bytes()).hexdigest()
        if actual != expected:
            raise AssertionError(f"Corrupt data after VFAT remount: {filename}")
    assert_no_partial(mount)
    try:
        export(mount, "Signed.JSON")
    except FileExistsError:
        pass
    else:
        raise AssertionError("Existing signed JSON replaced after remount")
    print("VFAT FAT32 remount data-integrity and no-replace checks PASSED", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mount", type=Path)
    parser.add_argument("--after-remount", action="store_true")
    parser.add_argument("--reject-insecure-mount", action="store_true")
    args = parser.parse_args()
    if args.after_remount and args.reject_insecure_mount:
        parser.error("Only one mounted-VFAT scenario may be selected")
    if args.reject_insecure_mount:
        validate_insecure_mount(args.mount)
    elif args.after_remount:
        validate_remount(args.mount)
    else:
        validate(args.mount)


if __name__ == "__main__":
    main()
