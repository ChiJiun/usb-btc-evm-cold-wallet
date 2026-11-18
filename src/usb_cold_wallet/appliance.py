"""Single-purpose text console for the bootable air-gapped appliance."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

from .exchange import read_envelope

VAULT = Path("/mnt/cold-vault/wallet.vault")
TRANSFER = Path("/mnt/transfer")
BOOT_CHECKS = Path("/run/usb-wallet/boot-checks.txt")
LOCKDOWN = Path("/run/usb-wallet/lockdown")
SAFE_MOUNT_OPTIONS = "rw,noexec,nodev,nosuid,sync,fmask=0177,dmask=0077"
BOOT_PARTUUID = "e2bd6d1b-8de5-502d-a897-c53a8e60f46b"
VAULT_PARTUUID = "18f1c36f-d5c0-5052-9cd2-03e9c2a48f00"


def _mount_info(path: Path) -> tuple[str, str, set[str]] | None:
    try:
        entries = Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    needle = str(path)
    for line in entries:
        fields = line.split()
        if len(fields) >= 4 and fields[1] == needle:
            return fields[0], fields[2], set(fields[3].split(","))
    return None


def _mounted(path: Path) -> bool:
    return _mount_info(path) is not None


def _blkid_devices(tag: str) -> list[str]:
    result = subprocess.run(
        ["blkid", "-t", tag, "-o", "device"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []
    return [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip().startswith("/dev/")
    ]


def _unique_blkid_device(tag: str) -> str | None:
    devices = _blkid_devices(tag)
    return devices[0] if len(devices) == 1 else None


def _scsi_parent(device: str) -> str | None:
    match = re.fullmatch(r"(/dev/sd[a-z]+)\d+", device)
    return match.group(1) if match else None


def _transfer_candidate() -> str | None:
    candidate = _unique_blkid_device("LABEL=TX_TRANSFER")
    boot = _unique_blkid_device(f"PARTUUID={BOOT_PARTUUID}")
    vault = _unique_blkid_device(f"PARTUUID={VAULT_PARTUUID}")
    if candidate is None or boot is None or vault is None:
        return None

    boot_parent = _scsi_parent(boot)
    vault_parent = _scsi_parent(vault)
    transfer_parent = _scsi_parent(candidate)
    if (
        boot_parent is None
        or vault_parent is None
        or transfer_parent is None
        or boot_parent != vault_parent
        or transfer_parent == boot_parent
    ):
        return None
    return candidate


def _safe_transfer_mount(expected_source: str) -> bool:
    info = _mount_info(TRANSFER)
    if info is None:
        return False
    source, filesystem, options = info
    return (
        source == expected_source
        and filesystem == "vfat"
        and {"rw", "noexec", "nodev", "nosuid", "sync"} <= options
    )


def security_status() -> list[str]:
    try:
        boot_lines = BOOT_CHECKS.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ["FAIL: boot security audit missing"]

    status = [line for line in boot_lines if line.startswith(("PASS:", "FAIL:"))]
    if not status:
        return ["FAIL: boot security audit contained no checks"]

    status.append(
        "PASS: live network stack absent"
        if not Path("/proc/net").exists()
        else "FAIL: live /proc/net exists"
    )
    try:
        swaps = Path("/proc/swaps").read_text(encoding="utf-8").strip().splitlines()
        status.append(
            "PASS: live swap remains disabled"
            if len(swaps) <= 1
            else "FAIL: active swap detected"
        )
    except OSError:
        status.append("FAIL: unable to inspect live swap state")
    return status


def _security_locked(status: list[str]) -> bool:
    return LOCKDOWN.exists() or any(item.startswith("FAIL:") for item in status)


def mount_transfer() -> bool:
    TRANSFER.mkdir(parents=True, exist_ok=True)
    candidate = _transfer_candidate()
    if candidate is None:
        return False
    if _mounted(TRANSFER):
        return _safe_transfer_mount(candidate)
    result = subprocess.run(
        [
            "mount", "-t", "vfat", "-o", SAFE_MOUNT_OPTIONS,
            candidate, str(TRANSFER),
        ],
        check=False,
    )
    return result.returncode == 0 and _safe_transfer_mount(candidate)


def unmount_transfer() -> None:
    if _mounted(TRANSFER):
        subprocess.run(["umount", str(TRANSFER)], check=False)


def _run_cli(arguments: list[str]) -> None:
    subprocess.run(
        [sys.executable, "-m", "usb_cold_wallet.cli", "--vault", str(VAULT), *arguments],
        check=False,
    )


def _select_file(suffix: str | tuple[str, ...]) -> Path | None:
    if not mount_transfer():
        print(
            "TX_TRANSFER USB missing/ambiguous/unsafe. "
            "Use exactly one separate FAT USB labelled TX_TRANSFER."
        )
        return None
    suffixes = (suffix,) if isinstance(suffix, str) else suffix
    files = sorted(
        p for p in TRANSFER.iterdir()
        if p.is_file() and p.name.lower().endswith(suffixes)
    )
    if not files:
        print(f"No matching transfer file ({', '.join(suffixes)}) found.")
        return None
    for index, path in enumerate(files, start=1):
        print(f"  {index}. {path.name}")
    try:
        selected = int(input("Select file number: "))
        if not 1 <= selected <= len(files):
            raise ValueError("selection out of range")
        return files[selected - 1]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return None


def _exchange_kind(path: Path) -> str | None:
    try:
        return read_envelope(path)["kind"]
    except (ValueError, OSError, KeyError, TypeError):
        return None


def _new_wallet() -> None:
    if VAULT.exists():
        print("Encrypted vault already exists; refusing to overwrite it.")
        return
    _run_cli(["init", "--offline-ack", "--i-have-paper-backup"])


def _addresses() -> None:
    if not VAULT.exists():
        print("Create or restore a test wallet first.")
        return
    _run_cli(["addresses", "--count", "5"])


def _sign_evm() -> None:
    source = _select_file(".json")
    if source is None:
        return
    kind = _exchange_kind(source)
    if kind not in (None, "evm-request"):
        print(f"Wrong exchange envelope kind for EVM signing: {kind}")
        return
    recipient = input("Independently verified Sepolia recipient (0x...): ").strip()
    wei = input("Independently verified value in wei: ").strip()
    output = TRANSFER / (source.stem + ".signed.json")
    source_flag = "--request" if kind == "evm-request" else "--tx"
    _run_cli([
        "sign-evm", source_flag, str(source), "--to", recipient,
        "--wei", wei, "--out", str(output),
    ])


def _sign_btc() -> None:
    source = _select_file((".psbt", ".json"))
    if source is None:
        return
    kind = _exchange_kind(source) if source.suffix.lower() == ".json" else None
    if source.suffix.lower() == ".json" and kind != "btc-request":
        print("Bitcoin JSON transport must be a verified btc-request envelope.")
        return
    recipient = input("Independently verified Bitcoin TESTNET recipient (tb1...): ").strip()
    sats = input("Independently verified value in satoshis: ").strip()
    max_fee = input("Maximum acceptable fee in satoshis: ").strip()
    change = input("Expected BIP84 change index (blank if no change): ").strip()
    output = TRANSFER / (source.stem + ".signed.json")
    source_flag = "--request" if kind == "btc-request" else "--psbt"
    args = [
        "sign-btc", source_flag, str(source), "--to", recipient,
        "--sats", sats, "--max-fee-sats", max_fee, "--out", str(output),
    ]
    if change:
        args.extend(["--change-index", change])
    _run_cli(args)


def main() -> int:
    os.environ["HISTFILE"] = "/dev/null"
    while True:
        print("\n=== USB BTC + EVM COLD WALLET ===")
        print("TESTNET RESEARCH APPLIANCE — NOT AUDITED FOR REAL FUNDS")
        status = security_status()
        for item in status:
            print(item)
        if _security_locked(status):
            print("\nLOCKDOWN: wallet creation/signing is disabled because a boot security check failed.")
            print("6) Power off")
            if input("> ").strip() == "6":
                unmount_transfer()
                subprocess.run(["poweroff"], check=False)
                return 1
            continue
        print("\n1) Create encrypted TESTNET wallet")
        print("2) Show public BTC testnet + Sepolia addresses")
        print("3) Sign Sepolia native ETH transaction")
        print("4) Sign Bitcoin testnet PSBT")
        print("5) Re-scan TX_TRANSFER USB")
        print("6) Power off")
        choice = input("> ").strip()
        if choice == "1":
            _new_wallet()
        elif choice == "2":
            _addresses()
        elif choice == "3":
            _sign_evm()
        elif choice == "4":
            _sign_btc()
        elif choice == "5":
            unmount_transfer()
            print("TX_TRANSFER mounted." if mount_transfer() else "TX_TRANSFER not found or unsafe.")
        elif choice == "6":
            unmount_transfer()
            subprocess.run(["poweroff"], check=False)
            return 0
        else:
            print("Unknown option.")


if __name__ == "__main__":
    raise SystemExit(main())
