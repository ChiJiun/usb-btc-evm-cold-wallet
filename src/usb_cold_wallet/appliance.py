"""Single-purpose text console for the bootable air-gapped appliance."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

VAULT = Path("/mnt/cold-vault/wallet.vault")
TRANSFER = Path("/mnt/transfer")
BOOT_CHECKS = Path("/run/usb-wallet/boot-checks.txt")
LOCKDOWN = Path("/run/usb-wallet/lockdown")
BOOT_PARENT_FILE = Path("/run/usb-wallet/boot-parent")
VAULT_DEVICE_FILE = Path("/run/usb-wallet/vault-device")
SAFE_MOUNT_OPTIONS = "rw,noexec,nodev,nosuid,sync,fmask=0177,dmask=0077"


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


def _block_parent(device: str) -> str | None:
    try:
        resolved = (Path("/sys/class/block") / Path(device).name).resolve(strict=True)
    except OSError:
        return None
    parent = resolved.parent.name
    if not (Path("/sys/class/block") / parent).exists():
        return None
    return parent


def _blkid(*args: str) -> list[str]:
    result = subprocess.run(
        ["blkid", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode not in (0, 2):
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _unique_transfer_device() -> str | None:
    devices = _blkid("-t", "LABEL=TX_TRANSFER", "-o", "device")
    if len(devices) != 1:
        return None
    device = devices[0]

    types = _blkid("-s", "TYPE", "-o", "value", device)
    if types != ["vfat"]:
        return None

    try:
        boot_parent = BOOT_PARENT_FILE.read_text(encoding="utf-8").strip()
        vault_device = VAULT_DEVICE_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None

    parent = _block_parent(device)
    if not parent or parent == boot_parent or device == vault_device:
        return None
    return device


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

    try:
        boot_parent = BOOT_PARENT_FILE.read_text(encoding="utf-8").strip()
        vault_device = VAULT_DEVICE_FILE.read_text(encoding="utf-8").strip()
        if not boot_parent or not vault_device:
            raise ValueError
        status.append("PASS: verified boot/vault device identity remains available")
    except (OSError, ValueError):
        status.append("FAIL: verified boot/vault device identity missing")

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
    device = _unique_transfer_device()
    if device is None:
        return False
    if _mounted(TRANSFER):
        return _safe_transfer_mount(device)
    result = subprocess.run(
        ["mount", "-t", "vfat", "-o", SAFE_MOUNT_OPTIONS, device, str(TRANSFER)],
        check=False,
    )
    return result.returncode == 0 and _safe_transfer_mount(device)


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
            "TX_TRANSFER USB unavailable or ambiguous. "
            "Use exactly one separate VFAT USB labelled TX_TRANSFER."
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
    recipient = input("Independently verified Sepolia recipient (0x...): ").strip()
    wei = input("Independently verified value in wei: ").strip()
    output = TRANSFER / (source.stem + ".signed.json")
    # Appliance JSON transport is always the bounded #5/#11 request envelope.
    # Do not pre-read untrusted USB content here and then read it again in the
    # CLI: a malicious device could present different bytes between reads.
    _run_cli([
        "sign-evm", "--request", str(source), "--to", recipient,
        "--wei", wei, "--out", str(output),
    ])


def _sign_btc() -> None:
    source = _select_file((".psbt", ".json"))
    if source is None:
        return
    recipient = input("Independently verified Bitcoin TESTNET recipient (tb1...): ").strip()
    sats = input("Independently verified value in satoshis: ").strip()
    max_fee = input("Maximum acceptable fee in satoshis: ").strip()
    change = input("Expected BIP84 change index (blank if no change): ").strip()
    output = TRANSFER / (source.stem + ".signed.json")
    # The suffix decides only the transport parser. JSON is always a strict
    # btc-request envelope; content is read exactly once by the CLI parser.
    source_flag = "--request" if source.suffix.lower() == ".json" else "--psbt"
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
