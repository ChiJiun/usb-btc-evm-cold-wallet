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
SAFE_MOUNT_OPTIONS = "rw,noexec,nodev,nosuid,sync,fmask=0177,dmask=0077"


def _mounted(path: Path) -> bool:
    try:
        entries = Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    needle = str(path)
    return any(len(line.split()) >= 2 and line.split()[1] == needle for line in entries)


def security_status() -> list[str]:
    try:
        boot_lines = BOOT_CHECKS.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ["FAIL: boot security audit missing"]

    status = [line for line in boot_lines if line.startswith(("PASS:", "FAIL:"))]
    if not status:
        return ["FAIL: boot security audit contained no checks"]

    # Re-check the two invariants that could materially change during runtime.
    status.append(
        "PASS: live network stack absent"
        if not Path("/proc/net").exists()
        else "FAIL: live /proc/net exists"
    )
    try:
        swaps = Path("/proc/swaps").read_text(encoding="utf-8").strip().splitlines()
        status.append("PASS: live swap remains disabled" if len(swaps) <= 1 else "FAIL: active swap detected")
    except OSError:
        status.append("FAIL: unable to inspect live swap state")
    return status


def _security_locked(status: list[str]) -> bool:
    return LOCKDOWN.exists() or any(item.startswith("FAIL:") for item in status)


def mount_transfer() -> bool:
    TRANSFER.mkdir(parents=True, exist_ok=True)
    if _mounted(TRANSFER):
        return True
    result = subprocess.run(
        ["mount", "-t", "vfat", "-o", SAFE_MOUNT_OPTIONS, "-L", "TX_TRANSFER", str(TRANSFER)],
        check=False,
    )
    return result.returncode == 0 and _mounted(TRANSFER)


def unmount_transfer() -> None:
    if _mounted(TRANSFER):
        subprocess.run(["umount", str(TRANSFER)], check=False)


def _run_cli(arguments: list[str]) -> None:
    subprocess.run(
        [sys.executable, "-m", "usb_cold_wallet.cli", "--vault", str(VAULT), *arguments],
        check=False,
    )


def _select_file(suffix: str) -> Path | None:
    if not mount_transfer():
        print("TX_TRANSFER USB not found. Format a separate FAT USB with label TX_TRANSFER.")
        return None
    files = sorted(p for p in TRANSFER.iterdir() if p.is_file() and p.name.lower().endswith(suffix))
    if not files:
        print(f"No *{suffix} file found on TX_TRANSFER.")
        return None
    for index, path in enumerate(files, start=1):
        print(f"  {index}. {path.name}")
    try:
        selected = int(input("Select file number: "))
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
    _run_cli(["sign-evm", "--tx", str(source), "--to", recipient, "--wei", wei, "--out", str(output)])


def _sign_btc() -> None:
    source = _select_file(".psbt")
    if source is None:
        return
    recipient = input("Independently verified Bitcoin TESTNET recipient (tb1...): ").strip()
    sats = input("Independently verified value in satoshis: ").strip()
    max_fee = input("Maximum acceptable fee in satoshis: ").strip()
    change = input("Expected BIP84 change index (blank if no change): ").strip()
    output = TRANSFER / (source.stem + ".signed.json")
    args = [
        "sign-btc", "--psbt", str(source), "--to", recipient, "--sats", sats,
        "--max-fee-sats", max_fee, "--out", str(output),
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
            print("TX_TRANSFER mounted." if mount_transfer() else "TX_TRANSFER not found.")
        elif choice == "6":
            unmount_transfer()
            subprocess.run(["poweroff"], check=False)
            return 0
        else:
            print("Unknown option.")


if __name__ == "__main__":
    raise SystemExit(main())
