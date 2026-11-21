"""Single-purpose text console for the bootable air-gapped appliance."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

VAULT = Path("/mnt/cold-vault/wallet.vault")
TRANSFER = Path("/mnt/transfer")
BOOT_CHECKS = Path("/run/usb-wallet/boot-checks.txt")
LOCKDOWN = Path("/run/usb-wallet/lockdown")
BOOT_PARENT_FILE = Path("/run/usb-wallet/boot-parent")
VAULT_DEVICE_FILE = Path("/run/usb-wallet/vault-device")
SAFE_MOUNT_OPTIONS = "rw,noexec,nodev,nosuid,sync,fmask=0177,dmask=0077"
SYS_BLOCK = Path("/sys/class/block")
DEV_ROOT = Path("/dev")


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


def _fat_label(partition: Path) -> str | None:
    """Recognize FAT12/16/32 with 512-byte sectors without util-linux.

    BusyBox blkid in the embedded image lacks the query flags used by the
    original console. Reject ambiguous or malformed transfer devices.
    """
    try:
        with partition.open("rb") as handle:
            sector = handle.read(512)
        if (len(sector) != 512 or sector[510:512] != b"\x55\xaa" or
                sector[11:13] != b"\x00\x02"):
            return None
        fat_type = b"FAT32   " if sector[82:90] == b"FAT32   " else sector[54:62]
        if fat_type not in (b"FAT12   ", b"FAT16   ", b"FAT32   "):
            return None
        label = sector[71:82] if fat_type == b"FAT32   " else sector[43:54]
        return label.decode("ascii").rstrip(" ")
    except (OSError, ValueError, UnicodeError):
        return None


def _transfer_candidates() -> list[str]:
    """Identify exact FAT-labelled SCSI/USB partitions using sysfs."""
    matches: list[str] = []
    try:
        entries = list(SYS_BLOCK.iterdir())
    except OSError:
        return matches
    for entry in entries:
        if (not re.fullmatch(r"sd[a-z]+[1-9][0-9]*", entry.name) or
                not (entry / "partition").is_file()):
            continue
        device = DEV_ROOT / entry.name
        if _fat_label(device) == "TX_TRANSFER":
            matches.append(str(device))
    return matches


def _unique_transfer_device() -> str | None:
    devices = _transfer_candidates()
    if len(devices) != 1:
        return None
    device = devices[0]

    try:
        boot_parent = BOOT_PARENT_FILE.read_text(encoding="utf-8").strip()
        vault_device = VAULT_DEVICE_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None

    if not re.fullmatch(r"sd[a-z]+", boot_parent):
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


def _initialize_policy() -> None:
    """Explicitly create the encrypted policy; the hash must be kept separately."""
    if not VAULT.is_file():
        print("Create or recover the encrypted wallet before initializing its policy.")
        return
    policy_path = VAULT.with_name(VAULT.name + ".policy")
    if policy_path.exists() or policy_path.is_symlink():
        print("Policy exists; refusing overwrite. Use offline policy maintenance separately.")
        return
    _run_cli(["policy", "--file", str(policy_path), "--action", "init"])
    print("After successful initialization, record the printed POLICY SHA256")
    print("independently on paper. Signing never reads that anchor from the USB.")


def _paper_policy_anchor() -> str | None:
    """Do not derive a trusted policy anchor from the same mutable USB."""
    digest = input("Current policy SHA256 copied from independent PAPER (64 lowercase hex): ").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        print("Missing or invalid independent policy anchor; signing cancelled.")
        return None
    return digest


def _sign_evm() -> None:
    source = _select_file(".json")
    if source is None:
        return
    recipient = input("Independently verified Sepolia recipient (0x...): ").strip()
    wei = input("Independently verified value in wei: ").strip()
    anchor = _paper_policy_anchor()
    if anchor is None:
        return
    output = TRANSFER / (source.stem + ".signed.json")
    # Appliance JSON transport is always the bounded #5/#11 request envelope.
    # Do not pre-read untrusted USB content here and then read it again in the
    # CLI: a malicious device could present different bytes between reads.
    _run_cli([
        "sign-evm", "--request", str(source), "--to", recipient,
        "--wei", wei, "--out", str(output),
        "--expected-policy-sha256", anchor,
    ])


def _sign_btc() -> None:
    source = _select_file((".psbt", ".json"))
    if source is None:
        return
    recipient = input("Independently verified Bitcoin TESTNET recipient (tb1...): ").strip()
    sats = input("Independently verified value in satoshis: ").strip()
    max_fee = input("Maximum acceptable fee in satoshis: ").strip()
    change = input("Expected BIP84 change index (blank if no change): ").strip()
    anchor = _paper_policy_anchor()
    if anchor is None:
        return
    output = TRANSFER / (source.stem + ".signed.json")
    # The suffix decides only the transport parser. JSON is always a strict
    # btc-request envelope; content is read exactly once by the CLI parser.
    source_flag = "--request" if source.suffix.lower() == ".json" else "--psbt"
    args = [
        "sign-btc", source_flag, str(source), "--to", recipient,
        "--sats", sats, "--max-fee-sats", max_fee, "--out", str(output),
        "--expected-policy-sha256", anchor,
    ]
    if change:
        args.extend(["--change-index", change])
    _run_cli(args)


def main() -> int:
    os.environ["HISTFILE"] = "/dev/null"
    while True:
        print("\n=== USB BTC + EVM COLD WALLET ===")
        print("TESTNET DEVELOPMENT BUILD — NOT APPROVED FOR MAINNET ASSETS")
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
        print("7) Initialize encrypted offline signing policy (record SHA256 on paper)")
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
        elif choice == "7":
            _initialize_policy()
        elif choice == "6":
            unmount_transfer()
            subprocess.run(["poweroff"], check=False)
            return 0
        else:
            print("Unknown option.")


if __name__ == "__main__":
    raise SystemExit(main())
