"""Single-purpose text console for the bootable air-gapped appliance."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import time

VAULT = Path("/mnt/cold-vault/wallet.vault")
TRANSFER = Path("/mnt/transfer")
BOOT_CHECKS = Path("/run/usb-wallet/boot-checks.txt")
LOCKDOWN = Path("/run/usb-wallet/lockdown")
BOOT_PARENT_FILE = Path("/run/usb-wallet/boot-parent")
VAULT_DEVICE_FILE = Path("/run/usb-wallet/vault-device")
TRANSFER_DEVICE_FILE = Path("/run/usb-wallet/transfer-device")
SAFE_MOUNT_OPTIONS = "rw,noexec,nodev,nosuid,sync,fmask=0177,dmask=0077"
SYS_BLOCK = Path("/sys/class/block")
DEV_ROOT = Path("/dev")
DIAGNOSTIC_HELPER = Path("/usr/libexec/usb-wallet-identify-media")


def _signal_console_ready(*, locked: bool = False) -> None:
    """Use the same bounded, best-effort serial diagnostic as startup."""
    try:
        subprocess.run(
            [sys.executable, str(DIAGNOSTIC_HELPER), "--serial",
             "lockdown-ready" if locked else "console-ready"],
            check=False, timeout=4, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


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


def _usb_mass_storage(entry: Path) -> bool:
    """Require kernel sysfs USB ancestry, not merely a spoofable FAT label."""
    try:
        resolved = entry.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    parts = resolved.parts
    return any(
        re.fullmatch(r"usb[0-9]+", parts[i])
        and re.fullmatch(r"[0-9]+-[0-9]+(?:\.[0-9]+)*", parts[i + 1])
        for i in range(len(parts) - 1)
    )


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
        if device.is_symlink():
            continue
        if not _usb_mass_storage(entry):
            continue
        if _fat_label(device) == "TX_TRANSFER":
            matches.append(str(device))
    return matches


def _unique_transfer_device() -> str | None:
    """Allow legacy separate USB, or the exact boot-verified single-USB partition."""
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
    if not parent or device == vault_device:
        return None

    if parent != boot_parent:
        # Preserve the original two-USB policy for legacy images.
        return device

    # Same-parent media is allowed only when S01airgap verified the complete
    # three-partition GPT layout and persisted the exact transfer device path.
    try:
        expected = TRANSFER_DEVICE_FILE.read_text(encoding="ascii").strip()
    except OSError:
        return None
    if expected != device or not re.fullmatch(r"/dev/sd[a-z]+[1-9][0-9]*", expected):
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
        and {"rw", "noexec", "nodev", "nosuid", "sync", "fmask=0177", "dmask=0077"} <= options
    )


def security_status() -> list[str]:
    try:
        boot_lines = BOOT_CHECKS.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ["FAIL: boot security audit missing"]

    status = [line for line in boot_lines if line.startswith(("PASS:", "FAIL:"))]
    stages = [line for line in boot_lines if line.startswith("INFO:")]
    if not status:
        return stages + ["FAIL: boot security audit contained no checks"]
    status = [line for line in boot_lines if line.startswith(("INFO:", "PASS:", "FAIL:"))]

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

    # A successful boot audit is historical evidence only. A user may insert,
    # remove or remount USB media after S01airgap has finished; the console must
    # re-check the same live mount and block-device boundaries as the Tk signer.
    try:
        from .gui import runtime_audit
        safe, findings = runtime_audit()
        if safe:
            status.append("PASS: current RAM root, vault and transfer mounts audited")
        else:
            status.extend(line for line in findings if line.startswith("FAIL:"))
            status.append("FAIL: live appliance runtime audit rejected signing")
    except Exception:
        status.append("FAIL: unable to complete live appliance runtime audit")
    return status


def _security_locked(status: list[str]) -> bool:
    return LOCKDOWN.exists() or any(item.startswith("FAIL:") for item in status)


def mount_transfer() -> bool:
    # Public integration callers may invoke this without the console menu.
    # Never mount removable exchange media after a failed boot audit.
    if LOCKDOWN.exists():
        return False
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
    if result.returncode == 0 and _safe_transfer_mount(device):
        return True
    # A failed or unexpected new mount must not remain usable.
    unmount_transfer()
    return False


def _unmount_path(path: Path) -> bool:
    if not _mounted(path):
        return True
    try:
        result = subprocess.run(["umount", str(path)], check=False)
        return result.returncode == 0 and not _mounted(path)
    except OSError:
        return False


def unmount_transfer() -> bool:
    return _unmount_path(TRANSFER)


def _poweroff() -> bool:
    """Normal shutdown only; no forced halt and no silent error."""
    print("Power off requested; closing removable filesystems.", flush=True)
    try:
        LOCKDOWN.touch()
        # An unavailable mount table is not evidence that media is unmounted.
        Path("/proc/mounts").read_text(encoding="utf-8")
        if not unmount_transfer() or not _unmount_path(VAULT.parent):
            print("FAIL: removable filesystem unmount failed; power off cancelled.", flush=True)
            return False
        if subprocess.run(["sync"], check=False).returncode != 0:
            print("FAIL: filesystem sync failed; power off cancelled.", flush=True)
            return False
        if subprocess.run(["poweroff"], check=False).returncode != 0:
            print("FAIL: poweroff command failed; system remains locked.", flush=True)
            return False
    except (OSError, UnicodeError):
        print("FAIL: shutdown operation unavailable; system remains locked.", flush=True)
        return False
    print("Poweroff accepted by OS; waiting for hardware shutdown.", flush=True)
    return True


def _attended_poweroff() -> None:
    if _poweroff():
        # BusyBox poweroff requests shutdown from PID 1. Do not exit into its
        # tty1 respawn loop while shutdown is in progress.
        time.sleep(10)
        print("Poweroff requested but system is still running; retry option 6.", flush=True)


def _run_cli(arguments: list[str]) -> None:
    # Revalidate after user prompts/media selection, not only when the menu
    # was drawn. The child also rechecks while handling sensitive operations.
    if _security_locked(security_status()):
        print("LOCKDOWN: live USB safety audit failed; operation cancelled.")
        return
    subprocess.run(
        [sys.executable, "-m", "usb_cold_wallet.cli", "--vault", str(VAULT), *arguments],
        check=False,
        env={**os.environ, "USB_WALLET_APPLIANCE": "1"},
    )


def _select_file(suffix: str | tuple[str, ...]) -> Path | None:
    if not mount_transfer():
        print(
            "TX_TRANSFER unavailable or ambiguous. "
            "Use the verified single-USB transfer partition or one separate legacy VFAT USB."
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
    shutdown_requested = False
    normal_ready = False
    locked_ready = False
    while True:
        print("\n=== USB BTC + EVM COLD WALLET ===")
        print("TESTNET DEVELOPMENT BUILD — NOT APPROVED FOR MAINNET ASSETS")
        status = security_status()
        for item in status:
            print(item)
        if shutdown_requested or _security_locked(status):
            print("\nLOCKDOWN: wallet creation/signing is disabled because a boot security check failed or shutdown was requested.")
            print("6) Power off")
            if not locked_ready:
                _signal_console_ready(locked=True)
                locked_ready = True
            if input("> ").strip() == "6":
                shutdown_requested = True
                _attended_poweroff()
            continue
        # This is emitted only after the live runtime audit passed and the
        # single-purpose console reached its attended menu.
        if not normal_ready:
            _signal_console_ready()
            normal_ready = True
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
            if not unmount_transfer():
                print("FAIL: TX_TRANSFER unmount failed; re-scan cancelled.")
            else:
                print("TX_TRANSFER mounted." if mount_transfer() else "TX_TRANSFER not found or unsafe.")
        elif choice == "7":
            _initialize_policy()
        elif choice == "6":
            shutdown_requested = True
            _attended_poweroff()
        else:
            print("Unknown option.")


if __name__ == "__main__":
    raise SystemExit(main())
