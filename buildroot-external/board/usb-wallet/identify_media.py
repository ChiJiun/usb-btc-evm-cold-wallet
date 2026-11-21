#!/usr/bin/env python3
"""Identify the unique expected cold-wallet USB GPT layout without udev/blkid.

This validates public partition metadata and Linux USB ancestry. It does not
authenticate the USB contents or provide a trusted boot root.
"""
from __future__ import annotations

from pathlib import Path
import re
import struct
import sys
import uuid
import zlib

DISK_UUID = uuid.UUID("f1448aa1-28cc-54bf-8fdd-3008514c0ab5")
BOOT_UUID = uuid.UUID("e2bd6d1b-8de5-502d-a897-c53a8e60f46b")
VAULT_UUID = uuid.UUID("18f1c36f-d5c0-5052-9cd2-03e9c2a48f00")
TRANSFER_UUID = uuid.UUID("42f6f5d4-9310-5ac3-b5d4-1540cbe7d6b4")
EFI_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
LINUX_FS_TYPE = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
DATA_TYPE = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")
READ_ONLY = 1 << 60
SECTOR_SIZE = 512
BOOT_SECTORS = 64 * 1024 * 1024 // SECTOR_SIZE
VAULT_SECTORS = 64 * 1024 * 1024 // SECTOR_SIZE
TRANSFER_SECTORS = 512 * 1024 * 1024 // SECTOR_SIZE


def read_gpt(
    disk: Path,
) -> tuple[uuid.UUID, list[tuple[uuid.UUID, uuid.UUID, int, int, int]]]:
    """Read/CRC-check the primary GPT, rejecting malformed entries."""
    if disk.is_symlink():
        raise ValueError("block device path must not be a symlink")
    with disk.open("rb") as source:
        mbr = source.read(SECTOR_SIZE)
        if (len(mbr) != SECTOR_SIZE or mbr[510:512] != b"\x55\xaa"
                or mbr[450] != 0xEE or any(mbr[462:510])):
            raise ValueError("missing or hybrid protective MBR")
        header = source.read(SECTOR_SIZE)
        if len(header) != SECTOR_SIZE or header[:8] != b"EFI PART":
            raise ValueError("missing GPT")
        size, checksum = struct.unpack_from("<II", header, 12)
        if not 92 <= size <= SECTOR_SIZE:
            raise ValueError("invalid GPT header size")
        copy = bytearray(header[:size])
        copy[16:20] = b"\x00" * 4
        if zlib.crc32(copy) != checksum:
            raise ValueError("invalid GPT header CRC")
        disk_id = uuid.UUID(bytes_le=header[56:72])
        lba, count, width, entries_crc = struct.unpack_from("<QIII", header, 72)
        if not 2 <= count <= 128 or not 128 <= width <= 512 or width % 8 or lba < 2:
            raise ValueError("invalid GPT partition table")
        source.seek(lba * SECTOR_SIZE)
        entries = source.read(count * width)
        if len(entries) != count * width or zlib.crc32(entries) != entries_crc:
            raise ValueError("invalid GPT entries CRC")
    partitions = []
    seen_empty = False
    for index in range(count):
        entry = entries[index * width:(index + 1) * width]
        if entry[:16] == bytes(16):
            seen_empty = True
            continue
        # Linux names GPT entry N as sdXN; gaps can bind an unexpected
        # partition to an expected device path even with valid GPT CRCs.
        if seen_empty:
            raise ValueError("non-contiguous GPT partition entries")
        kind = uuid.UUID(bytes_le=entry[:16])
        part_id = uuid.UUID(bytes_le=entry[16:32])
        first_lba, last_lba, attrs = struct.unpack_from("<QQQ", entry, 32)
        if not first_lba or last_lba < first_lba:
            raise ValueError("invalid GPT partition range")
        partitions.append((kind, part_id, attrs, first_lba, last_lba))
    return disk_id, partitions


def fat_label(partition: Path) -> str:
    """Read the fixed FAT12/16/FAT32 volume label directly from its boot sector."""
    if partition.is_symlink():
        raise ValueError("partition device path must not be a symlink")
    with partition.open("rb") as source:
        sector = source.read(SECTOR_SIZE)
    if len(sector) != SECTOR_SIZE or sector[510:512] != b"\x55\xaa":
        raise ValueError("missing FAT boot sector")
    if struct.unpack_from("<H", sector, 11)[0] != SECTOR_SIZE:
        raise ValueError("unexpected FAT sector size")
    fat_type = sector[82:90] if sector[82:90] == b"FAT32   " else sector[54:62]
    if fat_type not in (b"FAT12   ", b"FAT16   ", b"FAT32   "):
        raise ValueError("unsupported FAT filesystem")
    raw = sector[71:82] if fat_type == b"FAT32   " else sector[43:54]
    return raw.decode("ascii").rstrip(" ")


def _usb_mass_storage(entry: Path) -> bool:
    """Require a USB sysfs transport ancestry for an sdX block device."""
    try:
        resolved = entry.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    parts = resolved.parts
    for i in range(len(parts) - 1):
        if (
            re.fullmatch(r"usb[0-9]+", parts[i])
            and re.fullmatch(r"[0-9]+-[0-9]+(?:\.[0-9]+)*", parts[i + 1])
        ):
            return True
    return False


def _partition_matches_kernel(
    sys_block: Path,
    disk_entry: Path,
    name: str,
    number: int,
    part: tuple[uuid.UUID, uuid.UUID, int, int, int],
) -> bool:
    """Require the kernel's actual device mapping to match the CRC-checked GPT."""
    try:
        node = (sys_block / name).resolve(strict=True)
        disk = disk_entry.resolve(strict=True)
        return (
            node.parent == disk
            and (node / "partition").read_text().strip() == str(number)
            and int((node / "start").read_text().strip()) == part[3]
            and int((node / "size").read_text().strip()) == _size(part)
        )
    except (OSError, ValueError, RuntimeError):
        return False


def _size(part: tuple[uuid.UUID, uuid.UUID, int, int, int]) -> int:
    return part[4] - part[3] + 1


def _layout_valid(
    parts: list[tuple[uuid.UUID, uuid.UUID, int, int, int]],
) -> bool:
    if len(parts) not in (2, 3):
        return False
    boot, vault = parts[0], parts[1]
    if (
        boot[:2] != (EFI_TYPE, BOOT_UUID)
        or not (boot[2] & READ_ONLY)
        or _size(boot) != BOOT_SECTORS
        or vault[:2] != (
            LINUX_FS_TYPE if len(parts) == 3 else DATA_TYPE, VAULT_UUID
        )
        or (vault[2] & READ_ONLY)
        or _size(vault) != VAULT_SECTORS
        or boot[4] >= vault[3]
    ):
        return False
    if len(parts) == 3:
        transfer = parts[2]
        if (
            transfer[:2] != (DATA_TYPE, TRANSFER_UUID)
            or (transfer[2] & READ_ONLY)
            or _size(transfer) != TRANSFER_SECTORS
            or vault[4] >= transfer[3]
        ):
            return False
    return True


def identify(
    sys_block: Path = Path("/sys/class/block"),
    dev_root: Path = Path("/dev"),
) -> tuple[str, str, str | None, str]:
    """Return boot, vault, optional same-device transfer, and parent block name."""
    matches = []
    unsafe_duplicate = False
    for entry in sorted(sys_block.iterdir()):
        name = entry.name
        if not re.fullmatch(r"sd[a-z]+", name) or not entry.is_dir():
            continue
        if (entry / "partition").exists():
            continue
        try:
            if (entry / "queue/logical_block_size").read_text().strip() != "512":
                continue
            disk_id, parts = read_gpt(dev_root / name)
        except (OSError, ValueError):
            continue
        part_ids = {part[1] for part in parts}
        if disk_id != DISK_UUID and not (
            part_ids & {BOOT_UUID, VAULT_UUID, TRANSFER_UUID}
        ):
            continue
        if not _usb_mass_storage(entry):
            unsafe_duplicate = True
            continue
        if disk_id != DISK_UUID or not _layout_valid(parts):
            unsafe_duplicate = True
            continue

        boot = dev_root / f"{name}1"
        vault = dev_root / f"{name}2"
        transfer = dev_root / f"{name}3" if len(parts) == 3 else None
        names = [f"{name}1", f"{name}2"] + ([f"{name}3"] if transfer else [])
        if not all(
            _partition_matches_kernel(sys_block, entry, part_name, index, parts[index - 1])
            for index, part_name in enumerate(names, 1)
        ):
            unsafe_duplicate = True
            continue
        try:
            if fat_label(boot) != "USBCOLD_EFI" or fat_label(vault) != "COLD_VAULT":
                unsafe_duplicate = True
                continue
            if transfer is not None and fat_label(transfer) != "TX_TRANSFER":
                unsafe_duplicate = True
                continue
        except (OSError, ValueError, UnicodeDecodeError):
            unsafe_duplicate = True
            continue
        matches.append(
            (
                str(boot),
                str(vault),
                str(transfer) if transfer is not None else None,
                name,
            )
        )
    if unsafe_duplicate or len(matches) != 1:
        raise ValueError("missing, duplicated, or inconsistent trusted USB partitions")
    return matches[0]


def main() -> int:
    try:
        boot, vault, transfer, parent = identify()
    except (OSError, ValueError) as exc:
        print(f"usb media identification failed: {exc}", file=sys.stderr)
        return 1
    print(boot, vault, transfer or "-", parent, sep="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
