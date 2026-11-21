#!/usr/bin/env python3
"""Identify the unique trusted USB GPT and FAT partitions without udev/blkid.

BusyBox blkid does not implement util-linux's -t/-o/-s options. This helper
uses only the Python standard library and Linux devtmpfs/sysfs at boot.
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
EFI_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
DATA_TYPE = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")
READ_ONLY = 1 << 60


def read_gpt(disk: Path) -> tuple[uuid.UUID, list[tuple[uuid.UUID, uuid.UUID, int]]]:
    """Read/CRC-check the primary GPT, rejecting malformed or ambiguous entries."""
    with disk.open("rb") as source:
        if source.read(512)[510:512] != b"\x55\xaa":
            raise ValueError("missing protective MBR")
        header = source.read(512)
        if len(header) != 512 or header[:8] != b"EFI PART":
            raise ValueError("missing GPT")
        size, checksum = struct.unpack_from("<II", header, 12)
        if not 92 <= size <= 512:
            raise ValueError("invalid GPT header size")
        copy = bytearray(header[:size])
        copy[16:20] = b"\x00" * 4
        if zlib.crc32(copy) != checksum:
            raise ValueError("invalid GPT header CRC")
        disk_id = uuid.UUID(bytes_le=header[56:72])
        lba, count, width, entries_crc = struct.unpack_from("<QIII", header, 72)
        if not 2 <= count <= 128 or not 128 <= width <= 512 or width % 8 or lba < 2:
            raise ValueError("invalid GPT partition table")
        source.seek(lba * 512)
        entries = source.read(count * width)
        if len(entries) != count * width or zlib.crc32(entries) != entries_crc:
            raise ValueError("invalid GPT entries CRC")
    partitions = []
    for index in range(count):
        entry = entries[index * width:(index + 1) * width]
        if entry[:16] == bytes(16):
            continue
        kind = uuid.UUID(bytes_le=entry[:16])
        part_id = uuid.UUID(bytes_le=entry[16:32])
        first_lba, last_lba, attrs = struct.unpack_from("<QQQ", entry, 32)
        if not first_lba or last_lba < first_lba:
            raise ValueError("invalid GPT partition range")
        partitions.append((kind, part_id, attrs))
    return disk_id, partitions


def fat_label(partition: Path) -> str:
    """Read the fixed FAT12/16/FAT32 volume label directly from its boot sector."""
    with partition.open("rb") as source:
        sector = source.read(512)
    if len(sector) != 512 or sector[510:512] != b"\x55\xaa":
        raise ValueError("missing FAT boot sector")
    if struct.unpack_from("<H", sector, 11)[0] != 512:
        raise ValueError("unexpected FAT sector size")
    fat_type = sector[82:90] if sector[82:90] == b"FAT32   " else sector[54:62]
    if fat_type not in (b"FAT12   ", b"FAT16   ", b"FAT32   "):
        raise ValueError("unsupported FAT filesystem")
    raw = sector[71:82] if fat_type == b"FAT32   " else sector[43:54]
    return raw.decode("ascii").rstrip(" ")


def _usb_mass_storage(entry: Path) -> bool:
    """Require a USB sysfs transport ancestry for an sdX block device.

    A SATA/SCSI/virtio-backed sdX can copy all public GPT and FAT identifiers.
    USB transport is necessary but does not authenticate firmware or contents.
    """
    try:
        resolved = entry.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    parts = resolved.parts
    # Genuine Linux sysfs USB topology includes usbN/<port id>, e.g.
    # .../usb1/1-2/1-2:1.0/host0/.../block/sda. An sdX name alone proves
    # only the SCSI block driver, not USB ancestry.
    for i in range(len(parts) - 1):
        if (re.fullmatch(r"usb[0-9]+", parts[i]) and
                re.fullmatch(r"[0-9]+-[0-9]+(?:\.[0-9]+)*", parts[i + 1])):
            return True
    return False


def identify(sys_block: Path = Path("/sys/class/block"),
             dev_root: Path = Path("/dev")) -> tuple[str, str, str]:
    matches = []
    unsafe_duplicate = False
    for entry in sorted(sys_block.iterdir()):
        name = entry.name
        # USB mass-storage (including UAS) uses sdX; other block drivers are
        # intentionally unavailable in the verified offline kernel.
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
        if disk_id != DISK_UUID and not (part_ids & {BOOT_UUID, VAULT_UUID}):
            continue
        # A forged copy on a non-USB SCSI/SATA bus is an ambiguous trusted
        # identifier: lock down, even if another genuine USB is also present.
        if not _usb_mass_storage(entry):
            unsafe_duplicate = True
            continue
        boot, vault = dev_root / (name + "1"), dev_root / (name + "2")
        if (disk_id != DISK_UUID or len(parts) != 2 or
                parts[0][:2] != (EFI_TYPE, BOOT_UUID) or
                not (parts[0][2] & READ_ONLY) or
                parts[1][:2] != (DATA_TYPE, VAULT_UUID) or
                (parts[1][2] & READ_ONLY) or
                not (sys_block / (name + "1") / "partition").is_file() or
                not (sys_block / (name + "2") / "partition").is_file()):
            unsafe_duplicate = True
            continue
        try:
            if fat_label(boot) != "USBCOLD_EFI" or fat_label(vault) != "COLD_VAULT":
                unsafe_duplicate = True
                continue
        except (OSError, ValueError, UnicodeDecodeError):
            unsafe_duplicate = True
            continue
        matches.append((str(boot), str(vault), name))
    if unsafe_duplicate or len(matches) != 1:
        raise ValueError("missing, duplicated, or inconsistent trusted USB partitions")
    return matches[0]


def main() -> int:
    try:
        boot, vault, parent = identify()
    except (OSError, ValueError) as exc:
        print(f"usb media identification failed: {exc}", file=sys.stderr)
        return 1
    print(boot, vault, parent, sep="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
