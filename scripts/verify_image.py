#!/usr/bin/env python3
"""Structural verification of the generated GPT single-USB image."""
from __future__ import annotations

import argparse
from pathlib import Path
import struct
import uuid
import zlib


EXPECTED_DISK_UUID = uuid.UUID("f1448aa1-28cc-54bf-8fdd-3008514c0ab5")
EXPECTED_BOOT_UUID = uuid.UUID("e2bd6d1b-8de5-502d-a897-c53a8e60f46b")
EXPECTED_VAULT_UUID = uuid.UUID("18f1c36f-d5c0-5052-9cd2-03e9c2a48f00")
EXPECTED_TRANSFER_UUID = uuid.UUID("42f6f5d4-9310-5ac3-b5d4-1540cbe7d6b4")
EFI_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
LINUX_FS_TYPE = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
BASIC_DATA_TYPE = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")
GPT_READ_ONLY = 1 << 60
SECTOR = 512
BOOT_SECTORS = 64 * 1024 * 1024 // SECTOR
VAULT_SECTORS = 64 * 1024 * 1024 // SECTOR
TRANSFER_SECTORS = 512 * 1024 * 1024 // SECTOR


def _fat_label(data: bytes, first_lba: int, *, require_fat32: bool = False) -> str:
    sector = data[first_lba * SECTOR:(first_lba + 1) * SECTOR]
    if len(sector) != SECTOR or sector[510:512] != b"\x55\xaa":
        raise SystemExit("FAT boot sector missing")
    if struct.unpack_from("<H", sector, 11)[0] != SECTOR:
        raise SystemExit("FAT logical sector size is not 512 bytes")
    fat_type = sector[82:90] if sector[82:90] == b"FAT32   " else sector[54:62]
    if fat_type not in (b"FAT12   ", b"FAT16   ", b"FAT32   "):
        raise SystemExit("unsupported FAT filesystem")
    if require_fat32 and fat_type != b"FAT32   ":
        raise SystemExit("TX_TRANSFER must be FAT32")
    raw = sector[71:82] if fat_type == b"FAT32   " else sector[43:54]
    return raw.decode("ascii").rstrip(" ")


def _sectors(part) -> int:
    return part[3] - part[2] + 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    data = args.image.read_bytes()
    if len(data) < 640 * 1024 * 1024:
        raise SystemExit("single-USB image is unexpectedly small")
    if data[510:512] != b"\x55\xaa":
        raise SystemExit("protective MBR signature missing")
    if data[450] != 0xEE or any(data[462:510]):
        raise SystemExit("protective MBR is missing or contains hybrid partitions")

    header = data[SECTOR:SECTOR * 2]
    if header[:8] != b"EFI PART":
        raise SystemExit("GPT header missing")
    size, checksum = struct.unpack_from("<II", header, 12)
    if not 92 <= size <= SECTOR:
        raise SystemExit("invalid GPT header size")
    canonical = bytearray(header[:size])
    canonical[16:20] = bytes(4)
    if zlib.crc32(canonical) != checksum:
        raise SystemExit("invalid GPT header CRC")

    disk_uuid = uuid.UUID(bytes_le=header[56:72])
    if disk_uuid != EXPECTED_DISK_UUID:
        raise SystemExit(f"unexpected GPT disk UUID: {disk_uuid}")

    entries_lba = struct.unpack_from("<Q", header, 72)[0]
    count = struct.unpack_from("<I", header, 80)[0]
    entry_size = struct.unpack_from("<I", header, 84)[0]
    if not (2 <= entries_lba and 3 <= count <= 128 and
            128 <= entry_size <= SECTOR and entry_size % 8 == 0):
        raise SystemExit("invalid GPT entry geometry")
    entries_start = entries_lba * SECTOR
    entries = data[entries_start:entries_start + count * entry_size]
    if len(entries) != count * entry_size:
        raise SystemExit("GPT entry table truncated")
    if zlib.crc32(entries) != struct.unpack_from("<I", header, 88)[0]:
        raise SystemExit("invalid GPT entries CRC")
    partitions = []
    seen_empty = False
    for index in range(count):
        entry = entries[index * entry_size:(index + 1) * entry_size]
        if entry[:16] == bytes(16):
            seen_empty = True
            continue
        if seen_empty:
            raise SystemExit("non-contiguous GPT partition entries")
        part_type = uuid.UUID(bytes_le=entry[:16])
        part_uuid = uuid.UUID(bytes_le=entry[16:32])
        first_lba, last_lba, attrs = struct.unpack_from("<QQQ", entry, 32)
        name = entry[56:128].decode("utf-16le", errors="ignore").rstrip("\x00")
        partitions.append((part_type, part_uuid, first_lba, last_lba, attrs, name))

    if len(partitions) != 3:
        raise SystemExit(f"expected exactly three GPT partitions, got {len(partitions)}")

    boot, vault, transfer = partitions
    expected = (
        (boot, EFI_TYPE, EXPECTED_BOOT_UUID, BOOT_SECTORS, "USBCOLD_EFI"),
        (vault, LINUX_FS_TYPE, EXPECTED_VAULT_UUID, VAULT_SECTORS, "COLD_VAULT"),
        (transfer, BASIC_DATA_TYPE, EXPECTED_TRANSFER_UUID, TRANSFER_SECTORS, "TX_TRANSFER"),
    )
    for part, part_type, part_uuid, sectors, label in expected:
        if part[0] != part_type:
            raise SystemExit(f"{label} has unexpected GPT type: {part[0]}")
        if part[1] != part_uuid:
            raise SystemExit(f"{label} has unexpected partition UUID: {part[1]}")
        if _sectors(part) != sectors:
            raise SystemExit(f"{label} has unexpected fixed size")
        if not (1 < part[2] <= part[3] < len(data) // SECTOR - 1):
            raise SystemExit(f"{label} extends beyond the image/GPT usable area")
        if _fat_label(data, part[2], require_fat32=label == "TX_TRANSFER") != label:
            raise SystemExit(f"{label} FAT volume label mismatch")

    if not (boot[4] & GPT_READ_ONLY):
        raise SystemExit("boot partition is not marked GPT read-only")
    if vault[4] != 0 or transfer[4] != 0:
        raise SystemExit("vault/transfer partition has unexpected GPT attributes (hidden/no-drive-letter/read-only)")
    if boot[3] >= vault[2] or vault[3] >= transfer[2]:
        raise SystemExit("GPT partitions overlap or are out of order")

    # Windows compatibility boundary: only TX_TRANSFER is Microsoft Basic Data.
    # COLD_VAULT intentionally uses Linux filesystem type to avoid ordinary
    # Explorer drive-letter assignment; an admin/hostile Windows can still
    # raw-write the USB and is outside this testnet boot-integrity guarantee.
    if sum(1 for part in partitions if part[0] == BASIC_DATA_TYPE) != 1:
        raise SystemExit("Windows-visible Basic Data partition set is ambiguous")

    print(f"GPT single-USB structure OK; disk UUID={disk_uuid}")
    for part in partitions:
        print(
            f"  {part[5] or '<unnamed>'}: UUID={part[1]} "
            f"LBA {part[2]}..{part[3]} type={part[0]} attrs=0x{part[4]:x}"
        )
    print("  Windows-visible data partition: TX_TRANSFER only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
