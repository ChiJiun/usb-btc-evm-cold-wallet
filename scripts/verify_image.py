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
GPT_ENTRY_COUNT = 128
GPT_ENTRY_SIZE = 128
GPT_TABLE_SECTORS = GPT_ENTRY_COUNT * GPT_ENTRY_SIZE // SECTOR
BOOT_SECTORS = 64 * 1024 * 1024 // SECTOR
VAULT_SECTORS = 64 * 1024 * 1024 // SECTOR
TRANSFER_SECTORS = 512 * 1024 * 1024 // SECTOR
BOOT_START_LBA = 2048
VAULT_START_LBA = BOOT_START_LBA + BOOT_SECTORS
TRANSFER_START_LBA = VAULT_START_LBA + VAULT_SECTORS


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


def _parse_header(data: bytes, lba: int) -> dict[str, int | uuid.UUID]:
    header = data[lba * SECTOR:(lba + 1) * SECTOR]
    if len(header) != SECTOR or header[:8] != b"EFI PART":
        raise SystemExit("GPT header missing")
    revision, size, checksum = struct.unpack_from("<III", header, 8)
    if revision != 0x00010000 or size != 92 or header[20:24] != bytes(4):
        raise SystemExit("invalid GPT header geometry")
    canonical = bytearray(header[:size])
    canonical[16:20] = bytes(4)
    if zlib.crc32(canonical) != checksum:
        raise SystemExit("invalid GPT header CRC")
    current_lba, backup_lba, first_usable, last_usable = struct.unpack_from("<QQQQ", header, 24)
    disk_uuid = uuid.UUID(bytes_le=header[56:72])
    entries_lba, count, entry_size, entries_crc = struct.unpack_from("<QIII", header, 72)
    if (
        current_lba != lba
        or count != GPT_ENTRY_COUNT
        or entry_size != GPT_ENTRY_SIZE
        or first_usable > last_usable
    ):
        raise SystemExit("invalid GPT header geometry")
    return {
        "current_lba": current_lba,
        "backup_lba": backup_lba,
        "first_usable": first_usable,
        "last_usable": last_usable,
        "disk_uuid": disk_uuid,
        "entries_lba": entries_lba,
        "count": count,
        "entry_size": entry_size,
        "entries_crc": entries_crc,
    }


def _entries(data: bytes, header: dict[str, int | uuid.UUID]) -> bytes:
    start = int(header["entries_lba"]) * SECTOR
    length = int(header["count"]) * int(header["entry_size"])
    entries = data[start:start + length]
    if len(entries) != length or zlib.crc32(entries) != int(header["entries_crc"]):
        raise SystemExit("invalid GPT entries CRC")
    return entries


def _sectors(part) -> int:
    return part[3] - part[2] + 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    data = args.image.read_bytes()
    if len(data) < 640 * 1024 * 1024 or len(data) % SECTOR:
        raise SystemExit("single-USB image has invalid geometry")

    if data[510:512] != b"\x55\xaa":
        raise SystemExit("protective MBR signature missing")
    first_mbr = data[446:462]
    last_lba = len(data) // SECTOR - 1
    if (
        first_mbr[0] != 0
        or first_mbr[4] != 0xEE
        or struct.unpack_from("<I", first_mbr, 8)[0] != 1
        or struct.unpack_from("<I", first_mbr, 12)[0] != min(last_lba, 0xFFFFFFFF)
        or any(data[462:510])
    ):
        raise SystemExit("protective MBR is missing or contains hybrid partitions")

    primary = _parse_header(data, 1)
    backup = _parse_header(data, last_lba)
    if (
        int(primary["backup_lba"]) != last_lba
        or int(backup["backup_lba"]) != 1
        or primary["disk_uuid"] != backup["disk_uuid"]
        or primary["first_usable"] != backup["first_usable"]
        or primary["last_usable"] != backup["last_usable"]
        or primary["count"] != backup["count"]
        or primary["entry_size"] != backup["entry_size"]
        or primary["entries_crc"] != backup["entries_crc"]
        or int(primary["entries_lba"]) != 2
        or int(backup["entries_lba"]) != last_lba - GPT_TABLE_SECTORS
        or int(primary["first_usable"]) < 2 + GPT_TABLE_SECTORS
        or int(primary["last_usable"]) >= int(backup["entries_lba"])
    ):
        raise SystemExit("primary/backup GPT geometry mismatch")

    primary_entries = _entries(data, primary)
    backup_entries = _entries(data, backup)
    if primary_entries != backup_entries:
        raise SystemExit("primary/backup GPT partition tables differ")

    disk_uuid = primary["disk_uuid"]
    if disk_uuid != EXPECTED_DISK_UUID:
        raise SystemExit(f"unexpected GPT disk UUID: {disk_uuid}")

    partitions = []
    seen_empty = False
    for index in range(GPT_ENTRY_COUNT):
        entry = primary_entries[index * GPT_ENTRY_SIZE:(index + 1) * GPT_ENTRY_SIZE]
        if entry[:16] == bytes(16):
            seen_empty = True
            continue
        if seen_empty:
            raise SystemExit("non-contiguous GPT partition entries")
        part_type = uuid.UUID(bytes_le=entry[:16])
        part_uuid = uuid.UUID(bytes_le=entry[16:32])
        first_lba, last_part_lba, attrs = struct.unpack_from("<QQQ", entry, 32)
        name = entry[56:128].decode("utf-16le", errors="strict").rstrip("\x00")
        if (
            first_lba < int(primary["first_usable"])
            or last_part_lba > int(primary["last_usable"])
            or last_part_lba < first_lba
        ):
            raise SystemExit("GPT partition outside usable geometry")
        partitions.append((part_type, part_uuid, first_lba, last_part_lba, attrs, name))

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
        if _fat_label(data, part[2], require_fat32=label == "TX_TRANSFER") != label:
            raise SystemExit(f"{label} FAT volume label mismatch")

    expected_geometry = (
        (boot, BOOT_START_LBA, VAULT_START_LBA - 1, "USBCOLD_EFI"),
        (vault, VAULT_START_LBA, TRANSFER_START_LBA - 1, "COLD_VAULT"),
        (
            transfer,
            TRANSFER_START_LBA,
            TRANSFER_START_LBA + TRANSFER_SECTORS - 1,
            "TX_TRANSFER",
        ),
    )
    for part, expected_first, expected_last, label in expected_geometry:
        if part[2] != expected_first or part[3] != expected_last:
            raise SystemExit(f"{label} GPT LBA geometry mismatch")

    if boot[4] != GPT_READ_ONLY:
        raise SystemExit(
            "boot partition GPT attributes are not exactly read-only: "
            f"got 0x{boot[4]:016x}, expected 0x{GPT_READ_ONLY:016x}"
        )
    if vault[4] != 0 or transfer[4] != 0:
        raise SystemExit(
            "vault/transfer partition has unexpected GPT attributes: "
            f"vault=0x{vault[4]:016x}, transfer=0x{transfer[4]:016x}"
        )
    if boot[3] >= vault[2] or vault[3] >= transfer[2]:
        raise SystemExit("GPT partitions overlap or are out of order")

    if sum(1 for part in partitions if part[0] == BASIC_DATA_TYPE) != 1:
        raise SystemExit("Windows-visible Basic Data partition set is ambiguous")

    print(f"GPT single-USB structure OK; disk UUID={disk_uuid}")
    print("Primary/backup GPT headers, tables, CRCs and geometry match")
    for part in partitions:
        print(
            f"  {part[5] or '<unnamed>'}: UUID={part[1]} "
            f"LBA {part[2]}..{part[3]} type={part[0]} attrs=0x{part[4]:x}"
        )
    print("  Windows-visible data partition: TX_TRANSFER only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
