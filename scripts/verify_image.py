#!/usr/bin/env python3
"""Structural verification of the generated GPT USB image."""
from __future__ import annotations

import argparse
from pathlib import Path
import struct
import uuid


EXPECTED_DISK_UUID = uuid.UUID("f1448aa1-28cc-54bf-8fdd-3008514c0ab5")
EXPECTED_BOOT_UUID = uuid.UUID("e2bd6d1b-8de5-502d-a897-c53a8e60f46b")
EXPECTED_VAULT_UUID = uuid.UUID("18f1c36f-d5c0-5052-9cd2-03e9c2a48f00")
EFI_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
BASIC_DATA_TYPE = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")
GPT_READ_ONLY = 1 << 60


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    data = args.image.read_bytes()
    if len(data) < 128 * 1024 * 1024:
        raise SystemExit("image is unexpectedly small")
    if data[510:512] != b"\x55\xaa":
        raise SystemExit("protective MBR signature missing")

    sector = 512
    header = data[sector : sector * 2]
    if header[:8] != b"EFI PART":
        raise SystemExit("GPT header missing")

    disk_uuid = uuid.UUID(bytes_le=header[56:72])
    if disk_uuid != EXPECTED_DISK_UUID:
        raise SystemExit(f"unexpected GPT disk UUID: {disk_uuid}")

    entries_lba = struct.unpack_from("<Q", header, 72)[0]
    count = struct.unpack_from("<I", header, 80)[0]
    entry_size = struct.unpack_from("<I", header, 84)[0]
    partitions = []
    for index in range(min(count, 16)):
        start = entries_lba * sector + index * entry_size
        entry = data[start : start + entry_size]
        type_raw = entry[:16]
        if type_raw == bytes(16):
            continue
        part_type = uuid.UUID(bytes_le=type_raw)
        part_uuid = uuid.UUID(bytes_le=entry[16:32])
        first_lba, last_lba, attrs = struct.unpack_from("<QQQ", entry, 32)
        name = entry[56:128].decode("utf-16le", errors="ignore").rstrip("\x00")
        partitions.append((part_type, part_uuid, first_lba, last_lba, attrs, name))

    if len(partitions) != 2:
        raise SystemExit(f"expected exactly two GPT partitions, got {len(partitions)}")

    boot, vault = partitions
    if boot[0] != EFI_TYPE:
        raise SystemExit("first partition is not EFI System Partition")
    if boot[1] != EXPECTED_BOOT_UUID:
        raise SystemExit(f"unexpected boot partition UUID: {boot[1]}")
    if not (boot[4] & GPT_READ_ONLY):
        raise SystemExit("boot partition is not marked GPT read-only")

    if vault[0] != BASIC_DATA_TYPE:
        raise SystemExit("vault partition is not Microsoft basic data / FAT type")
    if vault[1] != EXPECTED_VAULT_UUID:
        raise SystemExit(f"unexpected vault partition UUID: {vault[1]}")
    if vault[4] & GPT_READ_ONLY:
        raise SystemExit("vault partition unexpectedly marked read-only")

    if boot[3] >= vault[2]:
        raise SystemExit("GPT partitions overlap")

    print(f"GPT image structure OK; disk UUID={disk_uuid}")
    for part in partitions:
        print(
            f"  {part[5] or '<unnamed>'}: UUID={part[1]} "
            f"LBA {part[2]}..{part[3]} type={part[0]} attrs=0x{part[4]:x}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
