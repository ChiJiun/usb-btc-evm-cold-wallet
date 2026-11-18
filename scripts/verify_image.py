#!/usr/bin/env python3
"""Cheap structural verification of the generated GPT USB image."""
from __future__ import annotations

import argparse
from pathlib import Path
import struct
import uuid


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
        first_lba, last_lba = struct.unpack_from("<QQ", entry, 32)
        name = entry[56:128].decode("utf-16le", errors="ignore").rstrip("\x00")
        partitions.append((uuid.UUID(bytes_le=type_raw), first_lba, last_lba, name))
    if len(partitions) != 2:
        raise SystemExit(f"expected exactly two GPT partitions, got {len(partitions)}")
    efi_type = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
    if partitions[0][0] != efi_type:
        raise SystemExit("first partition is not EFI System Partition")
    if partitions[0][2] >= partitions[1][1]:
        raise SystemExit("GPT partitions overlap")
    print("GPT image structure OK")
    for part in partitions:
        print(f"  {part[3] or '<unnamed>'}: LBA {part[1]}..{part[2]} type={part[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
