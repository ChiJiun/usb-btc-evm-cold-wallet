#!/usr/bin/env python3
"""Prepare an exact-capacity regular-file single-USB image; never touch a disk device.

Only GPT metadata is relocated. Partition entries and payloads are preserved.
The output is a derived testnet image, not the reproducible CI artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import zlib

if __package__:
    from .verify_image import SECTOR, GPT_TABLE_SECTORS, _parse_header, _entries, verify_image_data
else:
    from verify_image import SECTOR, GPT_TABLE_SECTORS, _parse_header, _entries, verify_image_data

MAX_SOURCE = 1024 ** 3
MAX_CAPACITY = 128 * 1024 ** 3


def _set_header_geometry(header, *, current, backup, last_usable, entries_lba):
    struct.pack_into("<Q", header, 24, current)
    struct.pack_into("<Q", header, 32, backup)
    struct.pack_into("<Q", header, 48, last_usable)
    struct.pack_into("<Q", header, 72, entries_lba)
    struct.pack_into("<I", header, 16, 0)
    struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))


def relocate_gpt(handle, capacity: int) -> None:
    """Operate on a disposable regular-file copy, never on a block device."""
    info = os.fstat(handle.fileno())
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("only a regular image file may be prepared")
    old_size = info.st_size
    if (type(capacity) is not int or capacity % SECTOR or capacity > MAX_CAPACITY or
            capacity < old_size + (GPT_TABLE_SECTORS + 1) * SECTOR):
        raise ValueError("target capacity must be sector-aligned and larger than the source")
    old_last = old_size // SECTOR - 1
    new_last = capacity // SECTOR - 1
    old_table = old_last - GPT_TABLE_SECTORS
    new_table = new_last - GPT_TABLE_SECTORS
    handle.flush()
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as image:
        verify_image_data(image)
        primary_info = _parse_header(image, 1)
        entries = _entries(image, primary_info)
        mbr = bytearray(image[:SECTOR])
        primary = bytearray(image[SECTOR:2 * SECTOR])
        backup = bytearray(image[old_last * SECTOR:(old_last + 1) * SECTOR])
    # Old secondary metadata is outside every verified fixed partition.
    # Remove the stale GPT at its former end before relocating it.
    handle.seek(old_table * SECTOR)
    handle.write(bytes((GPT_TABLE_SECTORS + 1) * SECTOR))
    handle.truncate(capacity)
    struct.pack_into("<I", mbr, 458, min(new_last, 0xFFFFFFFF))
    _set_header_geometry(primary, current=1, backup=new_last,
                         last_usable=new_table - 1, entries_lba=2)
    _set_header_geometry(backup, current=new_last, backup=1,
                         last_usable=new_table - 1, entries_lba=new_table)
    handle.seek(0)
    handle.write(mbr)
    handle.write(primary)
    handle.seek(new_table * SECTOR)
    handle.write(entries)
    handle.write(backup)
    handle.flush()
    os.fsync(handle.fileno())
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as image:
        verify_image_data(image)
        if (_entries(image, _parse_header(image, 1)) != entries or
                _entries(image, _parse_header(image, new_last)) != entries):
            raise ValueError("partition entries changed during capacity preparation")


def prepare_image(source: Path, output: Path, capacity: int, expected_sha256: str) -> dict:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise ValueError("an independently obtained CI raw image SHA-256 is required")
    if source.is_symlink() or not source.is_file() or output.exists() or output.is_symlink():
        raise ValueError("source must be a regular file and output must not exist")
    # Copy/hash in one pass before any GPT modification. Exclusive temporary
    # creation and no-replace publication prevent overwriting another file.
    with source.open("rb") as original:
        info = os.fstat(original.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_SOURCE:
            raise ValueError("source must be a bounded regular CI image")
        if (type(capacity) is not int or capacity % SECTOR or capacity > MAX_CAPACITY or
                capacity < info.st_size + (GPT_TABLE_SECTORS + 1) * SECTOR):
            raise ValueError("invalid target capacity")
        digest = hashlib.sha256()
        temp = None
        try:
            with tempfile.NamedTemporaryFile(mode="w+b", dir=output.parent,
                                             prefix=".wallet-capacity-", delete=False) as copy:
                temp = Path(copy.name)
                remaining = info.st_size
                while remaining:
                    chunk = original.read(min(1024 ** 2, remaining))
                    if not chunk:
                        raise ValueError("source truncated during copy")
                    digest.update(chunk)
                    if chunk == bytes(len(chunk)):
                        copy.seek(len(chunk), os.SEEK_CUR)
                    else:
                        copy.write(chunk)
                    remaining -= len(chunk)
                if original.read(1) or digest.hexdigest() != expected_sha256.lower():
                    raise ValueError("source image SHA-256 mismatch")
                copy.truncate(info.st_size)
                relocate_gpt(copy, capacity)
                copy.seek(0)
                derived = hashlib.file_digest(copy, "sha256").hexdigest()
            os.link(temp, output)  # atomic, fails rather than replaces
            return {
                "sourceSha256": digest.hexdigest(), "derivedSha256": derived,
                "sourceSizeBytes": info.st_size, "derivedSizeBytes": capacity,
                "physicalMediaVerified": False, "releaseArtifact": False,
            }
        finally:
            if temp is not None:
                temp.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--capacity-bytes", type=int, required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(prepare_image(args.source, args.output, args.capacity_bytes,
                                   args.expected_sha256), sort_keys=True))


if __name__ == "__main__":
    main()
