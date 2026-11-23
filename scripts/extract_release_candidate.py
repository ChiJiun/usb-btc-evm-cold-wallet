#!/usr/bin/env python3
"""Verify a pinned GitHub artifact ZIP before bounded, safe extraction."""
from __future__ import annotations

import argparse
import hashlib
import re
import stat
import zipfile
from pathlib import Path

from scripts.verify_release_assets import (
    ASSET_RE, MAX_MANIFEST_BYTES, MAX_RAW_IMAGE_BYTES,
    REQUIRED_STAGED_FILES, ReleaseVerificationError,
)

LIMITS = {
    "SHA256SUMS": MAX_MANIFEST_BYTES,
    "release-metadata.json": MAX_MANIFEST_BYTES,
    "SBOM.spdx.json": 256 * 1024 * 1024,
    "build-host-packages.txt": 8 * 1024 * 1024,
}


def extract_candidate_archive(archive_dir: str | Path, output_dir: str | Path,
                              expected_digest: str) -> None:
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", expected_digest):
        raise ReleaseVerificationError("Missing or invalid pinned artifact digest")
    source, destination = Path(archive_dir), Path(output_dir)
    if not source.is_dir() or source.is_symlink():
        raise ReleaseVerificationError("Unsafe archive directory")
    archives = list(source.iterdir())
    if len(archives) != 1 or not archives[0].is_file() or archives[0].is_symlink():
        raise ReleaseVerificationError("Expected exactly one regular artifact ZIP")
    archive = archives[0]
    if archive.stat().st_size > MAX_RAW_IMAGE_BYTES:
        raise ReleaseVerificationError("Artifact ZIP too large")
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected_digest.removeprefix("sha256:"):
        raise ReleaseVerificationError("Artifact ZIP digest mismatch")
    if destination.exists() and (
        not destination.is_dir() or destination.is_symlink() or any(destination.iterdir())
    ):
        raise ReleaseVerificationError("Artifact destination must be empty and safe")

    try:
        with zipfile.ZipFile(archive) as zipped:
            members = zipped.infolist()
            names = [info.filename for info in members]
            assets = [name for name in names if ASSET_RE.fullmatch(name)]
            expected = set(LIMITS) | set(assets)
            if len(assets) != 1 or len(names) != len(expected) or set(names) != expected:
                raise ReleaseVerificationError("Unsafe, missing, or duplicate ZIP member")
            for member in members:
                mode = stat.S_IFMT(member.external_attr >> 16)
                bound = LIMITS.get(member.filename, MAX_RAW_IMAGE_BYTES)
                if (
                    member.is_dir() or mode not in (0, stat.S_IFREG)
                    or member.flag_bits & 1
                    or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or not (0 < member.file_size <= bound)
                ):
                    raise ReleaseVerificationError("Unsafe ZIP member type or size")
            destination.mkdir(parents=True, exist_ok=True)
            for member in members:
                bound = LIMITS.get(member.filename, MAX_RAW_IMAGE_BYTES)
                with zipped.open(member) as src, (destination / member.filename).open("xb") as dest:
                    length = 0
                    while data := src.read(1024 * 1024):
                        length += len(data)
                        if length > bound:
                            raise ReleaseVerificationError("ZIP member expansion limit exceeded")
                        dest.write(data)
                    if length != member.file_size:
                        raise ReleaseVerificationError("ZIP member length mismatch")
    except (zipfile.BadZipFile, OSError, EOFError, RuntimeError) as exc:
        raise ReleaseVerificationError("Malformed or truncated artifact ZIP") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--expected-digest", required=True)
    args = parser.parse_args()
    try:
        extract_candidate_archive(args.archive_dir, args.output_dir, args.expected_digest)
    except ReleaseVerificationError as exc:
        parser.exit(1, f"FAIL: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
