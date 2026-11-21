#!/usr/bin/env python3
"""Fail-closed, independent verification of a published USB wallet release.

Requires a recent GitHub CLI (gh) with release integrity and artifact
attestation commands. Never downloads arbitrary URLs or executes release assets.
The expected commit must come from a separately trusted source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

REPOSITORY = "ChiJiun/usb-btc-evm-cold-wallet"
TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?")
SHA_RE = re.compile(r"[a-fA-F0-9]{40}")
ASSET_RE = re.compile(r"usb-cold-wallet-v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?\.img(?:\.xz)?")
CHECKSUM_RE = re.compile(r"([a-fA-F0-9]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._+-]*)")
MAX_MANIFEST_BYTES = 128 * 1024
Run = Callable[[list[str]], str]


class ReleaseVerificationError(ValueError):
    """Unsafe or unverifiable release input."""


def _gh(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["gh", *args], check=True, capture_output=True, text=True,
            timeout=180,
        )
        return result.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        # Never echo stderr: CLI errors can include credentials or remote data.
        raise ReleaseVerificationError(
            "GitHub CLI verification failed: " + " ".join(args[:2])
        ) from exc


def _json(run: Run, args: list[str]) -> dict:
    try:
        value = json.loads(run(args))
    except (ValueError, TypeError) as exc:
        raise ReleaseVerificationError("Invalid GitHub API JSON response") from exc
    if not isinstance(value, dict):
        raise ReleaseVerificationError("Expected a GitHub JSON object")
    return value


def _sha256(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _safe_download(directory: Path, name: str) -> Path:
    path = directory / name
    if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
        raise ReleaseVerificationError("Release asset is missing, empty, or not a regular file")
    return path


def parse_sha256sums(raw: bytes, filename: str) -> str:
    """Require an unambiguous GNU sha256sum manifest with safe basenames."""
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ReleaseVerificationError("SHA256SUMS is too large")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise ReleaseVerificationError("SHA256SUMS must be ASCII") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if not line:
            continue
        match = CHECKSUM_RE.fullmatch(line)
        if not match:
            raise ReleaseVerificationError("Invalid or unsafe SHA256SUMS line")
        digest, name = match.groups()
        if name in entries:
            raise ReleaseVerificationError("Duplicate SHA256SUMS entry")
        entries[name] = digest.lower()
    if filename not in entries:
        raise ReleaseVerificationError("Requested asset is absent from SHA256SUMS")
    return entries[filename]


def _verify_signed_tag(run: Run, tag: str, commit: str) -> None:
    ref = _json(run, ["api", f"repos/{REPOSITORY}/git/ref/tags/{tag}"])
    obj = ref.get("object")
    if not isinstance(obj, dict) or obj.get("type") != "tag":
        raise ReleaseVerificationError("Lightweight or missing signed annotated tag")
    tag_sha = obj.get("sha")
    if not isinstance(tag_sha, str) or not SHA_RE.fullmatch(tag_sha):
        raise ReleaseVerificationError("Malformed annotated tag object")
    annotated = _json(run, ["api", f"repos/{REPOSITORY}/git/tags/{tag_sha}"])
    target = annotated.get("object")
    verification = annotated.get("verification")
    if (
        annotated.get("tag") != tag
        or not isinstance(target, dict)
        or target.get("type") != "commit"
        or target.get("sha") != commit
        or not isinstance(verification, dict)
        or verification.get("verified") is not True
    ):
        raise ReleaseVerificationError("Tag signature, tag name, or pinned commit mismatch")


def verify_release(tag: str, commit: str, asset: str, *, run: Run = _gh) -> str:
    if not TAG_RE.fullmatch(tag):
        raise ReleaseVerificationError("Tag must be a full vMAJOR.MINOR.PATCH release tag")
    if not SHA_RE.fullmatch(commit):
        raise ReleaseVerificationError("Expected commit must be a full 40-character SHA")
    commit = commit.lower()
    if not ASSET_RE.fullmatch(asset) or not asset.startswith(f"usb-cold-wallet-{tag}.img"):
        raise ReleaseVerificationError("Asset name does not match the pinned release tag")

    _verify_signed_tag(run, tag, commit)
    release = _json(run, ["release", "view", tag, "-R", REPOSITORY, "--json", "tagName,isDraft"])
    if release.get("tagName") != tag or release.get("isDraft") is not False:
        raise ReleaseVerificationError("Release is draft or points to a different tag")

    # This checks GitHub's release integrity attestation (immutable release),
    # not the separate build provenance attestation verified below.
    run(["release", "verify", tag, "-R", REPOSITORY])
    with tempfile.TemporaryDirectory(prefix="wallet-release-verify-") as temp:
        directory = Path(temp)
        for name in ("SHA256SUMS", asset):
            run(["release", "download", tag, "-R", REPOSITORY,
                 "--pattern", name, "--dir", str(directory)])
            _safe_download(directory, name)

        manifest = _safe_download(directory, "SHA256SUMS")
        if manifest.stat().st_size > MAX_MANIFEST_BYTES:
            raise ReleaseVerificationError("SHA256SUMS is too large")
        expected = parse_sha256sums(manifest.read_bytes(), asset)
        image = _safe_download(directory, asset)
        actual = _sha256(image)
        if actual != expected:
            raise ReleaseVerificationError("Downloaded binary does not match SHA256SUMS")

        # Independently authenticate the release manifest and binary against
        # GitHub's signed immutable-release asset attestations.
        for name in ("SHA256SUMS", asset):
            run(["release", "verify-asset", tag, str(directory / name), "-R", REPOSITORY])

        # Pin the build identity in addition to artifact digest and repository:
        # no successful attestation from a different tag/commit/workflow counts.
        run(["attestation", "verify", str(image), "-R", REPOSITORY,
             "--source-ref", f"refs/tags/{tag}", "--source-digest", commit,
             "--signer-workflow", f"{REPOSITORY}/.github/workflows/release.yml",
             "--deny-self-hosted-runners"])
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Signed annotated release tag")
    parser.add_argument("--commit", required=True, help="Independently pinned source commit SHA")
    parser.add_argument("--asset", required=True, help="Exact .img or .img.xz asset name")
    args = parser.parse_args()
    try:
        digest = verify_release(args.tag, args.commit, args.asset)
    except ReleaseVerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"VERIFIED: {args.asset} sha256:{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
