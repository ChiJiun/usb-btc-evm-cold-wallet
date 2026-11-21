#!/usr/bin/env python3
"""Fail-closed verification for release source, staged artifacts, and published assets.

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
from typing import Callable, Mapping

REPOSITORY = "ChiJiun/usb-btc-evm-cold-wallet"
RELEASE_WORKFLOW = f"{REPOSITORY}/.github/workflows/release.yml"
TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?")
SHA_RE = re.compile(r"[a-fA-F0-9]{40}")
ASSET_RE = re.compile(
    r"usb-cold-wallet-v[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?\.img(?:\.xz)?"
)
CHECKSUM_RE = re.compile(r"([a-fA-F0-9]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._+-]*)")
MAX_MANIFEST_BYTES = 128 * 1024
REQUIRED_STAGED_FILES = ("SBOM.spdx.json", "release-metadata.json", "build-host-packages.txt")
Run = Callable[[list[str]], str]


class ReleaseVerificationError(ValueError):
    """Unsafe or unverifiable release input."""


def _gh(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["gh", *args],
            check=True,
            capture_output=True,
            text=True,
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


def _safe_file(directory: Path, name: str) -> Path:
    path = directory / name
    if path.parent.resolve() != directory.resolve():
        raise ReleaseVerificationError("Release asset escaped the verification directory")
    if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
        raise ReleaseVerificationError(
            "Release asset is missing, empty, symlinked, or not a regular file"
        )
    return path


def parse_sha256sums_entries(raw: bytes) -> dict[str, str]:
    """Parse a strict GNU sha256sum manifest into safe basename entries."""
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
    if not entries:
        raise ReleaseVerificationError("SHA256SUMS is empty")
    return entries


def parse_sha256sums(raw: bytes, filename: str) -> str:
    """Require an unambiguous GNU sha256sum manifest with safe basenames."""
    entries = parse_sha256sums_entries(raw)
    if filename not in entries:
        raise ReleaseVerificationError("Requested asset is absent from SHA256SUMS")
    return entries[filename]


def _validate_identity(tag: str, commit: str, asset: str | None = None) -> tuple[str, str]:
    if not TAG_RE.fullmatch(tag):
        raise ReleaseVerificationError("Tag must be a full vMAJOR.MINOR.PATCH release tag")
    if not SHA_RE.fullmatch(commit):
        raise ReleaseVerificationError("Expected commit must be a full 40-character SHA")
    commit = commit.lower()
    if asset is not None:
        if (
            not ASSET_RE.fullmatch(asset)
            or not asset.startswith(f"usb-cold-wallet-{tag}.img")
        ):
            raise ReleaseVerificationError("Asset name does not match the pinned release tag")
    return tag, commit


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
        or target.get("sha", "").lower() != commit
        or not isinstance(verification, dict)
        or verification.get("verified") is not True
    ):
        raise ReleaseVerificationError("Tag signature, tag name, or pinned commit mismatch")


def verify_source(tag: str, commit: str, *, run: Run = _gh) -> None:
    """Verify only the independently pinned signed tag -> exact commit binding."""
    tag, commit = _validate_identity(tag, commit)
    _verify_signed_tag(run, tag, commit)


def _attest_args(image: Path, tag: str, commit: str) -> list[str]:
    return [
        "attestation",
        "verify",
        str(image),
        "-R",
        REPOSITORY,
        "--source-ref",
        f"refs/tags/{tag}",
        "--source-digest",
        commit,
        "--signer-workflow",
        RELEASE_WORKFLOW,
        "--signer-digest",
        commit,
        "--predicate-type",
        "https://slsa.dev/provenance/v1",
        "--deny-self-hosted-runners",
    ]


def _verify_metadata(path: Path, tag: str, commit: str, asset: str) -> None:
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReleaseVerificationError("Invalid release-metadata.json") from exc
    if not isinstance(metadata, dict):
        raise ReleaseVerificationError("release-metadata.json must contain an object")

    expected = {
        "repository": REPOSITORY,
        "tag": tag,
        "source_sha": commit,
        "workflow": ".github/workflows/release.yml",
        "asset": asset,
        "compression": "xz -6 --threads=1 --check=crc64 --no-sparse",
        "reproducibility_runs": 2,
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ReleaseVerificationError(f"Release metadata mismatch: {key}")

    digest = metadata.get("raw_image_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ReleaseVerificationError("Release metadata has invalid raw image digest")
    for key in ("buildroot_sha256",):
        value = metadata.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ReleaseVerificationError(f"Release metadata has invalid {key}")
    for key in ("buildroot_version", "node_version", "xz_version"):
        value = metadata.get(key)
        if not isinstance(value, str) or not value or len(value) > 80:
            raise ReleaseVerificationError(f"Release metadata has invalid {key}")
    for key in ("workflow_run_id", "workflow_run_attempt"):
        value = metadata.get(key)
        if not isinstance(value, str) or not value.isdigit():
            raise ReleaseVerificationError(f"Release metadata has invalid {key}")


def _verify_spdx(path: Path) -> None:
    try:
        sbom = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReleaseVerificationError("Invalid SPDX SBOM") from exc
    if (
        not isinstance(sbom, dict)
        or sbom.get("spdxVersion") != "SPDX-2.3"
        or sbom.get("SPDXID") != "SPDXRef-DOCUMENT"
        or sbom.get("dataLicense") != "CC0-1.0"
    ):
        raise ReleaseVerificationError("SPDX SBOM identity is invalid")


def _verify_build_provenance(
    run: Run, directory: Path, names: list[str], tag: str, commit: str
) -> None:
    for name in names:
        run(_attest_args(_safe_file(directory, name), tag, commit))


def verify_local_artifacts(
    tag: str,
    commit: str,
    asset: str,
    directory: str | Path,
    *,
    run: Run = _gh,
) -> str:
    """Verify the exact staged bytes after attestation and before publish."""
    tag, commit = _validate_identity(tag, commit, asset)
    _verify_signed_tag(run, tag, commit)

    root = Path(directory)
    if not root.is_dir() or root.is_symlink():
        raise ReleaseVerificationError("Local release directory is missing or unsafe")

    manifest = _safe_file(root, "SHA256SUMS")
    entries = parse_sha256sums_entries(manifest.read_bytes())
    expected_names = {asset, *REQUIRED_STAGED_FILES}
    if set(entries) != expected_names:
        raise ReleaseVerificationError(
            "SHA256SUMS must cover exactly the final image, SBOM, and release metadata"
        )

    for name, expected_digest in entries.items():
        actual_digest = _sha256(_safe_file(root, name))
        if actual_digest != expected_digest:
            raise ReleaseVerificationError(f"Staged release digest mismatch: {name}")

    image = _safe_file(root, asset)
    _verify_metadata(_safe_file(root, "release-metadata.json"), tag, commit, asset)
    _verify_spdx(_safe_file(root, "SBOM.spdx.json"))

    # Every published byte set is independently bound to the same signed tag,
    # source commit and release workflow. A substituted manifest/SBOM/metadata
    # therefore cannot authenticate a different image.
    _verify_build_provenance(
        run,
        root,
        ["SHA256SUMS", asset, *REQUIRED_STAGED_FILES],
        tag,
        commit,
    )
    return _sha256(image)


def require_successful_jobs(job_results: Mapping[str, str]) -> None:
    """Fail closed unless every required release job completed successfully."""
    required = {"build", "attest", "verify"}
    if set(job_results) != required:
        raise ReleaseVerificationError("Release gate is missing a required job result")
    failed = [name for name in sorted(required) if job_results.get(name) != "success"]
    if failed:
        raise ReleaseVerificationError(
            "Required release jobs did not succeed: " + ", ".join(failed)
        )


def verify_release(tag: str, commit: str, asset: str, *, run: Run = _gh) -> str:
    """Independently download and verify an already-published immutable release."""
    tag, commit = _validate_identity(tag, commit, asset)
    _verify_signed_tag(run, tag, commit)

    release = _json(
        run,
        ["release", "view", tag, "-R", REPOSITORY, "--json", "tagName,isDraft"],
    )
    if release.get("tagName") != tag or release.get("isDraft") is not False:
        raise ReleaseVerificationError("Release is draft or points to a different tag")

    # This checks GitHub's immutable-release integrity attestation, not the
    # separate build provenance attestation verified below.
    run(["release", "verify", tag, "-R", REPOSITORY])

    with tempfile.TemporaryDirectory(prefix="wallet-release-verify-") as temp:
        directory = Path(temp)
        release_files = ["SHA256SUMS", asset, *REQUIRED_STAGED_FILES]
        for name in release_files:
            run(
                [
                    "release",
                    "download",
                    tag,
                    "-R",
                    REPOSITORY,
                    "--pattern",
                    name,
                    "--dir",
                    str(directory),
                ]
            )
            _safe_file(directory, name)

        manifest = _safe_file(directory, "SHA256SUMS")
        entries = parse_sha256sums_entries(manifest.read_bytes())
        expected_names = {asset, *REQUIRED_STAGED_FILES}
        if set(entries) != expected_names:
            raise ReleaseVerificationError(
                "SHA256SUMS must cover exactly every published payload file"
            )
        for name, expected_digest in entries.items():
            if _sha256(_safe_file(directory, name)) != expected_digest:
                raise ReleaseVerificationError(f"Downloaded release digest mismatch: {name}")

        image = _safe_file(directory, asset)
        actual = _sha256(image)
        _verify_metadata(_safe_file(directory, "release-metadata.json"), tag, commit, asset)
        _verify_spdx(_safe_file(directory, "SBOM.spdx.json"))

        # Authenticate every published file with immutable-release integrity
        # and the same SLSA source/workflow identity.
        for name in release_files:
            run(
                [
                    "release",
                    "verify-asset",
                    tag,
                    str(directory / name),
                    "-R",
                    REPOSITORY,
                ]
            )
        _verify_build_provenance(run, directory, release_files, tag, commit)
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Signed annotated release tag")
    parser.add_argument(
        "--commit",
        required=True,
        help="Independently pinned source commit SHA",
    )
    parser.add_argument("--asset", help="Exact .img or .img.xz asset name")
    parser.add_argument(
        "--local-dir",
        help="Verify already-built final bytes in this directory; never downloads assets",
    )
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="Verify only signed tag -> exact source commit binding",
    )
    args = parser.parse_args()

    try:
        if args.source_only:
            if args.asset or args.local_dir:
                raise ReleaseVerificationError(
                    "--source-only cannot be combined with artifact verification options"
                )
            verify_source(args.tag, args.commit)
            print(f"VERIFIED SOURCE: {args.tag} -> {args.commit.lower()}")
            return 0

        if not args.asset:
            raise ReleaseVerificationError("--asset is required for artifact verification")

        if args.local_dir:
            digest = verify_local_artifacts(
                args.tag,
                args.commit,
                args.asset,
                args.local_dir,
            )
        else:
            digest = verify_release(args.tag, args.commit, args.asset)
    except ReleaseVerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print(f"VERIFIED: {args.asset} sha256:{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
