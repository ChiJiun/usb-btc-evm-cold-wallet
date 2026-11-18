from __future__ import annotations

import argparse
import json
import os
import shutil
import urllib.parse
import urllib.request
from pathlib import Path

from tools.image_common import ImageBuildError, load_json, sha256_file, validate_lock_manifest

USER_AGENT = "usb-btc-evm-cold-wallet-image-builder/0.1"
PYPI_BASE = "https://pypi.org/pypi"


def _request_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            value = json.load(response)
    except Exception as exc:
        raise ImageBuildError(f"cannot fetch package metadata {url}: {exc}") from exc
    if not isinstance(value, dict):
        raise ImageBuildError(f"unexpected package metadata from {url}")
    return value


def _download(url: str, destination: Path, expected_sha256: str) -> None:
    partial = destination.with_name(destination.name + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        actual = sha256_file(partial)
        if actual != expected_sha256:
            raise ImageBuildError(
                f"artifact hash mismatch for {destination.name}: expected {expected_sha256}, got {actual}"
            )
        os.replace(partial, destination)
    except Exception:
        partial.unlink(missing_ok=True)
        raise


def verify_artifacts(lock_path: Path, artifact_dir: Path) -> list[dict]:
    manifest = load_json(lock_path)
    artifacts = validate_lock_manifest(manifest)
    for artifact in artifacts:
        path = artifact_dir / artifact["filename"]
        if not path.is_file():
            raise ImageBuildError(f"missing locked Python artifact: {path.name}")
        actual = sha256_file(path)
        if actual != artifact["sha256"].lower():
            raise ImageBuildError(
                f"Python artifact hash mismatch for {path.name}: expected {artifact['sha256']}, got {actual}"
            )
    return artifacts


def fetch_artifacts(
    lock_path: Path, artifact_dir: Path, offline: bool = False, pypi_base: str = PYPI_BASE
) -> list[dict]:
    manifest = load_json(lock_path)
    artifacts = validate_lock_manifest(manifest)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    for artifact in artifacts:
        destination = artifact_dir / artifact["filename"]
        expected = artifact["sha256"].lower()
        if destination.is_file() and sha256_file(destination) == expected:
            continue
        destination.unlink(missing_ok=True)
        if offline:
            raise ImageBuildError(f"offline mode: missing valid artifact {artifact['filename']}")

        package = urllib.parse.quote(artifact["package"], safe="")
        version = urllib.parse.quote(artifact["version"], safe="")
        metadata = _request_json(f"{pypi_base.rstrip('/')}/{package}/{version}/json")
        candidates = [
            item
            for item in metadata.get("urls", [])
            if isinstance(item, dict) and item.get("filename") == artifact["filename"]
        ]
        if len(candidates) != 1:
            raise ImageBuildError(
                f"PyPI metadata did not contain exactly one locked artifact {artifact['filename']}"
            )
        candidate = candidates[0]
        metadata_digest = ((candidate.get("digests") or {}).get("sha256") or "").lower()
        if metadata_digest != expected:
            raise ImageBuildError(
                f"PyPI hash for {artifact['filename']} changed: {metadata_digest or 'missing'}"
            )
        url = candidate.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ImageBuildError(f"invalid PyPI artifact URL for {artifact['filename']}")
        _download(url, destination, expected)

    verify_artifacts(lock_path, artifact_dir)
    return artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch the exact hash-locked Python artifacts for the Live ISO")
    parser.add_argument("--lock", type=Path, default=Path("image/python-artifacts.lock.json"))
    parser.add_argument("--artifact-dir", type=Path, default=Path("build/cache/python-artifacts"))
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        artifacts = fetch_artifacts(args.lock, args.artifact_dir, args.offline)
    except ImageBuildError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "artifact_dir": str(args.artifact_dir),
                "artifact_count": len(artifacts),
                "status": "verified",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
