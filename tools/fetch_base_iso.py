from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from tools.image_common import (
    ImageBuildError,
    load_json,
    normalized_fingerprint,
    parse_sha256sums,
    sha256_file,
)

USER_AGENT = "usb-btc-evm-cold-wallet-image-builder/0.1"


def _download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        os.replace(partial, destination)
    except Exception:
        partial.unlink(missing_ok=True)
        raise


def _ensure_file(url: str, destination: Path, offline: bool) -> None:
    if destination.is_file():
        return
    if offline:
        raise ImageBuildError(f"offline mode: required file missing: {destination}")
    try:
        _download(url, destination)
    except Exception as exc:
        raise ImageBuildError(f"download failed: {url}: {exc}") from exc


def _verify_signing_key_and_signature(
    key_path: Path, signature_path: Path, sums_path: Path, expected_fingerprint: str
) -> str:
    expected = normalized_fingerprint(expected_fingerprint)
    if shutil.which("gpg") is None:
        raise ImageBuildError("gpg is required to authenticate Debian checksum metadata")

    show = subprocess.run(
        [
            "gpg",
            "--batch",
            "--with-colons",
            "--import-options",
            "show-only",
            "--import",
            str(key_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if show.returncode != 0:
        raise ImageBuildError(f"cannot inspect Debian signing key: {show.stderr.strip()}")
    fingerprints = [
        line.split(":")[9].upper()
        for line in show.stdout.splitlines()
        if line.startswith("fpr:") and len(line.split(":")) > 9
    ]
    if expected not in fingerprints:
        raise ImageBuildError(
            f"Debian key fingerprint mismatch: expected {expected}, got {fingerprints or 'none'}"
        )

    with tempfile.TemporaryDirectory(prefix="usbwallet-gnupg-") as temp:
        home = Path(temp)
        home.chmod(0o700)
        imported = subprocess.run(
            ["gpg", "--batch", "--homedir", str(home), "--import", str(key_path)],
            text=True,
            capture_output=True,
            check=False,
        )
        if imported.returncode != 0:
            raise ImageBuildError(f"cannot import Debian signing key: {imported.stderr.strip()}")
        verified = subprocess.run(
            [
                "gpg",
                "--batch",
                "--homedir",
                str(home),
                "--status-fd",
                "1",
                "--verify",
                str(signature_path),
                str(sums_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
    if verified.returncode != 0:
        detail = (verified.stderr or verified.stdout).strip()
        raise ImageBuildError(f"Debian checksum signature verification failed: {detail}")
    valid = []
    for line in verified.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "[GNUPG:]" and fields[1] == "VALIDSIG":
            valid.append(fields[2].upper())
    if expected not in valid:
        raise ImageBuildError(f"signature is valid but not from pinned Debian key {expected}")
    return expected


def fetch_and_verify(config_path: Path, cache_dir: Path, offline: bool = False) -> dict[str, str]:
    config = load_json(config_path)
    required = (
        "base_url",
        "iso_filename",
        "sha256",
        "checksums_filename",
        "signature_filename",
        "signing_key_url",
        "signing_key_fingerprint",
    )
    for key in required:
        if not isinstance(config.get(key), str) or not config[key]:
            raise ImageBuildError(f"base image config missing {key}")

    cache_dir.mkdir(parents=True, exist_ok=True)
    base_url = config["base_url"].rstrip("/")
    key_path = cache_dir / "debian-cd-signing-key.asc"
    sums_path = cache_dir / config["checksums_filename"]
    sig_path = cache_dir / config["signature_filename"]
    iso_path = cache_dir / config["iso_filename"]

    _ensure_file(config["signing_key_url"], key_path, offline)
    _ensure_file(f"{base_url}/{config['checksums_filename']}", sums_path, offline)
    _ensure_file(f"{base_url}/{config['signature_filename']}", sig_path, offline)

    signer = _verify_signing_key_and_signature(
        key_path, sig_path, sums_path, config["signing_key_fingerprint"]
    )
    signed_sums = parse_sha256sums(sums_path.read_text(encoding="utf-8"))
    signed_digest = signed_sums.get(config["iso_filename"])
    if signed_digest is None:
        raise ImageBuildError("pinned ISO is absent from Debian's signed SHA256SUMS")
    pinned_digest = config["sha256"].lower()
    if signed_digest != pinned_digest:
        raise ImageBuildError(
            f"signed Debian checksum {signed_digest} differs from repository pin {pinned_digest}"
        )

    if not iso_path.is_file() or sha256_file(iso_path) != pinned_digest:
        if offline:
            raise ImageBuildError(f"offline mode: valid base ISO missing: {iso_path}")
        iso_path.unlink(missing_ok=True)
        _download(f"{base_url}/{config['iso_filename']}", iso_path)
    actual = sha256_file(iso_path)
    if actual != pinned_digest:
        raise ImageBuildError(f"base ISO SHA-256 mismatch: expected {pinned_digest}, got {actual}")

    return {
        "iso": str(iso_path),
        "sha256": actual,
        "signer_fingerprint": signer,
        "release": str(config.get("release", "")),
        "architecture": str(config.get("architecture", "")),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch and authenticate the pinned Debian Live base ISO")
    parser.add_argument("--config", type=Path, default=Path("image/base-image.json"))
    parser.add_argument("--cache-dir", type=Path, default=Path("build/cache/base-image"))
    parser.add_argument("--offline", action="store_true", help="perform no downloads; only verify cached files")
    args = parser.parse_args()
    try:
        result = fetch_and_verify(args.config, args.cache_dir, args.offline)
    except ImageBuildError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
