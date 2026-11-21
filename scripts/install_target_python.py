#!/usr/bin/env python3
"""Install the hash-verified Python payload into a Buildroot target rootfs.

No package manager runs in the target image. Wheels are ZIP archives and are
expanded directly after their exact SHA-256 values were verified.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import shutil
import tarfile
from zipfile import ZipFile

from build_offline_wheel import ALLOWED_OFFLINE_MODULES, ONLINE_MODULES

PYTHON = "3.14"
TARGET_EMBIT_PREBUILT = "libsecp256k1_linux_x86_64.so"


def _keep_target_embit_prebuilt(extracted: Path) -> None:
    """Remove hash-pinned embit binaries that target other OS/CPU combinations."""
    prebuilt = extracted / "util/prebuilt"
    allowed = prebuilt / TARGET_EMBIT_PREBUILT
    if not allowed.is_file():
        raise SystemExit("embit x86_64 libsecp256k1 prebuilt library is missing")
    for artifact in prebuilt.iterdir():
        if artifact.is_file() and artifact != allowed:
            artifact.unlink()


def _manifest(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        digest, filename = line.split(None, 1)
        result[filename.strip().lstrip("*")] = digest
    return result


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _install_verified_offline_package(source: Path, destination: Path) -> None:
    """Install only reviewed offline modules; never copy Companion/RPC code into Live USB."""
    if not source.is_dir() or source.is_symlink():
        raise SystemExit("Offline package source is missing or not a real directory")
    available = {entry.name for entry in source.iterdir() if entry.suffix == ".py"}
    required = ALLOWED_OFFLINE_MODULES | ONLINE_MODULES
    if available != required:
        raise SystemExit(f"Unreviewed or missing Python modules: {sorted(available ^ required)}")
    destination.mkdir(parents=True, exist_ok=True)
    for name in sorted(ALLOWED_OFFLINE_MODULES):
        entry = source / name
        if not entry.is_file() or entry.is_symlink():
            raise SystemExit(f"Untrusted offline module path: {name}")
        shutil.copy2(entry, destination / name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()

    expected = _manifest(args.source / "infra/wheelhouse.sha256")
    actual_names = {path.name for path in args.wheelhouse.iterdir() if path.is_file()}
    if actual_names != set(expected):
        missing = sorted(set(expected) - actual_names)
        extra = sorted(actual_names - set(expected))
        raise SystemExit(f"wheelhouse file set mismatch; missing={missing}, extra={extra}")

    for filename, digest in expected.items():
        path = args.wheelhouse / filename
        if _sha256(path) != digest:
            raise SystemExit(f"SHA-256 mismatch: {filename}")

    site = args.target / f"usr/lib/python{PYTHON}/site-packages"
    site.mkdir(parents=True, exist_ok=True)
    for wheel in sorted(args.wheelhouse.glob("*.whl")):
        with ZipFile(wheel) as archive:
            archive.extractall(site)

    embit = args.wheelhouse / "embit-0.8.0.tar.gz"
    with tarfile.open(embit, "r:gz") as archive:
        members = [m for m in archive.getmembers() if m.name.startswith("embit-0.8.0/src/embit/")]
        archive.extractall(args.target / "tmp/embit-extract", members=members, filter="data")
    extracted = args.target / "tmp/embit-extract/embit-0.8.0/src/embit"
    _keep_target_embit_prebuilt(extracted)
    shutil.copytree(extracted, site / "embit", dirs_exist_ok=True)
    shutil.rmtree(args.target / "tmp/embit-extract")

    _install_verified_offline_package(args.source / "src/usb_cold_wallet", site / "usb_cold_wallet")

    bindir = args.target / "usr/bin"
    bindir.mkdir(parents=True, exist_ok=True)
    launcher = bindir / "usb-cold-wallet"
    launcher.write_text(
        "#!/usr/bin/python3\nfrom usb_cold_wallet.cli import main\nraise SystemExit(main())\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    console = bindir / "usb-wallet-console"
    console.write_text(
        "#!/usr/bin/python3\nfrom usb_cold_wallet.appliance import main\nraise SystemExit(main())\n",
        encoding="utf-8",
    )
    console.chmod(0o755)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
