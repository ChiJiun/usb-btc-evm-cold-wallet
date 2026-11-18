from __future__ import annotations

import argparse
import json
import os
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from tools.fetch_python_artifacts import verify_artifacts
from tools.image_common import ImageBuildError, load_json, validate_lock_manifest


def _safe_relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ImageBuildError(f"unsafe archive path: {name!r}")
    return path


def _write_bytes(destination: Path, data: bytes, mode: int = 0o644) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as stream:
        stream.write(data)
    destination.chmod(mode & 0o777 or 0o644)


def _wheel_destination(path: PurePosixPath) -> PurePosixPath | None:
    parts = path.parts
    if len(parts) >= 3 and parts[0].endswith(".data"):
        category = parts[1]
        if category in {"purelib", "platlib"}:
            return PurePosixPath(*parts[2:])
        if category in {"scripts", "headers", "data"}:
            return None
        raise ImageBuildError(f"unsupported wheel .data category: {category}")
    return path


def install_wheel(wheel: Path, site_packages: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            source = _safe_relative(info.filename)
            destination_rel = _wheel_destination(source)
            if destination_rel is None:
                continue
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise ImageBuildError(f"wheel contains symlink: {info.filename}")
            destination = site_packages.joinpath(*destination_rel.parts)
            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            _write_bytes(destination, archive.read(info), mode or 0o644)


def install_sdist(archive_path: Path, artifact: dict, site_packages: Path) -> None:
    prefix_value = artifact.get("source_subdir")
    if not isinstance(prefix_value, str) or not prefix_value:
        raise ImageBuildError(f"sdist {archive_path.name} lacks source_subdir")
    prefix = _safe_relative(prefix_value)
    copied = 0
    license_files = artifact.get("license_files", [])
    if not isinstance(license_files, list) or any(not isinstance(item, str) for item in license_files):
        raise ImageBuildError(f"invalid license_files for {archive_path.name}")
    requested_licenses = {_safe_relative(item): item for item in license_files}
    found_licenses: set[PurePosixPath] = set()

    with tarfile.open(archive_path, mode="r:*") as archive:
        for member in archive.getmembers():
            source = _safe_relative(member.name)
            if source in requested_licenses:
                if not member.isfile():
                    raise ImageBuildError(f"license is not a regular file: {member.name}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ImageBuildError(f"cannot read license entry: {member.name}")
                license_name = Path(member.name).name
                license_dir = site_packages / f"{artifact['package']}-{artifact.get('version', 'unknown')}.dist-info/licenses"
                _write_bytes(license_dir / license_name, extracted.read(), member.mode or 0o644)
                found_licenses.add(source)

            if source.parts[: len(prefix.parts)] != prefix.parts:
                continue
            relative_parts = source.parts[len(prefix.parts) :]
            if not relative_parts:
                continue
            if member.issym() or member.islnk() or member.isdev():
                raise ImageBuildError(f"sdist contains unsafe special file: {member.name}")
            destination = site_packages.joinpath(prefix.name, *relative_parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ImageBuildError(f"unsupported sdist entry: {member.name}")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ImageBuildError(f"cannot read sdist entry: {member.name}")
            _write_bytes(destination, extracted.read(), member.mode or 0o644)
            copied += 1
    if copied == 0:
        raise ImageBuildError(f"source_subdir {prefix_value} not found in {archive_path.name}")
    missing_licenses = set(requested_licenses) - found_licenses
    if missing_licenses:
        raise ImageBuildError(
            "missing required sdist license file(s): "
            + ", ".join(str(item) for item in sorted(missing_licenses, key=str))
        )


def install_artifacts(lock_path: Path, artifact_dir: Path, site_packages: Path) -> dict:
    manifest = load_json(lock_path)
    artifacts = validate_lock_manifest(manifest)
    verify_artifacts(lock_path, artifact_dir)
    site_packages.mkdir(parents=True, exist_ok=True)
    if any(site_packages.iterdir()):
        raise ImageBuildError(f"refusing to install into non-empty directory: {site_packages}")

    for artifact in artifacts:
        source = artifact_dir / artifact["filename"]
        if artifact["kind"] == "wheel":
            install_wheel(source, site_packages)
        else:
            install_sdist(source, artifact, site_packages)

    install_manifest = {
        "schema": 1,
        "target": manifest.get("target", {}),
        "roots": manifest.get("roots", []),
        "artifacts": [
            {
                "package": item["package"],
                "version": item["version"],
                "filename": item["filename"],
                "sha256": item["sha256"],
            }
            for item in artifacts
        ],
    }
    (site_packages / "USB_COLD_WALLET_ARTIFACTS.json").write_text(
        json.dumps(install_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return install_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Install locked wheel/sdist contents without executing package code")
    parser.add_argument("--lock", type=Path, default=Path("image/python-artifacts.lock.json"))
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--site-packages", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = install_artifacts(args.lock, args.artifact_dir, args.site_packages)
    except ImageBuildError as exc:
        parser.error(str(exc))
    print(json.dumps({"status": "installed", "artifacts": len(result["artifacts"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
