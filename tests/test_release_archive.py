"""Hostile GitHub Actions artifact archive tests (no network or secrets)."""
import hashlib
import stat
import zipfile

import pytest

from scripts.extract_release_candidate import extract_candidate_archive
from scripts.verify_release_assets import ReleaseVerificationError

IMAGE = "usb-cold-wallet-v0.1.0-beta.1.img.xz"
FILES = {
    "SHA256SUMS": b"manifest",
    "release-metadata.json": b"metadata",
    "SBOM.spdx.json": b"sbom",
    "build-host-packages.txt": b"packages",
    IMAGE: b"compressed-image",
}


def archive(tmp_path, files=None):
    folder = tmp_path / "archive"
    folder.mkdir()
    path = folder / "artifact.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as out:
        for name, content in (files if files is not None else FILES.items()):
            out.writestr(name, content)
    return folder, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def test_valid_archive(tmp_path):
    source, digest = archive(tmp_path)
    dest = tmp_path / "release"
    extract_candidate_archive(source, dest, digest)
    assert {p.name for p in dest.iterdir()} == set(FILES)
    assert all((dest / name).read_bytes() == content for name, content in FILES.items())


@pytest.mark.parametrize("name", [
    "../outside.txt", "/tmp/outside.txt", "nested/payload", "nested\\payload", "unexpected",
])
def test_path_traversal_extra_member_fails_before_extraction(tmp_path, name):
    source, digest = archive(tmp_path, list(FILES.items()) + [(name, b"attack")])
    with pytest.raises(ReleaseVerificationError, match="Unsafe, missing"):
        extract_candidate_archive(source, tmp_path / "release", digest)
    assert not (tmp_path / "release").exists()
    assert not (tmp_path / "outside.txt").exists()


def test_duplicate_member_fails(tmp_path):
    with pytest.warns(UserWarning, match="Duplicate name"):
        source, digest = archive(tmp_path, list(FILES.items()) + [(IMAGE, b"other")])
    with pytest.raises(ReleaseVerificationError, match="duplicate"):
        extract_candidate_archive(source, tmp_path / "release", digest)


def test_symlink_member_fails(tmp_path):
    folder = tmp_path / "archive"
    folder.mkdir()
    path = folder / "artifact.zip"
    with zipfile.ZipFile(path, "w") as out:
        for name, data in FILES.items():
            info = zipfile.ZipInfo(name)
            if name == IMAGE:
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                data = b"../target"
            out.writestr(info, data)
    digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ReleaseVerificationError, match="member type"):
        extract_candidate_archive(folder, tmp_path / "release", digest)
    assert not (tmp_path / "release").exists()


def test_modified_archive_digest_fails(tmp_path):
    source, digest = archive(tmp_path)
    path = source / "artifact.zip"
    path.write_bytes(path.read_bytes() + b"modified")
    with pytest.raises(ReleaseVerificationError, match="digest mismatch"):
        extract_candidate_archive(source, tmp_path / "release", digest)


def test_missing_asset_or_oversized_metadata_fails(tmp_path):
    source, digest = archive(tmp_path, {**FILES, "release-metadata.json": b"x" * (128 * 1024 + 1)}.items())
    with pytest.raises(ReleaseVerificationError, match="member type or size"):
        extract_candidate_archive(source, tmp_path / "release", digest)

    folder = tmp_path / "second"
    folder.mkdir()
    path = folder / "artifact.zip"
    with zipfile.ZipFile(path, "w") as out:
        for name, data in FILES.items():
            if name != IMAGE:
                out.writestr(name, data)
    digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ReleaseVerificationError, match="Unsafe, missing"):
        extract_candidate_archive(folder, tmp_path / "release", digest)


def test_multiple_archives_fail(tmp_path):
    folder = tmp_path / "archive"
    folder.mkdir()
    (folder / "one.zip").write_bytes(b"1")
    (folder / "two.zip").write_bytes(b"2")
    with pytest.raises(ReleaseVerificationError, match="exactly one"):
        extract_candidate_archive(folder, tmp_path / "release", "sha256:" + "f" * 64)
