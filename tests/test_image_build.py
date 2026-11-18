from __future__ import annotations

import importlib.util
import io
import json
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from tools.audit_live_iso import _check_boot_config, _read_expected_hash
from tools.build_live_iso import BOOT_TOKENS, _harden_boot_file, _tree_checksums, _xorriso_uuid
from tools.image_common import ImageBuildError, load_json, parse_sha256sums, validate_lock_manifest
from tools.install_python_artifacts import install_sdist, install_wheel

ROOT = Path(__file__).resolve().parents[1]


def _load_audit_module():
    path = ROOT / "image/runtime/offline_audit.py"
    spec = importlib.util.spec_from_file_location("offline_audit_test_module", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUDIT = _load_audit_module()


def test_real_artifact_lock_is_closed_and_hash_pinned():
    manifest = load_json(ROOT / "image/python-artifacts.lock.json")
    artifacts = validate_lock_manifest(manifest)
    assert len(artifacts) == 27
    assert {item["package"] for item in artifacts} >= {"embit", "eth-account", "cryptography"}
    assert all(len(item["sha256"]) == 64 for item in artifacts)


def test_parse_sha256sums_rejects_unsafe_or_duplicate_names():
    digest = "a" * 64
    assert parse_sha256sums(f"{digest}  image.iso\n") == {"image.iso": digest}
    with pytest.raises(ImageBuildError):
        parse_sha256sums(f"{digest}  ../image.iso\n")
    with pytest.raises(ImageBuildError):
        parse_sha256sums(f"{digest}  image.iso\n{digest}  image.iso\n")


def test_wheel_installer_rejects_path_traversal(tmp_path: Path):
    wheel = tmp_path / "bad.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("../escaped.py", "raise SystemExit")
    target = tmp_path / "site"
    target.mkdir()
    with pytest.raises(ImageBuildError, match="unsafe archive path"):
        install_wheel(wheel, target)
    assert not (tmp_path / "escaped.py").exists()


def test_wheel_installer_maps_purelib(tmp_path: Path):
    wheel = tmp_path / "demo.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo/__init__.py", "VALUE = 1\n")
        archive.writestr("demo-1.0.data/purelib/extra.py", "EXTRA = 2\n")
        archive.writestr("demo-1.0.data/scripts/not-installed", "ignored")
    target = tmp_path / "site"
    target.mkdir()
    install_wheel(wheel, target)
    assert (target / "demo/__init__.py").read_text() == "VALUE = 1\n"
    assert (target / "extra.py").read_text() == "EXTRA = 2\n"
    assert not (target / "not-installed").exists()


def test_sdist_installer_extracts_only_locked_source_subdir(tmp_path: Path):
    archive_path = tmp_path / "embit-0.8.0.tar.gz"
    payloads = {
        "embit-0.8.0/src/embit/__init__.py": b"VERSION='test'\n",
        "embit-0.8.0/setup.py": b"raise RuntimeError('must not execute')\n",
        "embit-0.8.0/LICENSE": b"MIT test license\n",
    }
    with tarfile.open(archive_path, "w:gz") as archive:
        for name, payload in payloads.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
    target = tmp_path / "site"
    target.mkdir()
    install_sdist(
        archive_path,
        {
            "package": "embit",
            "version": "0.8.0",
            "filename": archive_path.name,
            "source_subdir": "embit-0.8.0/src/embit",
            "license_files": ["embit-0.8.0/LICENSE"],
        },
        target,
    )
    assert (target / "embit/__init__.py").is_file()
    assert (target / "embit-0.8.0.dist-info/licenses/LICENSE").read_text() == "MIT test license\n"
    assert not (target / "setup.py").exists()


def test_boot_hardening_adds_required_tokens_once(tmp_path: Path):
    path = tmp_path / "grub.cfg"
    path.write_text(
        "linux /live/vmlinuz boot=live components quiet\n"
        "# linux /live/vmlinuz boot=live components custom\n",
        encoding="utf-8",
    )
    path.chmod(0o444)
    _harden_boot_file(path)
    first = path.read_text(encoding="utf-8")
    for token in BOOT_TOKENS:
        assert first.splitlines()[0].split().count(token) == 1
        assert token not in first.splitlines()[1]
    _harden_boot_file(path)
    second = path.read_text(encoding="utf-8")
    assert second == first


def test_iso_checksum_files_are_sorted_and_exclude_self(tmp_path: Path):
    (tmp_path / "z.txt").write_text("z", encoding="utf-8")
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "md5sum.txt").write_text("old", encoding="utf-8")
    (tmp_path / "sha256sum.txt").write_text("old", encoding="utf-8")
    _tree_checksums(tmp_path)
    sha = (tmp_path / "sha256sum.txt").read_text(encoding="utf-8").splitlines()
    assert [line.split("  ", 1)[1] for line in sha] == ["./a.txt", "./z.txt"]
    assert _xorriso_uuid(1789230034) == "2026091216203400"


def test_post_build_boot_config_audit():
    good = "linux /live/vmlinuz boot=live components " + " ".join(BOOT_TOKENS) + "\n"
    assert _check_boot_config("grub", good)["ok"] is True
    assert _check_boot_config("grub", "linux /live/vmlinuz boot=live persistence\n")["ok"] is False


def test_sha256_sidecar_parser(tmp_path: Path):
    iso = tmp_path / "wallet.iso"
    iso.write_bytes(b"image")
    digest = "a" * 64
    sidecar = tmp_path / "wallet.iso.sha256"
    sidecar.write_text(f"{digest}  wallet.iso\n", encoding="ascii")
    assert _read_expected_hash(sidecar, iso) == digest
    sidecar.write_text(f"{digest}  other.iso\n", encoding="ascii")
    with pytest.raises(ImageBuildError):
        _read_expected_hash(sidecar, iso)


def test_boot_cmdline_policy_pass_and_fail():
    policy = load_json(ROOT / "image/runtime-policy.json")
    good = AUDIT.check_boot_cmdline("boot=live components nopersistence ipv6.disable=1", policy)
    assert good["ok"] is True
    bad = AUDIT.check_boot_cmdline("boot=live components persistence swap=true", policy)
    assert bad["ok"] is False
    assert "persistence" in bad["detail"]


def test_swap_audit():
    assert AUDIT.check_swaps("Filename\tType\tSize\tUsed\tPriority\n")["ok"] is True
    assert (
        AUDIT.check_swaps(
            "Filename\tType\tSize\tUsed\tPriority\n/dev/zram0 partition 1024 0 100\n"
        )["ok"]
        is False
    )


def test_core_dump_limit_audit(monkeypatch):
    monkeypatch.setattr(AUDIT.resource, "getrlimit", lambda _resource: (0, 0))
    assert AUDIT.check_core_limit()["ok"] is True
    monkeypatch.setattr(AUDIT.resource, "getrlimit", lambda _resource: (0, 1024))
    assert AUDIT.check_core_limit()["ok"] is False


def _make_static_root(root: Path, policy: dict) -> None:
    unit_dir = root / "etc/systemd/system"
    unit_dir.mkdir(parents=True)
    for unit in policy["masked_units"]:
        (unit_dir / unit).symlink_to("/dev/null")

    (root / "etc/network").mkdir(parents=True)
    (root / "etc/network/interfaces").write_text(
        "# offline\nauto lo\niface lo inet loopback\n", encoding="utf-8"
    )
    (root / "etc/resolv.conf").write_text("# no DNS\n", encoding="utf-8")

    files = [
        root / "usr/local/bin/usb-cold-wallet",
        root / "usr/local/sbin/usb-cold-wallet-airgap",
        root / "usr/local/sbin/usb-cold-wallet-offline-audit",
        root / "opt/usb-cold-wallet/runtime-policy.json",
        root / "opt/usb-cold-wallet/site-packages/USB_COLD_WALLET_ARTIFACTS.json",
    ]
    for path in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n" if path.suffix == ".json" else "test\n", encoding="utf-8")


def test_static_root_audit(tmp_path: Path):
    policy = load_json(ROOT / "image/runtime-policy.json")
    _make_static_root(tmp_path, policy)
    checks = AUDIT.check_static_files(tmp_path, policy)
    assert AUDIT.summarize(checks)["ok"] is True

    (tmp_path / "etc/resolv.conf").write_text("nameserver 8.8.8.8\n", encoding="utf-8")
    checks = AUDIT.check_static_files(tmp_path, policy)
    assert AUDIT.summarize(checks)["ok"] is False


def test_interface_flag_audit(tmp_path: Path):
    lo = tmp_path / "lo"
    eth = tmp_path / "eth0"
    lo.mkdir()
    eth.mkdir()
    (lo / "flags").write_text("0x49\n", encoding="ascii")
    (eth / "flags").write_text("0x1002\n", encoding="ascii")
    assert AUDIT.check_interface_flags(tmp_path)["ok"] is True
    (eth / "flags").write_text("0x1003\n", encoding="ascii")
    assert AUDIT.check_interface_flags(tmp_path)["ok"] is False
