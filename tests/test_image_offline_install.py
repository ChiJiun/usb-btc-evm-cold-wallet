"""Offline Buildroot installer must not silently copy connected Companion modules."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_offline_wheel import ALLOWED_OFFLINE_MODULES, ONLINE_MODULES
from install_target_python import _install_verified_offline_package


def test_project_source_installs_only_explicit_offline_modules(tmp_path):
    source = ROOT / "src/usb_cold_wallet"
    output = tmp_path / "offline"
    _install_verified_offline_package(source, output)
    assert {p.name for p in output.iterdir()} == ALLOWED_OFFLINE_MODULES
    assert "appliance.py" in ALLOWED_OFFLINE_MODULES
    assert not any((output / name).exists() for name in ONLINE_MODULES)


def test_offline_package_rejects_unreviewed_or_missing_modules(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for module in ALLOWED_OFFLINE_MODULES | ONLINE_MODULES:
        (source / module).write_text("# test fixture\n", encoding="utf-8")
    _install_verified_offline_package(source, tmp_path / "safe")
    (source / "accidental_rpc.py").write_text("# must fail\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="Unreviewed"):
        _install_verified_offline_package(source, tmp_path / "rejected")
    (source / "accidental_rpc.py").unlink()
    (source / "appliance.py").unlink()
    with pytest.raises(SystemExit, match="missing"):
        _install_verified_offline_package(source, tmp_path / "rejected2")


def test_offline_package_rejects_module_symlink(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for module in ALLOWED_OFFLINE_MODULES | ONLINE_MODULES:
        (source / module).write_text("# test fixture\n", encoding="utf-8")
    (source / "appliance.py").unlink()
    (source / "appliance.py").symlink_to(source / "cli.py")
    with pytest.raises(SystemExit, match="Untrusted"):
        _install_verified_offline_package(source, tmp_path / "target")
