"""Offline wheel build gate: connected network code must never ship to the signer."""
from pathlib import Path
import zipfile

import pytest

from scripts.build_offline_wheel import (
    ALLOWED_OFFLINE_MODULES, ONLINE_MODULES, _record,
    build_offline_wheel, verify_offline_wheel,
)


def _mock_combined_wheel(path: Path, *, extra_module=None):
    prefix = "usb_cold_wallet/"
    dist = "usb_btc_evm_cold_wallet-0.1.0.dist-info/"
    entries = {
        prefix + module: b"# public test stub\n" for module in
        ALLOWED_OFFLINE_MODULES | ONLINE_MODULES
    }
    entries[prefix + "companion_static/index.html"] = b"<p>online</p>"
    if extra_module:
        entries[prefix + extra_module] = b"import socket\n"
    entries[dist + "WHEEL"] = b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    entries[dist + "METADATA"] = b"Metadata-Version: 2.3\nName: usb-btc-evm-cold-wallet\nVersion: 0.1.0\n"
    entries[dist + "entry_points.txt"] = (
        b"[console_scripts]\n"
        b"usb-cold-wallet = usb_cold_wallet.cli:main\n"
        b"usb-cold-companion = usb_cold_wallet.companion_web:main\n"
    )
    record_path = dist + "RECORD"
    entries[record_path] = _record(entries, record_path)
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


def test_offline_wheel_drops_online_modules_and_command(tmp_path):
    source = tmp_path / "combined" / "usb_btc_evm_cold_wallet-0.1.0-py3-none-any.whl"
    source.parent.mkdir()
    _mock_combined_wheel(source)
    target = build_offline_wheel(source, tmp_path / "offline")
    verify_offline_wheel(target)
    with zipfile.ZipFile(target) as archive:
        names = set(archive.namelist())
        assert all("companion" not in name for name in names)
        assert all("usb_cold_wallet/" + module in names for module in ALLOWED_OFFLINE_MODULES)
        entries = archive.read("usb_btc_evm_cold_wallet-0.1.0.dist-info/entry_points.txt")
        assert b"usb-cold-wallet =" in entries
        assert b"usb-cold-companion =" not in entries
    with zipfile.ZipFile(source) as archive:
        assert "usb_cold_wallet/companion_web.py" in archive.namelist()


@pytest.mark.parametrize("module,error", [
    ("surprise_rpc.py", "Unexpected offline wallet Python modules"),
    ("network/client.py", "Unreviewed code or assets"),
])
def test_offline_build_fails_closed_on_unreviewed_module(tmp_path, module, error):
    source = tmp_path / "combined.whl"
    _mock_combined_wheel(source, extra_module=module)
    with pytest.raises(ValueError, match=error):
        build_offline_wheel(source, tmp_path / "offline")


def test_offline_build_does_not_overwrite_combined_wheel(tmp_path):
    source = tmp_path / "combined.whl"
    _mock_combined_wheel(source)
    with pytest.raises(ValueError, match="overwrite"):
        build_offline_wheel(source, tmp_path)


def test_offline_wheel_detects_tampered_record(tmp_path):
    source = tmp_path / "combined.whl"
    _mock_combined_wheel(source)
    target = build_offline_wheel(source, tmp_path / "offline")
    modified = tmp_path / "modified.whl"
    with zipfile.ZipFile(target) as archive, zipfile.ZipFile(modified, "w") as output:
        for name in archive.namelist():
            content = archive.read(name)
            if name.endswith("README.md"):
                content += b"tamper"
            if name.endswith(".dist-info/METADATA"):
                content += b"Tamper: yes\n"
            output.writestr(name, content)
    with pytest.raises(ValueError, match="RECORD"):
        verify_offline_wheel(modified)
