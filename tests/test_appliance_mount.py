"""Fail-closed checks for removable transaction transport."""
from types import SimpleNamespace

from usb_cold_wallet import appliance


def test_transfer_mount_rejects_unsafe_existing_mount(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    monkeypatch.setattr(appliance, "_mount_info", lambda path: ("vfat", {"rw", "nodev"}))
    assert appliance.mount_transfer() is False


def test_transfer_mount_rejects_nonfat_existing_mount(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    monkeypatch.setattr(appliance, "_mount_info", lambda path: ("ext4", {"rw", "nodev", "noexec", "nosuid", "sync"}))
    assert appliance.mount_transfer() is False


def test_transfer_mount_accepts_expected_flags(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    monkeypatch.setattr(appliance, "_mount_info", lambda path: ("vfat", {"rw", "nodev", "noexec", "nosuid", "sync"}))
    assert appliance.mount_transfer() is True


def test_transfer_mount_checks_new_mount_flags(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    monkeypatch.setattr(appliance, "_mount_info", lambda path: None)
    monkeypatch.setattr(appliance.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0))
    assert appliance.mount_transfer() is False


def test_file_selector_rejects_zero_and_negative_indices(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    (tmp_path / "a.psbt").write_text("test")
    monkeypatch.setattr(appliance, "mount_transfer", lambda: True)
    for index in ("0", "-1", "2"):
        monkeypatch.setattr("builtins.input", lambda prompt, value=index: value)
        assert appliance._select_file(".psbt") is None
    assert capsys.readouterr().out.count("Invalid selection.") == 3
