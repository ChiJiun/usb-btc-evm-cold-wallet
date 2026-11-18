"""Fail-closed checks for removable transaction transport."""
from pathlib import Path
from types import SimpleNamespace

from usb_cold_wallet import appliance


def _identity(monkeypatch, device="/dev/sdb1"):
    monkeypatch.setattr(appliance, "_unique_transfer_device", lambda: device)
    return device


def test_transfer_mount_rejects_ambiguous_or_missing_label(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    monkeypatch.setattr(appliance, "_unique_transfer_device", lambda: None)
    assert appliance.mount_transfer() is False


def test_transfer_mount_rejects_wrong_existing_source(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    _identity(monkeypatch, "/dev/sdb1")
    monkeypatch.setattr(
        appliance,
        "_mount_info",
        lambda path: ("/dev/sdc1", "vfat", {"rw", "nodev", "noexec", "nosuid", "sync"}),
    )
    assert appliance.mount_transfer() is False


def test_transfer_mount_rejects_unsafe_existing_mount(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    device = _identity(monkeypatch)
    monkeypatch.setattr(appliance, "_mount_info", lambda path: (device, "vfat", {"rw", "nodev"}))
    assert appliance.mount_transfer() is False


def test_transfer_mount_rejects_nonfat_existing_mount(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    device = _identity(monkeypatch)
    monkeypatch.setattr(
        appliance,
        "_mount_info",
        lambda path: (device, "ext4", {"rw", "nodev", "noexec", "nosuid", "sync"}),
    )
    assert appliance.mount_transfer() is False


def test_transfer_mount_accepts_expected_source_and_flags(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    device = _identity(monkeypatch)
    monkeypatch.setattr(
        appliance,
        "_mount_info",
        lambda path: (device, "vfat", {"rw", "nodev", "noexec", "nosuid", "sync"}),
    )
    assert appliance.mount_transfer() is True


def test_transfer_mount_checks_new_mount_source_and_flags(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    device = _identity(monkeypatch)
    calls = iter(
        [
            None,
            (device, "vfat", {"rw", "nodev", "noexec", "nosuid", "sync"}),
        ]
    )
    monkeypatch.setattr(appliance, "_mount_info", lambda path: next(calls))
    mounted = {}

    def run(args, **kwargs):
        mounted["args"] = args
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(appliance.subprocess, "run", run)
    assert appliance.mount_transfer() is True
    assert mounted["args"][5] == device


def test_unique_transfer_device_rejects_duplicate_label(monkeypatch):
    monkeypatch.setattr(
        appliance,
        "_blkid",
        lambda *args: ["/dev/sdb1", "/dev/sdc1"] if "LABEL=TX_TRANSFER" in args else [],
    )
    assert appliance._unique_transfer_device() is None


def test_unique_transfer_device_rejects_boot_parent(monkeypatch, tmp_path):
    boot_parent = tmp_path / "boot-parent"
    vault_device = tmp_path / "vault-device"
    boot_parent.write_text("sda\n", encoding="utf-8")
    vault_device.write_text("/dev/sda2\n", encoding="utf-8")
    monkeypatch.setattr(appliance, "BOOT_PARENT_FILE", boot_parent)
    monkeypatch.setattr(appliance, "VAULT_DEVICE_FILE", vault_device)

    def blkid(*args):
        if "LABEL=TX_TRANSFER" in args:
            return ["/dev/sda3"]
        if "TYPE" in args:
            return ["vfat"]
        return []

    monkeypatch.setattr(appliance, "_blkid", blkid)
    monkeypatch.setattr(appliance, "_block_parent", lambda device: "sda")
    assert appliance._unique_transfer_device() is None


def test_unique_transfer_device_accepts_separate_vfat_usb(monkeypatch, tmp_path):
    boot_parent = tmp_path / "boot-parent"
    vault_device = tmp_path / "vault-device"
    boot_parent.write_text("sda\n", encoding="utf-8")
    vault_device.write_text("/dev/sda2\n", encoding="utf-8")
    monkeypatch.setattr(appliance, "BOOT_PARENT_FILE", boot_parent)
    monkeypatch.setattr(appliance, "VAULT_DEVICE_FILE", vault_device)

    def blkid(*args):
        if "LABEL=TX_TRANSFER" in args:
            return ["/dev/sdb1"]
        if "TYPE" in args:
            return ["vfat"]
        return []

    monkeypatch.setattr(appliance, "_blkid", blkid)
    monkeypatch.setattr(appliance, "_block_parent", lambda device: "sdb")
    assert appliance._unique_transfer_device() == "/dev/sdb1"


def test_file_selector_rejects_zero_and_negative_indices(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    (tmp_path / "a.psbt").write_text("test")
    monkeypatch.setattr(appliance, "mount_transfer", lambda: True)
    for index in ("0", "-1", "2"):
        monkeypatch.setattr("builtins.input", lambda prompt, value=index: value)
        assert appliance._select_file(".psbt") is None
    assert capsys.readouterr().out.count("Invalid selection.") == 3


def test_request_envelope_mode_switches_appliance_source_flags(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    request = tmp_path / "request.json"
    request.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(appliance, "mount_transfer", lambda: True)
    monkeypatch.setattr(appliance, "_supports_request_envelopes", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "1" if "Select" in prompt else "1")
    seen = []
    monkeypatch.setattr(appliance, "_run_cli", lambda args: seen.append(args))

    # EVM and BTC both select a JSON request envelope once #5 exchange support
    # is present. Independent policy prompts are intentionally still required.
    prompts = iter(["1", "0x000000000000000000000000000000000000dEaD", "1"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(prompts))
    appliance._sign_evm()
    assert "--request" in seen[-1]

    prompts = iter(["1", "tb1qtest", "1000", "100", ""])
    monkeypatch.setattr("builtins.input", lambda prompt: next(prompts))
    appliance._sign_btc()
    assert "--request" in seen[-1]
