"""Fail-closed checks for removable transaction transport and appliance routing."""
from types import SimpleNamespace

from usb_cold_wallet import appliance


SAFE = {"rw", "nodev", "noexec", "nosuid", "sync"}


def _identity(monkeypatch, device="/dev/sdb1"):
    monkeypatch.setattr(appliance, "_unique_transfer_device", lambda: device)
    return device


def _identity_files(monkeypatch, tmp_path, boot_parent="sda", vault_device="/dev/sda2"):
    boot_file = tmp_path / "boot-parent"
    vault_file = tmp_path / "vault-device"
    boot_file.write_text(boot_parent + "\n", encoding="utf-8")
    vault_file.write_text(vault_device + "\n", encoding="utf-8")
    monkeypatch.setattr(appliance, "BOOT_PARENT_FILE", boot_file)
    monkeypatch.setattr(appliance, "VAULT_DEVICE_FILE", vault_file)


def test_transfer_mount_rejects_ambiguous_or_missing_label(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    monkeypatch.setattr(appliance, "_unique_transfer_device", lambda: None)
    assert appliance.mount_transfer() is False


def test_unique_transfer_device_rejects_duplicate_label(monkeypatch):
    monkeypatch.setattr(
        appliance,
        "_blkid",
        lambda *args: ["/dev/sdb1", "/dev/sdc1"] if "LABEL=TX_TRANSFER" in args else [],
    )
    assert appliance._unique_transfer_device() is None


def test_unique_transfer_device_rejects_boot_parent(monkeypatch, tmp_path):
    _identity_files(monkeypatch, tmp_path)

    def blkid(*args):
        if "LABEL=TX_TRANSFER" in args:
            return ["/dev/sda3"]
        if "TYPE" in args:
            return ["vfat"]
        return []

    monkeypatch.setattr(appliance, "_blkid", blkid)
    monkeypatch.setattr(appliance, "_block_parent", lambda device: "sda")
    assert appliance._unique_transfer_device() is None


def test_unique_transfer_device_rejects_non_vfat(monkeypatch, tmp_path):
    _identity_files(monkeypatch, tmp_path)

    def blkid(*args):
        if "LABEL=TX_TRANSFER" in args:
            return ["/dev/sdb1"]
        if "TYPE" in args:
            return ["ext4"]
        return []

    monkeypatch.setattr(appliance, "_blkid", blkid)
    assert appliance._unique_transfer_device() is None


def test_unique_transfer_device_accepts_separate_vfat_usb(monkeypatch, tmp_path):
    _identity_files(monkeypatch, tmp_path)

    def blkid(*args):
        if "LABEL=TX_TRANSFER" in args:
            return ["/dev/sdb1"]
        if "TYPE" in args:
            return ["vfat"]
        return []

    monkeypatch.setattr(appliance, "_blkid", blkid)
    monkeypatch.setattr(appliance, "_block_parent", lambda device: "sdb")
    assert appliance._unique_transfer_device() == "/dev/sdb1"


def test_transfer_mount_rejects_wrong_existing_source(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    _identity(monkeypatch, "/dev/sdb1")
    monkeypatch.setattr(
        appliance,
        "_mount_info",
        lambda path: ("/dev/sdc1", "vfat", SAFE),
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
    monkeypatch.setattr(appliance, "_mount_info", lambda path: (device, "ext4", SAFE))
    assert appliance.mount_transfer() is False


def test_transfer_mount_accepts_expected_source_and_flags(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    device = _identity(monkeypatch)
    monkeypatch.setattr(appliance, "_mount_info", lambda path: (device, "vfat", SAFE))
    assert appliance.mount_transfer() is True


def test_transfer_mount_checks_new_mount_source_and_flags(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    device = _identity(monkeypatch)
    states = iter([None, (device, "vfat", SAFE)])
    monkeypatch.setattr(appliance, "_mount_info", lambda path: next(states))
    calls = []
    monkeypatch.setattr(
        appliance.subprocess,
        "run",
        lambda args, **kwargs: calls.append(args) or SimpleNamespace(returncode=0),
    )
    assert appliance.mount_transfer() is True
    assert calls[0][5] == device
    assert calls[0][-1] == str(tmp_path)
    assert "-L" not in calls[0]


def test_file_selector_rejects_zero_and_negative_indices(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    (tmp_path / "a.psbt").write_text("test")
    monkeypatch.setattr(appliance, "mount_transfer", lambda: True)
    for index in ("0", "-1", "2"):
        monkeypatch.setattr("builtins.input", lambda prompt, value=index: value)
        assert appliance._select_file(".psbt") is None
    assert capsys.readouterr().out.count("Invalid selection.") == 3


def test_evm_json_always_routes_to_request_without_pre_read(monkeypatch, tmp_path):
    request = tmp_path / "evm-request.json"
    request.write_text("untrusted bytes are not inspected by appliance", encoding="utf-8")
    monkeypatch.setattr(appliance, "_select_file", lambda suffix: request)
    answers = iter(["0x000000000000000000000000000000000000dEaD", "1000"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    calls = []
    monkeypatch.setattr(appliance, "_run_cli", lambda args: calls.append(args))
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)

    appliance._sign_evm()

    assert calls
    assert calls[0][0:2] == ["sign-evm", "--request"]
    assert str(request) in calls[0]


def test_btc_json_routes_to_request_without_pre_read(monkeypatch, tmp_path):
    request = tmp_path / "btc-request.json"
    request.write_text("untrusted bytes are not inspected by appliance", encoding="utf-8")
    monkeypatch.setattr(appliance, "_select_file", lambda suffix: request)
    answers = iter(["tb1qexample", "50000", "2000", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    calls = []
    monkeypatch.setattr(appliance, "_run_cli", lambda args: calls.append(args))
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)

    appliance._sign_btc()

    assert calls
    assert calls[0][0:2] == ["sign-btc", "--request"]
    assert str(request) in calls[0]
