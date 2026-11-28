"""Fail-closed checks for removable transaction transport and appliance routing."""
import pytest

from usb_cold_wallet import appliance
from usb_cold_wallet.vault import save_vault


SAFE = {"rw", "nodev", "noexec", "nosuid", "sync", "fmask=0177", "dmask=0077"}


def _identity(monkeypatch, device="/dev/sdb1"):
    monkeypatch.setattr(appliance, "_bounded_transfer_device", lambda: device)
    return device


def _identity_files(
    monkeypatch,
    tmp_path,
    boot_parent="sda",
    vault_device="/dev/sda2",
    transfer_device=None,
):
    boot_file = tmp_path / "boot-parent"
    vault_file = tmp_path / "vault-device"
    transfer_file = tmp_path / "transfer-device"
    boot_file.write_text(boot_parent + "\n", encoding="utf-8")
    vault_file.write_text(vault_device + "\n", encoding="utf-8")
    if transfer_device is not None:
        transfer_file.write_text(transfer_device + "\n", encoding="ascii")
    monkeypatch.setattr(appliance, "BOOT_PARENT_FILE", boot_file)
    monkeypatch.setattr(appliance, "VAULT_DEVICE_FILE", vault_file)
    monkeypatch.setattr(appliance, "TRANSFER_DEVICE_FILE", transfer_file)


def test_transfer_mount_refuses_lockdown_before_scanning_or_mounting(monkeypatch, tmp_path):
    lockdown = tmp_path / "lockdown"
    lockdown.touch()
    monkeypatch.setattr(appliance, "LOCKDOWN", lockdown)
    monkeypatch.setattr(
        appliance, "_bounded_transfer_device",
        lambda: (_ for _ in ()).throw(AssertionError("No device discovery during lockdown")),
    )
    assert appliance.mount_transfer() is False


def test_transfer_mount_rejects_ambiguous_or_missing_label(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    monkeypatch.setattr(appliance, "_bounded_transfer_device", lambda: None)
    assert appliance.mount_transfer() is False


def test_unique_transfer_device_rejects_duplicate_label(monkeypatch):
    monkeypatch.setattr(appliance, "_transfer_candidates", lambda: ["/dev/sdb1", "/dev/sdc1"])
    assert appliance._unique_transfer_device() is None


def test_unique_transfer_device_same_parent_requires_exact_boot_verified_partition(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "_transfer_candidates", lambda: ["/dev/sda3"])
    monkeypatch.setattr(appliance, "_block_parent", lambda _device: "sda")

    _identity_files(monkeypatch, tmp_path)
    assert appliance._unique_transfer_device() is None

    _identity_files(monkeypatch, tmp_path, transfer_device="/dev/sda3")
    assert appliance._unique_transfer_device() == "/dev/sda3"

    _identity_files(monkeypatch, tmp_path, transfer_device="/dev/sda4")
    assert appliance._unique_transfer_device() is None


def test_unique_transfer_device_rejects_non_vfat(monkeypatch, tmp_path):
    _identity_files(monkeypatch, tmp_path)
    monkeypatch.setattr(appliance, "_transfer_candidates", lambda: [])
    assert appliance._unique_transfer_device() is None


def test_unique_transfer_device_accepts_separate_vfat_usb(monkeypatch, tmp_path):
    _identity_files(monkeypatch, tmp_path)
    monkeypatch.setattr(appliance, "_transfer_candidates", lambda: ["/dev/sdb1"])
    monkeypatch.setattr(appliance, "_block_parent", lambda _device: "sdb")
    assert appliance._unique_transfer_device() == "/dev/sdb1"


def test_fat_label_detection_checks_signature_and_exact_name(tmp_path):
    volume = tmp_path / "usb-fake-fat"
    sector = bytearray(512)
    sector[11:13] = b"\x00\x02"
    sector[71:82] = b"TX_TRANSFER"
    sector[82:90] = b"FAT32   "
    sector[510:512] = b"\x55\xaa"
    volume.write_bytes(sector)
    assert appliance._fat_label(volume) == "TX_TRANSFER"
    sector[510:512] = b"\x00\x00"
    volume.write_bytes(sector)
    assert appliance._fat_label(volume) is None
    sector[510:512] = b"\x55\xaa"
    sector[71:82] = b"NEVER_TRUST"
    volume.write_bytes(sector)
    assert appliance._fat_label(volume) == "NEVER_TRUST"


def test_sysfs_transfer_search_requires_usb_ancestry_and_sd_partition(monkeypatch, tmp_path):
    sys_block = tmp_path / "sys"
    dev_root = tmp_path / "dev"
    sys_block.mkdir()
    dev_root.mkdir()
    for name, usb in (
        ("sda1", True), ("sdb1", True), ("sdc1", False), ("nvme0n1p1", True),
    ):
        ancestry = (
            "usb1/1-1/1-1:1.0" if usb else "ata1/host0"
        )
        entry = tmp_path / "devices" / ancestry / "block" / name
        entry.mkdir(parents=True)
        (sys_block / name).symlink_to(entry, target_is_directory=True)
        (entry / "partition").write_text("1\n", encoding="ascii")
        sector = bytearray(512)
        sector[11:13] = b"\x00\x02"
        sector[71:82] = b"TX_TRANSFER"
        sector[82:90] = b"FAT32   "
        sector[510:512] = b"\x55\xaa"
        (dev_root / name).write_bytes(sector)
    monkeypatch.setattr(appliance, "SYS_BLOCK", sys_block)
    monkeypatch.setattr(appliance, "DEV_ROOT", dev_root)
    assert sorted(appliance._transfer_candidates()) == [
        str(dev_root / "sda1"), str(dev_root / "sdb1")
    ]
    assert appliance._usb_mass_storage(sys_block / "sda1") is True
    assert appliance._usb_mass_storage(sys_block / "sdc1") is False



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


def test_transfer_mount_rejects_insecure_fat_access_masks(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    device = _identity(monkeypatch)
    for missing in ("fmask=0177", "dmask=0077"):
        monkeypatch.setattr(appliance, "_mount_info", lambda _path, missing=missing: (device, "vfat", SAFE - {missing}))
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
        appliance, "_run_media_command", lambda args: calls.append(args) or True,
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
    answers = iter(["0x000000000000000000000000000000000000dEaD", "1000", "a" * 64])
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
    answers = iter(["tb1qexample", "50000", "2000", "0", "b" * 64])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    calls = []
    monkeypatch.setattr(appliance, "_run_cli", lambda args: calls.append(args))
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)

    appliance._sign_btc()

    assert calls
    assert calls[0][0:2] == ["sign-btc", "--request"]
    assert str(request) in calls[0]


def test_signed_request_requires_independent_policy_digest(monkeypatch, tmp_path):
    request = tmp_path / "evil.json"
    request.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(appliance, "_select_file", lambda _suffix: request)
    answers = iter(["0x000000000000000000000000000000000000dEaD", "1000", "bad"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    monkeypatch.setattr(appliance, "_run_cli",
                        lambda _args: (_ for _ in ()).throw(AssertionError("must not sign")))
    appliance._sign_evm()


def test_export_watch_only_requires_wallet_and_verified_transfer(monkeypatch, tmp_path):
    wallet = tmp_path / "wallet.vault"
    transfer = tmp_path / "transfer"
    transfer.mkdir()
    monkeypatch.setattr(appliance, "VAULT", wallet)
    monkeypatch.setattr(appliance, "TRANSFER", transfer)
    called = []
    monkeypatch.setattr(appliance, "_run_cli", lambda args: called.append(args))
    monkeypatch.setattr(appliance, "mount_transfer",
                        lambda: (_ for _ in ()).throw(AssertionError("no wallet: no mount")))
    appliance._export_watch_only()
    assert not called

    wallet.write_text("encrypted test fixture")
    monkeypatch.setattr(appliance, "mount_transfer", lambda: False)
    appliance._export_watch_only()
    assert not called

    monkeypatch.setattr(appliance, "mount_transfer", lambda: True)
    appliance._export_watch_only()
    assert called == [["export-watch-only", "--count", "5",
                       "--out", str(transfer / "watch-only.json")]]


def test_export_watch_only_is_blocked_by_lockdown(monkeypatch, tmp_path):
    wallet = tmp_path / "wallet.vault"
    wallet.write_text("encrypted test fixture")
    lockdown = tmp_path / "lockdown"
    lockdown.touch()
    monkeypatch.setattr(appliance, "VAULT", wallet)
    monkeypatch.setattr(appliance, "LOCKDOWN", lockdown)
    monkeypatch.setattr(appliance, "_bounded_transfer_device",
                        lambda: (_ for _ in ()).throw(AssertionError("no discovery in lockdown")))
    monkeypatch.setattr(appliance.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not export")))
    appliance._export_watch_only()


def test_export_watch_only_cli_is_create_only(tmp_path):
    """The CLI export path (exchange.write -> save_vault) never overwrites a transfer file."""
    target = tmp_path / "watch-only.json"
    target.write_text("attacker-controlled old export")
    with pytest.raises(OSError):
        save_vault(target, {"note": "public"})
    assert target.read_text() == "attacker-controlled old export"


def test_initialize_policy_never_overwrites_existing_policy(monkeypatch, tmp_path):
    wallet = tmp_path / "wallet.vault"
    wallet.write_text("encrypted test fixture")
    monkeypatch.setattr(appliance, "VAULT", wallet)
    called = []
    monkeypatch.setattr(appliance, "_run_cli", lambda args: called.append(args))
    appliance._initialize_policy()
    assert called == [["policy", "--file", str(wallet) + ".policy", "--action", "init"]]
    policy = tmp_path / "wallet.vault.policy"
    policy.write_text("existing encrypted test fixture")
    called.clear()
    appliance._initialize_policy()
    assert not called
