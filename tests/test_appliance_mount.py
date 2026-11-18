"""Fail-closed checks for removable transaction transport and appliance routing."""
from types import SimpleNamespace

from usb_cold_wallet import appliance


SAFE = {"rw", "nodev", "noexec", "nosuid", "sync"}


def _candidate(monkeypatch, value="/dev/sdb1"):
    monkeypatch.setattr(appliance, "_transfer_candidate", lambda: value)


def test_transfer_candidate_requires_unique_separate_usb_disk(monkeypatch):
    mapping = {
        f"PARTUUID={appliance.BOOT_PARTUUID}": "/dev/sda1",
        f"PARTUUID={appliance.VAULT_PARTUUID}": "/dev/sda2",
        "LABEL=TX_TRANSFER": "/dev/sdb1",
    }
    monkeypatch.setattr(appliance, "_unique_blkid_device", lambda tag: mapping.get(tag))
    assert appliance._transfer_candidate() == "/dev/sdb1"

    mapping["LABEL=TX_TRANSFER"] = "/dev/sda3"
    assert appliance._transfer_candidate() is None


def test_unique_blkid_rejects_ambiguous_label(monkeypatch):
    monkeypatch.setattr(appliance, "_blkid_devices", lambda tag: ["/dev/sdb1", "/dev/sdc1"])
    assert appliance._unique_blkid_device("LABEL=TX_TRANSFER") is None


def test_transfer_mount_rejects_unsafe_existing_mount(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    _candidate(monkeypatch)
    monkeypatch.setattr(appliance, "_mount_info", lambda path: ("/dev/sdb1", "vfat", {"rw", "nodev"}))
    assert appliance.mount_transfer() is False


def test_transfer_mount_rejects_wrong_filesystem_or_source(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    _candidate(monkeypatch)
    monkeypatch.setattr(appliance, "_mount_info", lambda path: ("/dev/sdb1", "ext4", SAFE))
    assert appliance.mount_transfer() is False
    monkeypatch.setattr(appliance, "_mount_info", lambda path: ("/dev/sdc1", "vfat", SAFE))
    assert appliance.mount_transfer() is False


def test_transfer_mount_accepts_expected_source_and_flags(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    _candidate(monkeypatch)
    monkeypatch.setattr(appliance, "_mount_info", lambda path: ("/dev/sdb1", "vfat", SAFE))
    assert appliance.mount_transfer() is True


def test_transfer_mount_checks_new_mount_source_and_flags(monkeypatch, tmp_path):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    _candidate(monkeypatch)
    states = iter([None, ("/dev/sdb1", "vfat", SAFE)])
    monkeypatch.setattr(appliance, "_mount_info", lambda path: next(states))
    calls = []
    monkeypatch.setattr(
        appliance.subprocess,
        "run",
        lambda args, **kwargs: calls.append(args) or SimpleNamespace(returncode=0),
    )
    assert appliance.mount_transfer() is True
    assert calls[0][-2:] == ["/dev/sdb1", str(tmp_path)]
    assert "-L" not in calls[0]


def test_file_selector_rejects_zero_and_negative_indices(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)
    (tmp_path / "a.psbt").write_text("test")
    monkeypatch.setattr(appliance, "mount_transfer", lambda: True)
    for index in ("0", "-1", "2"):
        monkeypatch.setattr("builtins.input", lambda prompt, value=index: value)
        assert appliance._select_file(".psbt") is None
    assert capsys.readouterr().out.count("Invalid selection.") == 3


def test_evm_envelope_routes_to_request_flag(monkeypatch, tmp_path):
    request = tmp_path / "evm-request.json"
    request.write_text("{}")
    monkeypatch.setattr(appliance, "_select_file", lambda suffix: request)
    monkeypatch.setattr(appliance, "_exchange_kind", lambda path: "evm-request")
    answers = iter(["0x000000000000000000000000000000000000dEaD", "1000"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    calls = []
    monkeypatch.setattr(appliance, "_run_cli", lambda args: calls.append(args))
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)

    appliance._sign_evm()

    assert calls
    assert calls[0][0:2] == ["sign-evm", "--request"]
    assert str(request) in calls[0]


def test_btc_envelope_routes_to_request_flag(monkeypatch, tmp_path):
    request = tmp_path / "btc-request.json"
    request.write_text("{}")
    monkeypatch.setattr(appliance, "_select_file", lambda suffix: request)
    monkeypatch.setattr(appliance, "_exchange_kind", lambda path: "btc-request")
    answers = iter(["tb1qexample", "50000", "2000", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    calls = []
    monkeypatch.setattr(appliance, "_run_cli", lambda args: calls.append(args))
    monkeypatch.setattr(appliance, "TRANSFER", tmp_path)

    appliance._sign_btc()

    assert calls
    assert calls[0][0:2] == ["sign-btc", "--request"]
    assert str(request) in calls[0]
