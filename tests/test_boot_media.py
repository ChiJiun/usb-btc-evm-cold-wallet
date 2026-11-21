"""Host-side adversarial tests for the standalone cold boot GPT media identifier."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import uuid
import zlib

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "buildroot-external/board/usb-wallet/identify_media.py"
spec = importlib.util.spec_from_file_location("cold_boot_media", HELPER)
assert spec is not None and spec.loader is not None
media = importlib.util.module_from_spec(spec)
spec.loader.exec_module(media)


def _fat(label: str) -> bytes:
    sector = bytearray(512)
    struct.pack_into("<H", sector, 11, 512)
    sector[43:54] = label.encode("ascii").ljust(11, b" ")
    sector[54:62] = b"FAT16   "
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


def _disk(
    disk_uuid=media.DISK_UUID,
    boot_uuid=media.BOOT_UUID,
    vault_uuid=media.VAULT_UUID,
    transfer_uuid=media.TRANSFER_UUID,
    include_transfer=True,
    extra_partition=False,
) -> bytes:
    entries = bytearray(128 * 128)
    start = 2048
    specs = [
        (media.EFI_TYPE, boot_uuid, media.READ_ONLY, media.BOOT_SECTORS),
        (media.LINUX_FS_TYPE, vault_uuid, 0, media.VAULT_SECTORS),
    ]
    if include_transfer:
        specs.append((media.DATA_TYPE, transfer_uuid, 0, media.TRANSFER_SECTORS))
    if extra_partition:
        specs.append((media.DATA_TYPE, uuid.uuid4(), 0, 128))
    for number, (kind, uid, attrs, sectors) in enumerate(specs):
        end = start + sectors - 1
        offset = number * 128
        entries[offset:offset + 16] = kind.bytes_le
        entries[offset + 16:offset + 32] = uid.bytes_le
        struct.pack_into("<QQQ", entries, offset + 32, start, end, attrs)
        start = end + 1

    header = bytearray(512)
    header[:8] = b"EFI PART"
    struct.pack_into("<I", header, 8, 0x00010000)
    struct.pack_into("<I", header, 12, 92)
    struct.pack_into("<QQ", header, 24, 1, start + 2048)
    struct.pack_into("<QQ", header, 40, 2048, start + 1024)
    header[56:72] = disk_uuid.bytes_le
    struct.pack_into("<QIII", header, 72, 2, 128, 128, zlib.crc32(entries))
    struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
    mbr = bytearray(512)
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr + header + entries)


def _create(
    sys_block: Path,
    dev: Path,
    name="sda",
    *,
    disk_uuid=media.DISK_UUID,
    boot_uuid=media.BOOT_UUID,
    transfer_uuid=media.TRANSFER_UUID,
    boot_label="USBCOLD_EFI",
    vault_label="COLD_VAULT",
    transfer_label="TX_TRANSFER",
    include_transfer=True,
    extra_partition=False,
    usb=True,
) -> None:
    sys_block.mkdir(parents=True, exist_ok=True)
    location = (
        sys_block.parent
        / "devices"
        / "pci0000:00"
        / ("usb1/1-1/1-1:1.0" if usb else "ata1/host0")
        / "host0/target0:0:0/0:0:0:0/block"
        / name
    )
    (location / "queue").mkdir(parents=True)
    (sys_block / name).symlink_to(location, target_is_directory=True)
    (location / "queue/logical_block_size").write_text("512\n")

    count = 3 if include_transfer else 2
    for index in range(1, count + 1):
        partition = location / f"{name}{index}"
        partition.mkdir()
        (partition / "partition").write_text(str(index) + "\n")
        (sys_block / f"{name}{index}").symlink_to(partition, target_is_directory=True)

    dev.mkdir(exist_ok=True)
    (dev / name).write_bytes(
        _disk(
            disk_uuid=disk_uuid,
            boot_uuid=boot_uuid,
            transfer_uuid=transfer_uuid,
            include_transfer=include_transfer,
            extra_partition=extra_partition,
        )
    )
    (dev / f"{name}1").write_bytes(_fat(boot_label))
    (dev / f"{name}2").write_bytes(_fat(vault_label))
    if include_transfer:
        (dev / f"{name}3").write_bytes(_fat(transfer_label))


def test_single_verified_three_partition_usb(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev)
    assert media.identify(sys_block, dev) == (
        str(dev / "sda1"),
        str(dev / "sda2"),
        str(dev / "sda3"),
        "sda",
    )


def test_legacy_two_partition_usb_remains_identifiable(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev, include_transfer=False)
    assert media.identify(sys_block, dev) == (
        str(dev / "sda1"),
        str(dev / "sda2"),
        None,
        "sda",
    )


def test_duplicated_cloned_usb_is_denied(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev, "sda")
    _create(sys_block, dev, "sdb")
    with pytest.raises(ValueError, match="duplicated"):
        media.identify(sys_block, dev)


@pytest.mark.parametrize(
    "mutation",
    [
        "bad_gpt_header_crc",
        "bad_gpt_entries_crc",
        "wrong_boot_guid",
        "wrong_transfer_guid",
        "wrong_disk_guid",
        "wrong_boot_label",
        "wrong_transfer_label",
        "missing_partition",
        "wrong_sector_size",
        "extra_partition",
    ],
)
def test_corruption_and_unexpected_media_fail_closed(tmp_path, mutation):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    kwargs = {}
    if mutation == "wrong_boot_guid":
        kwargs["boot_uuid"] = uuid.uuid4()
    elif mutation == "wrong_transfer_guid":
        kwargs["transfer_uuid"] = uuid.uuid4()
    elif mutation == "wrong_disk_guid":
        kwargs["disk_uuid"] = uuid.uuid4()
    elif mutation == "wrong_boot_label":
        kwargs["boot_label"] = "IMPOSTOR"
    elif mutation == "wrong_transfer_label":
        kwargs["transfer_label"] = "IMPOSTOR"
    elif mutation == "extra_partition":
        kwargs["extra_partition"] = True
    _create(sys_block, dev, **kwargs)

    if mutation == "bad_gpt_header_crc":
        data = bytearray((dev / "sda").read_bytes())
        data[512 + 8] ^= 1
        (dev / "sda").write_bytes(data)
    elif mutation == "bad_gpt_entries_crc":
        data = bytearray((dev / "sda").read_bytes())
        data[1024 + 32] ^= 1
        (dev / "sda").write_bytes(data)
    elif mutation == "missing_partition":
        (sys_block / "sda3").unlink()
    elif mutation == "wrong_sector_size":
        (sys_block / "sda/queue/logical_block_size").write_text("4096\n")

    with pytest.raises(ValueError, match="missing|duplicated|inconsistent"):
        media.identify(sys_block, dev)


def test_symlinked_partition_device_is_denied(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev)
    real = dev / "real-transfer"
    real.write_bytes((dev / "sda3").read_bytes())
    (dev / "sda3").unlink()
    (dev / "sda3").symlink_to(real)
    with pytest.raises(ValueError, match="missing|duplicated|inconsistent"):
        media.identify(sys_block, dev)


def test_collision_with_malformed_matching_disk_is_denied(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev, "sda")
    _create(sys_block, dev, "sdb", transfer_label="IMPOSTOR")
    with pytest.raises(ValueError, match="duplicated"):
        media.identify(sys_block, dev)


def test_identical_gpt_on_sata_scsi_disk_is_not_usb_trusted(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev, "sda", usb=False)
    assert not media._usb_mass_storage(sys_block / "sda")
    with pytest.raises(ValueError, match="inconsistent|duplicated"):
        media.identify(sys_block, dev)


def test_spoofed_trusted_identifiers_on_non_usb_disk_lock_down_even_with_valid_usb(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev, "sda", usb=True)
    _create(sys_block, dev, "sdb", usb=False)
    assert media._usb_mass_storage(sys_block / "sda")
    with pytest.raises(ValueError, match="inconsistent|duplicated"):
        media.identify(sys_block, dev)
