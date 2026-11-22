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


def _fat(label: str, *, fat32: bool = False) -> bytes:
    sector = bytearray(512)
    struct.pack_into("<H", sector, 11, 512)
    offset = 71 if fat32 else 43
    sector[offset:offset + 11] = label.encode("ascii").ljust(11, b" ")
    if fat32:
        sector[82:90] = b"FAT32   "
    else:
        sector[54:62] = b"FAT16   "
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


def _header(*, current_lba, backup_lba, first_usable, last_usable, disk_uuid, entries_lba, entries_crc):
    header = bytearray(512)
    header[:8] = b"EFI PART"
    struct.pack_into("<I", header, 8, 0x00010000)
    struct.pack_into("<I", header, 12, 92)
    struct.pack_into("<QQQQ", header, 24, current_lba, backup_lba, first_usable, last_usable)
    header[56:72] = disk_uuid.bytes_le
    struct.pack_into(
        "<QIII", header, 72, entries_lba,
        media.GPT_ENTRY_COUNT, media.GPT_ENTRY_SIZE, entries_crc,
    )
    struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
    return bytes(header)


def _write_disk(
    path: Path,
    disk_uuid=media.DISK_UUID,
    boot_uuid=media.BOOT_UUID,
    vault_uuid=media.VAULT_UUID,
    transfer_uuid=media.TRANSFER_UUID,
    transfer_attrs=0,
    include_transfer=True,
    extra_partition=False,
    gap_entry=False,
) -> None:
    entries = bytearray(media.GPT_ENTRY_COUNT * media.GPT_ENTRY_SIZE)
    start = 2048
    specs = [
        (media.EFI_TYPE, boot_uuid, media.READ_ONLY, media.BOOT_SECTORS),
        (
            media.LINUX_FS_TYPE if include_transfer else media.DATA_TYPE,
            vault_uuid, 0, media.VAULT_SECTORS,
        ),
    ]
    if include_transfer:
        specs.append((media.DATA_TYPE, transfer_uuid, transfer_attrs, media.TRANSFER_SECTORS))
    if extra_partition:
        specs.append((media.DATA_TYPE, uuid.uuid4(), 0, 128))
    for number, (kind, uid, attrs, sectors) in enumerate(specs):
        slot = number + (1 if gap_entry and number >= 2 else 0)
        end = start + sectors - 1
        offset = slot * media.GPT_ENTRY_SIZE
        entries[offset:offset + 16] = kind.bytes_le
        entries[offset + 16:offset + 32] = uid.bytes_le
        struct.pack_into("<QQQ", entries, offset + 32, start, end, attrs)
        start = end + 1

    table_crc = zlib.crc32(entries)
    last_lba = start + 2048
    backup_table_lba = last_lba - media.GPT_TABLE_SECTORS
    first_usable = 2 + media.GPT_TABLE_SECTORS
    last_usable = backup_table_lba - 1
    primary = _header(
        current_lba=1, backup_lba=last_lba,
        first_usable=first_usable, last_usable=last_usable,
        disk_uuid=disk_uuid, entries_lba=2, entries_crc=table_crc,
    )
    backup = _header(
        current_lba=last_lba, backup_lba=1,
        first_usable=first_usable, last_usable=last_usable,
        disk_uuid=disk_uuid, entries_lba=backup_table_lba, entries_crc=table_crc,
    )
    mbr = bytearray(512)
    mbr[450] = 0xEE
    struct.pack_into("<I", mbr, 454, 1)
    struct.pack_into("<I", mbr, 458, min(last_lba, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    with path.open("wb") as handle:
        handle.write(mbr)
        handle.write(primary)
        handle.write(entries)
        handle.seek(backup_table_lba * 512)
        handle.write(entries)
        handle.seek(last_lba * 512)
        handle.write(backup)
        handle.truncate((last_lba + 1) * 512)


def _create(
    sys_block: Path,
    dev: Path,
    name="sda",
    *,
    disk_uuid=media.DISK_UUID,
    boot_uuid=media.BOOT_UUID,
    transfer_uuid=media.TRANSFER_UUID,
    transfer_attrs=0,
    boot_label="USBCOLD_EFI",
    vault_label="COLD_VAULT",
    transfer_label="TX_TRANSFER",
    include_transfer=True,
    extra_partition=False,
    gap_entry=False,
    usb=True,
) -> None:
    sys_block.mkdir(parents=True, exist_ok=True)
    location = (
        sys_block.parent / "devices" / "pci0000:00"
        / ("usb1/1-1/1-1:1.0" if usb else "ata1/host0")
        / "host0/target0:0:0/0:0:0:0/block" / name
    )
    (location / "queue").mkdir(parents=True)
    (sys_block / name).symlink_to(location, target_is_directory=True)
    (location / "queue/logical_block_size").write_text("512\n")

    cursor = 2048
    sectors_by_number = [media.BOOT_SECTORS, media.VAULT_SECTORS]
    if include_transfer:
        sectors_by_number.append(media.TRANSFER_SECTORS)
    for index, sectors in enumerate(sectors_by_number, 1):
        partition = location / f"{name}{index}"
        partition.mkdir()
        (partition / "partition").write_text(str(index) + "\n")
        (partition / "start").write_text(str(cursor) + "\n")
        (partition / "size").write_text(str(sectors) + "\n")
        cursor += sectors
        (sys_block / f"{name}{index}").symlink_to(partition, target_is_directory=True)

    dev.mkdir(exist_ok=True)
    _write_disk(
        dev / name,
        disk_uuid=disk_uuid,
        boot_uuid=boot_uuid,
        transfer_uuid=transfer_uuid,
        transfer_attrs=transfer_attrs,
        include_transfer=include_transfer,
        extra_partition=extra_partition,
        gap_entry=gap_entry,
    )
    (dev / f"{name}1").write_bytes(_fat(boot_label))
    (dev / f"{name}2").write_bytes(_fat(vault_label))
    if include_transfer:
        (dev / f"{name}3").write_bytes(_fat(transfer_label, fat32=True))


def _flip(path: Path, offset: int) -> None:
    with path.open("r+b") as handle:
        handle.seek(offset)
        value = handle.read(1)
        handle.seek(offset)
        handle.write(bytes([value[0] ^ 1]))


def _last_lba(path: Path) -> int:
    return path.stat().st_size // 512 - 1

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
        "bad_backup_header_crc",
        "bad_backup_entries_crc",
        "backup_geometry_mismatch",
        "wrong_boot_guid",
        "wrong_transfer_guid",
        "wrong_disk_guid",
        "wrong_boot_label",
        "wrong_transfer_label",
        "transfer_fat16",
        "transfer_hidden",
        "transfer_no_drive_letter",
        "missing_partition",
        "wrong_sector_size",
        "extra_partition",
        "hybrid_mbr",
        "kernel_start_mismatch",
        "kernel_size_mismatch",
        "kernel_partition_number_mismatch",
        "gpt_entry_gap",
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
    elif mutation == "transfer_hidden":
        kwargs["transfer_attrs"] = 1 << 62
    elif mutation == "transfer_no_drive_letter":
        kwargs["transfer_attrs"] = 1 << 63
    elif mutation == "wrong_boot_label":
        kwargs["boot_label"] = "IMPOSTOR"
    elif mutation == "wrong_transfer_label":
        kwargs["transfer_label"] = "IMPOSTOR"
    elif mutation == "extra_partition":
        kwargs["extra_partition"] = True
    elif mutation == "gpt_entry_gap":
        kwargs["gap_entry"] = True
    _create(sys_block, dev, **kwargs)

    disk = dev / "sda"
    if mutation == "bad_gpt_header_crc":
        _flip(disk, 512 + 8)
    elif mutation == "bad_gpt_entries_crc":
        _flip(disk, 1024 + 32)
    elif mutation == "bad_backup_header_crc":
        _flip(disk, _last_lba(disk) * 512 + 8)
    elif mutation == "bad_backup_entries_crc":
        _flip(disk, (_last_lba(disk) - media.GPT_TABLE_SECTORS) * 512 + 32)
    elif mutation == "backup_geometry_mismatch":
        last = _last_lba(disk)
        with disk.open("r+b") as handle:
            handle.seek(last * 512)
            header = bytearray(handle.read(512))
            struct.pack_into("<Q", header, 72, last - media.GPT_TABLE_SECTORS - 1)
            struct.pack_into("<I", header, 16, 0)
            struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
            handle.seek(last * 512)
            handle.write(header)
    elif mutation == "transfer_fat16":
        (dev / "sda3").write_bytes(_fat("TX_TRANSFER"))
    elif mutation == "missing_partition":
        (sys_block / "sda3").unlink()
    elif mutation == "hybrid_mbr":
        with disk.open("r+b") as handle:
            handle.seek(462 + 4)
            handle.write(b"\x07")
    elif mutation == "wrong_sector_size":
        (sys_block / "sda/queue/logical_block_size").write_text("4096\n")
    elif mutation == "kernel_start_mismatch":
        (sys_block / "sda3/start").write_text("2048\n")
    elif mutation == "kernel_size_mismatch":
        (sys_block / "sda3/size").write_text(str(media.TRANSFER_SECTORS - 1) + "\n")
    elif mutation == "kernel_partition_number_mismatch":
        (sys_block / "sda3/partition").write_text("2\n")

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


