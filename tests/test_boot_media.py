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
    boot_type=media.EFI_TYPE,
    vault_type=None,
    transfer_type=media.DATA_TYPE,
    boot_attrs=media.READ_ONLY,
    vault_attrs=0,
    transfer_attrs=0,
    boot_sectors=media.BOOT_SECTORS,
    vault_sectors=media.VAULT_SECTORS,
    transfer_sectors=media.TRANSFER_SECTORS,
    include_transfer=True,
    extra_partition=False,
    gap_entry=False,
) -> None:
    entries = bytearray(media.GPT_ENTRY_COUNT * media.GPT_ENTRY_SIZE)
    start = 2048
    effective_vault_type = (
        vault_type
        if vault_type is not None
        else (media.LINUX_FS_TYPE if include_transfer else media.DATA_TYPE)
    )
    specs = [
        (boot_type, boot_uuid, boot_attrs, boot_sectors),
        (effective_vault_type, vault_uuid, vault_attrs, vault_sectors),
    ]
    if include_transfer:
        specs.append((transfer_type, transfer_uuid, transfer_attrs, transfer_sectors))
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
    vault_uuid=media.VAULT_UUID,
    transfer_uuid=media.TRANSFER_UUID,
    boot_type=media.EFI_TYPE,
    vault_type=None,
    transfer_type=media.DATA_TYPE,
    boot_attrs=media.READ_ONLY,
    vault_attrs=0,
    transfer_attrs=0,
    boot_sectors=media.BOOT_SECTORS,
    vault_sectors=media.VAULT_SECTORS,
    transfer_sectors=media.TRANSFER_SECTORS,
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
    sectors_by_number = [boot_sectors, vault_sectors]
    if include_transfer:
        sectors_by_number.append(transfer_sectors)
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
        vault_uuid=vault_uuid,
        transfer_uuid=transfer_uuid,
        boot_type=boot_type,
        vault_type=vault_type,
        transfer_type=transfer_type,
        boot_attrs=boot_attrs,
        vault_attrs=vault_attrs,
        transfer_attrs=transfer_attrs,
        boot_sectors=boot_sectors,
        vault_sectors=vault_sectors,
        transfer_sectors=transfer_sectors,
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


def test_primary_and_backup_gpt_preserve_exact_partition_security_fields(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev)
    disk_id, parts = media.read_gpt(dev / "sda")
    assert disk_id == media.DISK_UUID
    assert parts == [
        (
            media.EFI_TYPE,
            media.BOOT_UUID,
            media.READ_ONLY,
            media.BOOT_START_LBA,
            media.VAULT_START_LBA - 1,
        ),
        (
            media.LINUX_FS_TYPE,
            media.VAULT_UUID,
            0,
            media.VAULT_START_LBA,
            media.TRANSFER_START_LBA - 1,
        ),
        (
            media.DATA_TYPE,
            media.TRANSFER_UUID,
            0,
            media.TRANSFER_START_LBA,
            media.TRANSFER_START_LBA + media.TRANSFER_SECTORS - 1,
        ),
    ]


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
        "wrong_vault_guid",
        "wrong_transfer_guid",
        "wrong_disk_guid",
        "wrong_boot_type",
        "wrong_vault_type",
        "wrong_transfer_type",
        "missing_boot_read_only",
        "extra_boot_attribute",
        "vault_attribute",
        "wrong_boot_size",
        "wrong_vault_size",
        "wrong_transfer_size",
        "wrong_boot_label",
        "wrong_vault_label",
        "wrong_transfer_label",
        "transfer_fat16",
        "transfer_hidden",
        "transfer_no_drive_letter",
        "missing_partition",
        "wrong_sector_size",
        "extra_partition",
        "hybrid_mbr",
        "protective_mbr_size_mismatch",
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
    elif mutation == "wrong_vault_guid":
        kwargs["vault_uuid"] = uuid.uuid4()
    elif mutation == "wrong_transfer_guid":
        kwargs["transfer_uuid"] = uuid.uuid4()
    elif mutation == "wrong_disk_guid":
        kwargs["disk_uuid"] = uuid.uuid4()
    elif mutation == "wrong_boot_type":
        kwargs["boot_type"] = uuid.uuid4()
    elif mutation == "wrong_vault_type":
        kwargs["vault_type"] = uuid.uuid4()
    elif mutation == "wrong_transfer_type":
        kwargs["transfer_type"] = uuid.uuid4()
    elif mutation == "missing_boot_read_only":
        kwargs["boot_attrs"] = 0
    elif mutation == "extra_boot_attribute":
        kwargs["boot_attrs"] = media.READ_ONLY | (1 << 2)
    elif mutation == "vault_attribute":
        kwargs["vault_attrs"] = 1 << 62
    elif mutation == "wrong_boot_size":
        kwargs["boot_sectors"] = media.BOOT_SECTORS - 1
    elif mutation == "wrong_vault_size":
        kwargs["vault_sectors"] = media.VAULT_SECTORS - 1
    elif mutation == "wrong_transfer_size":
        kwargs["transfer_sectors"] = media.TRANSFER_SECTORS - 1
    elif mutation == "transfer_hidden":
        kwargs["transfer_attrs"] = 1 << 62
    elif mutation == "transfer_no_drive_letter":
        kwargs["transfer_attrs"] = 1 << 63
    elif mutation == "wrong_boot_label":
        kwargs["boot_label"] = "IMPOSTOR"
    elif mutation == "wrong_vault_label":
        kwargs["vault_label"] = "IMPOSTOR"
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
    elif mutation == "protective_mbr_size_mismatch":
        with disk.open("r+b") as handle:
            handle.seek(458)
            handle.write(struct.pack("<I", 1))
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



def test_layout_rejects_lba_gaps_even_when_partition_sizes_and_ids_match():
    boot = (
        media.EFI_TYPE,
        media.BOOT_UUID,
        media.READ_ONLY,
        media.BOOT_START_LBA,
        media.VAULT_START_LBA - 1,
    )
    vault = (
        media.LINUX_FS_TYPE,
        media.VAULT_UUID,
        0,
        media.VAULT_START_LBA + 1,
        media.TRANSFER_START_LBA,
    )
    transfer = (
        media.DATA_TYPE,
        media.TRANSFER_UUID,
        0,
        media.TRANSFER_START_LBA + 1,
        media.TRANSFER_START_LBA + media.TRANSFER_SECTORS,
    )
    assert not media._layout_valid([boot, vault, transfer])


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




class _Clock:
    now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def test_readiness_retries_only_pending_then_requires_two_full_scans():
    clock = _Clock()
    calls = []
    def scanner(_):
        calls.append(clock.now)
        if len(calls) <= 3:
            raise media.MediaPending("missing")
        return "stable"
    assert media.wait_ready(scanner=scanner, clock=clock.monotonic, sleeper=clock.sleep) == "stable"
    assert calls == [0, 1, 2, 3, 4]


def test_readiness_timeout_is_bounded():
    clock = _Clock()
    def scanner(_):
        raise media.MediaPending("missing")
    with pytest.raises(media.MediaTimeout):
        media.wait_ready(60, scanner=scanner, clock=clock.monotonic, sleeper=clock.sleep)
    assert clock.now == 60


@pytest.mark.parametrize("failure", [media.MediaInvalid, media.MediaDuplicate, media.MediaReplaced])
def test_security_failure_is_never_retried(failure):
    clock = _Clock()
    def scanner(_):
        raise failure("security failure")
    with pytest.raises(failure):
        media.wait_ready(scanner=scanner, clock=clock.monotonic, sleeper=clock.sleep)
    assert clock.now == 0


def test_readiness_rejects_replacement_between_complete_scans():
    clock = _Clock()
    identities = iter(("diskseq-1", "diskseq-2"))
    with pytest.raises(media.MediaReplaced):
        media.wait_ready(scanner=lambda _: next(identities), clock=clock.monotonic, sleeper=clock.sleep)


def test_observed_diskseq_cannot_be_replaced_while_waiting():
    previous = {}
    media.observe(previous, {"sda": ("/sys/device", "10", "8:0")})
    with pytest.raises(media.MediaReplaced):
        media.observe(previous, {"sda": ("/sys/device", "11", "8:0")})


def test_readiness_cannot_ignore_malformed_duplicate(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev, "sda")
    _create(sys_block, dev, "sdb")
    _flip(dev / "sdb", 512 + 8)
    with pytest.raises(media.MediaInvalid, match="malformed GPT"):
        media.identify(sys_block, dev)


def test_missing_partition_is_pending_but_malformed_gpt_is_permanent(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev)
    (sys_block / "sda3").unlink()
    with pytest.raises(media.MediaPending):
        media.identify(sys_block, dev)
    _flip(dev / "sda", 512 + 8)
    with pytest.raises(media.MediaInvalid):
        media.identify(sys_block, dev)


def test_delayed_real_fixture_enumerates_before_deadline(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    sys_block.mkdir()
    clock = _Clock()
    def scanner(_):
        if clock.now >= 4 and not (sys_block / "sda").exists():
            _create(sys_block, dev)
        return media.identify(sys_block, dev)
    result = media.wait_ready(scanner=scanner, clock=clock.monotonic, sleeper=clock.sleep)
    assert result[3] == "sda"
    assert clock.now == 5


def test_larger_unadjusted_flash_geometry_remains_rejected(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev)
    with (dev / "sda").open("r+b") as disk:
        disk.truncate(31_457_280_000)
    with pytest.raises(media.MediaInvalid, match="malformed GPT"):
        media.identify(sys_block, dev)


def test_malformed_primary_cannot_hide_valid_backup_clone(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev, "sda")
    _create(sys_block, dev, "sdb")
    with (dev / "sdb").open("r+b") as disk:
        disk.write(bytes((2 + media.GPT_TABLE_SECTORS) * media.SECTOR_SIZE))
    with pytest.raises(media.MediaInvalid, match="malformed GPT"):
        media.identify(sys_block, dev)


def test_unexpected_noncontiguous_kernel_partition_is_rejected(tmp_path):
    sys_block, dev = tmp_path / "sys", tmp_path / "dev"
    _create(sys_block, dev)
    (sys_block / "sda9").symlink_to((sys_block / "sda3").resolve(), target_is_directory=True)
    with pytest.raises(media.MediaInvalid, match="extra kernel partition"):
        media.identify(sys_block, dev)


@pytest.mark.parametrize("delay,accepted", [(5, True), (15, True), (30, True), (58, True), (59, False), (60, False)])
def test_readiness_deadline_matrix(delay, accepted):
    clock = _Clock()
    def scanner(_):
        if clock.now < delay:
            raise media.MediaPending("delayed enumeration")
        return "stable"
    if accepted:
        assert media.wait_ready(scanner=scanner, clock=clock.monotonic, sleeper=clock.sleep) == "stable"
    else:
        with pytest.raises(media.MediaTimeout):
            media.wait_ready(scanner=scanner, clock=clock.monotonic, sleeper=clock.sleep)
        assert clock.now == 60


def test_serial_watchdog_bounds_failed_and_stuck_driver(monkeypatch, tmp_path):
    import os
    import time
    if not hasattr(os, "fork"):
        pytest.skip("requires Linux fork")
    sink = tmp_path / "diagnostic"
    sink.touch()
    assert media._emit_serial(media.SERIAL_MARKERS["media-wait"], sink)
    assert sink.read_bytes() == b"USB_WALLET_MEDIA_WAIT\n"
    if Path("/dev/full").exists():
        assert not media._emit_serial(b"test", Path("/dev/full"))
    monkeypatch.setattr(media, "_write_serial", lambda *args: time.sleep(30))
    start = time.monotonic()
    assert not media._emit_serial(b"test", sink, budget=0.1)
    assert time.monotonic() - start < 2


@pytest.mark.parametrize("error,transient", [(11, True), (110, True), (16, True), (5, False), (19, False)])
def test_only_explicit_transport_readiness_errors_can_retry(error, transient):
    assert media._transient_io(OSError(error, "test")) is transient


@pytest.mark.parametrize("capacity", [8 * 1024**3, 16 * 1024**3, 31_457_280_000, 64 * 1024**3])
def test_capacity_preparation_preserves_partition_entries_and_payload(tmp_path, capacity):
    from scripts.prepare_usb_capacity_image import relocate_gpt
    from scripts.verify_image import verify_image
    disk = tmp_path / "capacity.img"
    _write_disk(disk)
    original = media.read_gpt(disk)
    with disk.open("r+b") as handle:
        for label, lba in (("USBCOLD_EFI", media.BOOT_START_LBA),
                           ("COLD_VAULT", media.VAULT_START_LBA),
                           ("TX_TRANSFER", media.TRANSFER_START_LBA)):
            handle.seek(lba * 512)
            handle.write(_fat(label, fat32=label == "TX_TRANSFER"))
            handle.write(b"partition-data")
        handle.flush()
        old_last = _last_lba(disk)
        relocate_gpt(handle, capacity)
        assert disk.stat().st_size == capacity
        assert media.read_gpt(disk) == original
        for _, _, _, start, _ in original[1]:
            handle.seek(start * 512 + 512)
            assert handle.read(14) == b"partition-data"
        handle.seek((old_last - media.GPT_TABLE_SECTORS) * 512)
        assert handle.read((media.GPT_TABLE_SECTORS + 1) * 512) == bytes(
            (media.GPT_TABLE_SECTORS + 1) * 512)
    assert verify_image(disk) == 0


def test_capacity_preparation_rejects_untrusted_digest_without_output(tmp_path):
    from scripts.prepare_usb_capacity_image import prepare_image
    source, output = tmp_path / "source.img", tmp_path / "output.img"
    source.write_bytes(b"not a verified image")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        prepare_image(source, output, 8 * 1024**3, "a" * 64)
    assert not output.exists()
    assert source.read_bytes() == b"not a verified image"
    assert list(tmp_path.iterdir()) == [source]


def test_capacity_preparation_full_path_uses_new_file_and_distinct_hash(tmp_path):
    import hashlib
    from scripts.prepare_usb_capacity_image import prepare_image
    from scripts.verify_image import verify_image
    source, output = tmp_path / "original.img", tmp_path / "prepared.img"
    _write_disk(source)
    with source.open("r+b") as handle:
        for label, lba in (("USBCOLD_EFI", media.BOOT_START_LBA),
                           ("COLD_VAULT", media.VAULT_START_LBA),
                           ("TX_TRANSFER", media.TRANSFER_START_LBA)):
            handle.seek(lba * 512)
            handle.write(_fat(label, fat32=label == "TX_TRANSFER"))
    with source.open("rb") as handle:
        expected = hashlib.file_digest(handle, "sha256").hexdigest()
    size = source.stat().st_size + 1024 * 1024
    result = prepare_image(source, output, size, expected)
    assert result["sourceSha256"] == expected
    assert result["physicalMediaVerified"] is False
    with output.open("rb") as handle:
        assert hashlib.file_digest(handle, "sha256").hexdigest() == result["derivedSha256"]
    with source.open("rb") as handle:
        assert hashlib.file_digest(handle, "sha256").hexdigest() == expected
    assert media.read_gpt(source) == media.read_gpt(output)
    assert output.stat().st_size == size
    assert verify_image(output) == 0
    with pytest.raises(ValueError, match="output must not exist"):
        prepare_image(source, output, size, expected)
