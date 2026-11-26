#!/usr/bin/env python3
"""Identify the unique expected cold-wallet USB GPT layout without udev/blkid.

This validates public partition metadata and Linux USB ancestry. It does not
authenticate the USB contents or provide a trusted boot root.
"""
from __future__ import annotations

import os
import errno
import fcntl
import hashlib
import select
import signal
import stat
import time
from pathlib import Path
import re
import struct
import sys
import uuid
import zlib

DISK_UUID = uuid.UUID("f1448aa1-28cc-54bf-8fdd-3008514c0ab5")
BOOT_UUID = uuid.UUID("e2bd6d1b-8de5-502d-a897-c53a8e60f46b")
VAULT_UUID = uuid.UUID("18f1c36f-d5c0-5052-9cd2-03e9c2a48f00")
TRANSFER_UUID = uuid.UUID("42f6f5d4-9310-5ac3-b5d4-1540cbe7d6b4")
EFI_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
LINUX_FS_TYPE = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
DATA_TYPE = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")
READ_ONLY = 1 << 60
SECTOR_SIZE = 512
BOOT_SECTORS = 64 * 1024 * 1024 // SECTOR_SIZE
VAULT_SECTORS = 64 * 1024 * 1024 // SECTOR_SIZE
TRANSFER_SECTORS = 512 * 1024 * 1024 // SECTOR_SIZE
GPT_ENTRY_COUNT = 128
GPT_ENTRY_SIZE = 128
GPT_TABLE_SECTORS = GPT_ENTRY_COUNT * GPT_ENTRY_SIZE // SECTOR_SIZE
BOOT_START_LBA = 2048
VAULT_START_LBA = BOOT_START_LBA + BOOT_SECTORS
TRANSFER_START_LBA = VAULT_START_LBA + VAULT_SECTORS


def _read_header(source, lba: int) -> dict[str, int | uuid.UUID]:
    source.seek(lba * SECTOR_SIZE)
    header = source.read(SECTOR_SIZE)
    if len(header) != SECTOR_SIZE or header[:8] != b"EFI PART":
        raise ValueError("missing GPT header")
    revision, size, checksum = struct.unpack_from("<III", header, 8)
    if revision != 0x00010000 or size != 92 or header[20:24] != bytes(4):
        raise ValueError("invalid GPT header geometry")
    canonical = bytearray(header[:size])
    canonical[16:20] = bytes(4)
    if zlib.crc32(canonical) != checksum:
        raise ValueError("invalid GPT header CRC")
    current_lba, backup_lba, first_usable, last_usable = struct.unpack_from("<QQQQ", header, 24)
    disk_id = uuid.UUID(bytes_le=header[56:72])
    entries_lba, count, width, entries_crc = struct.unpack_from("<QIII", header, 72)
    if (
        current_lba != lba
        or first_usable > last_usable
        or count != GPT_ENTRY_COUNT
        or width != GPT_ENTRY_SIZE
    ):
        raise ValueError("invalid GPT header geometry")
    return {
        "current_lba": current_lba,
        "backup_lba": backup_lba,
        "first_usable": first_usable,
        "last_usable": last_usable,
        "disk_id": disk_id,
        "entries_lba": entries_lba,
        "count": count,
        "width": width,
        "entries_crc": entries_crc,
    }


def _read_entries(source, header: dict[str, int | uuid.UUID]) -> bytes:
    lba = int(header["entries_lba"])
    count = int(header["count"])
    width = int(header["width"])
    source.seek(lba * SECTOR_SIZE)
    entries = source.read(count * width)
    if len(entries) != count * width or zlib.crc32(entries) != int(header["entries_crc"]):
        raise ValueError("invalid GPT entries CRC")
    return entries


# BLKGETDISKSEQ = _IOR(0x12, 128, __u64), on the x86-64 Linux target.
BLKGETDISKSEQ = 0x80081280


class MediaPending(ValueError):
    """Enumeration is incomplete; no unsafe media has been established."""


class MediaInvalid(ValueError):
    """Permanent security failure; never retry."""


class MediaDuplicate(MediaInvalid):
    """More than one trusted identity or a conflicting identity."""


class MediaReplaced(MediaInvalid):
    """Previously observed kernel device identity changed."""


class MediaTimeout(ValueError):
    """Readiness deadline expired."""


def _transient_io(exc: OSError) -> bool:
    # Retry only explicit transport readiness errors. Corrupt metadata, EIO,
    # removal and identity mismatches remain permanent failures.
    return exc.errno in {errno.EAGAIN, errno.EBUSY, errno.EINTR, errno.ETIMEDOUT}


def _open_media(path: Path, expected=None):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if expected is not None:
            _, sequence, dev = expected
            st = os.fstat(fd)
            if not stat.S_ISBLK(st.st_mode) or (
                f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}" != dev
            ):
                raise MediaReplaced("inconsistent device node identity")
            actual = struct.unpack("=Q", fcntl.ioctl(fd, BLKGETDISKSEQ, bytes(8)))[0]
            if str(actual) != sequence:
                raise MediaReplaced("inconsistent disk sequence")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def read_gpt(
    disk: Path, *, expected=None,
) -> tuple[uuid.UUID, list[tuple[uuid.UUID, uuid.UUID, int, int, int]]]:
    """Read and cross-check protective MBR plus primary/backup GPT copies."""
    if disk.is_symlink():
        raise ValueError("block device path must not be a symlink")
    with _open_media(disk, expected) as source:
        source.seek(0, os.SEEK_END)
        size_bytes = source.tell()
        if size_bytes < 68 * SECTOR_SIZE or size_bytes % SECTOR_SIZE:
            raise ValueError("invalid disk geometry")
        last_lba = size_bytes // SECTOR_SIZE - 1

        source.seek(0)
        mbr = source.read(SECTOR_SIZE)
        if len(mbr) != SECTOR_SIZE or mbr[510:512] != b"\x55\xaa":
            raise ValueError("missing protective MBR")
        first = mbr[446:462]
        if (
            first[0] != 0
            or first[4] != 0xEE
            or struct.unpack_from("<I", first, 8)[0] != 1
            or struct.unpack_from("<I", first, 12)[0] != min(last_lba, 0xFFFFFFFF)
        ):
            raise ValueError("invalid protective MBR")
        if any(mbr[462:510]):
            raise ValueError("hybrid protective MBR")

        primary = _read_header(source, 1)
        backup = _read_header(source, last_lba)
        if (
            int(primary["backup_lba"]) != last_lba
            or int(backup["backup_lba"]) != 1
            or primary["disk_id"] != backup["disk_id"]
            or primary["first_usable"] != backup["first_usable"]
            or primary["last_usable"] != backup["last_usable"]
            or primary["count"] != backup["count"]
            or primary["width"] != backup["width"]
            or primary["entries_crc"] != backup["entries_crc"]
            or int(primary["entries_lba"]) != 2
            or int(backup["entries_lba"]) != last_lba - GPT_TABLE_SECTORS
            or int(primary["first_usable"]) < 2 + GPT_TABLE_SECTORS
            or int(primary["last_usable"]) >= int(backup["entries_lba"])
        ):
            raise ValueError("primary/backup GPT geometry mismatch")

        entries = _read_entries(source, primary)
        backup_entries = _read_entries(source, backup)
        if entries != backup_entries:
            raise ValueError("primary/backup GPT partition tables differ")
        disk_id = primary["disk_id"]
        assert isinstance(disk_id, uuid.UUID)

    partitions = []
    seen_empty = False
    first_usable = int(primary["first_usable"])
    last_usable = int(primary["last_usable"])
    for index in range(GPT_ENTRY_COUNT):
        entry = entries[index * GPT_ENTRY_SIZE:(index + 1) * GPT_ENTRY_SIZE]
        if entry[:16] == bytes(16):
            seen_empty = True
            continue
        if seen_empty:
            raise ValueError("non-contiguous GPT partition entries")
        kind = uuid.UUID(bytes_le=entry[:16])
        part_id = uuid.UUID(bytes_le=entry[16:32])
        first_lba, last_part_lba, attrs = struct.unpack_from("<QQQ", entry, 32)
        if first_lba < first_usable or last_part_lba > last_usable or last_part_lba < first_lba:
            raise ValueError("invalid GPT partition range")
        partitions.append((kind, part_id, attrs, first_lba, last_part_lba))
    return disk_id, partitions


def fat_label(partition: Path, *, require_fat32: bool = False, expected=None) -> str:
    """Read the fixed FAT12/16/FAT32 volume label directly from its boot sector."""
    if partition.is_symlink():
        raise ValueError("partition device path must not be a symlink")
    with _open_media(partition, expected) as source:
        sector = source.read(SECTOR_SIZE)
    if len(sector) != SECTOR_SIZE or sector[510:512] != b"\x55\xaa":
        raise ValueError("missing FAT boot sector")
    if struct.unpack_from("<H", sector, 11)[0] != SECTOR_SIZE:
        raise ValueError("unexpected FAT sector size")
    fat_type = sector[82:90] if sector[82:90] == b"FAT32   " else sector[54:62]
    if fat_type not in (b"FAT12   ", b"FAT16   ", b"FAT32   "):
        raise ValueError("unsupported FAT filesystem")
    if require_fat32 and fat_type != b"FAT32   ":
        raise ValueError("TX_TRANSFER must use FAT32")
    raw = sector[71:82] if fat_type == b"FAT32   " else sector[43:54]
    return raw.decode("ascii").rstrip(" ")


def _usb_mass_storage(entry: Path) -> bool:
    """Require a USB sysfs transport ancestry for an sdX block device."""
    try:
        resolved = entry.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    parts = resolved.parts
    for i in range(len(parts) - 1):
        if (
            re.fullmatch(r"usb[0-9]+", parts[i])
            and re.fullmatch(r"[0-9]+-[0-9]+(?:\.[0-9]+)*", parts[i + 1])
        ):
            return True
    return False


def _partition_matches_kernel(
    sys_block: Path,
    disk_entry: Path,
    name: str,
    number: int,
    part: tuple[uuid.UUID, uuid.UUID, int, int, int],
    *, allow_pending: bool = False,
) -> bool:
    """Require the kernel's actual device mapping to match the CRC-checked GPT."""
    try:
        node = (sys_block / name).resolve(strict=True)
        disk = disk_entry.resolve(strict=True)
        return (
            node.parent == disk
            and (node / "partition").read_text().strip() == str(number)
            and int((node / "start").read_text().strip()) == part[3]
            and int((node / "size").read_text().strip()) == _size(part)
        )
    except FileNotFoundError as exc:
        if allow_pending:
            raise MediaPending("incomplete kernel partition attributes") from exc
        return False
    except (OSError, ValueError, RuntimeError):
        return False


def _size(part: tuple[uuid.UUID, uuid.UUID, int, int, int]) -> int:
    return part[4] - part[3] + 1


def _layout_valid(
    parts: list[tuple[uuid.UUID, uuid.UUID, int, int, int]],
) -> bool:
    if len(parts) not in (2, 3):
        return False
    boot, vault = parts[0], parts[1]
    if (
        boot[:2] != (EFI_TYPE, BOOT_UUID)
        or boot[2] != READ_ONLY
        or _size(boot) != BOOT_SECTORS
        or boot[3] != BOOT_START_LBA
        or boot[4] != VAULT_START_LBA - 1
        or vault[:2] != (
            LINUX_FS_TYPE if len(parts) == 3 else DATA_TYPE, VAULT_UUID
        )
        or vault[2] != 0
        or _size(vault) != VAULT_SECTORS
        or vault[3] != VAULT_START_LBA
        or vault[4] != TRANSFER_START_LBA - 1
    ):
        return False
    if len(parts) == 3:
        transfer = parts[2]
        if (
            transfer[:2] != (DATA_TYPE, TRANSFER_UUID)
            or transfer[2] != 0
            or _size(transfer) != TRANSFER_SECTORS
            or transfer[3] != TRANSFER_START_LBA
            or transfer[4] != TRANSFER_START_LBA + TRANSFER_SECTORS - 1
        ):
            return False
    return True


def _gpt_hint(path: Path, expected=None) -> bool:
    """A malformed GPT must not disappear from a uniqueness scan."""
    with _open_media(path, expected) as source:
        prefix = source.read((2 + GPT_TABLE_SECTORS) * SECTOR_SIZE)
        source.seek(0, os.SEEK_END)
        end = source.tell()
        tail_size = min(end, (GPT_TABLE_SECTORS + 1) * SECTOR_SIZE)
        source.seek(end - tail_size)
        tail = source.read(tail_size)
    return (
        any(prefix[i + 4:i + 5] == b"\xee" for i in range(446, 510, 16))
        or prefix[512:520] == b"EFI PART"
        or tail[-SECTOR_SIZE:-SECTOR_SIZE + 8] == b"EFI PART"
        or any(uid.bytes_le in prefix or uid.bytes_le in tail
               for uid in (DISK_UUID, BOOT_UUID, VAULT_UUID, TRANSFER_UUID))
    )


def identify(
    sys_block: Path = Path("/sys/class/block"),
    dev_root: Path = Path("/dev"),
    *,
    inventory=None,
) -> tuple[str, str, str | None, str]:
    """Return boot, vault, optional same-device transfer, and parent block name."""
    matches = []
    pending = False
    for entry in sorted(sys_block.iterdir()):
        name = entry.name
        if not re.fullmatch(r"sd[a-z]+", name) or not entry.is_dir():
            continue
        if (entry / "partition").exists():
            continue
        disk = dev_root / name
        expected = inventory.get(name) if inventory is not None else None
        if inventory is not None and expected is None:
            pending = True
            continue
        if not disk.exists():
            pending = True
            continue
        if disk.is_symlink():
            raise MediaInvalid("inconsistent disk device path")
        try:
            if (entry / "queue/logical_block_size").read_text().strip() != "512":
                raise MediaInvalid("inconsistent logical block size")
            if inventory is not None and int((entry / "size").read_text().strip()) == 0:
                pending = True
                continue
            disk_id, parts = read_gpt(disk, expected=expected)
        except MediaInvalid:
            raise
        except FileNotFoundError:
            pending = True
            continue
        except ValueError:
            # Non-GPT media (e.g. a separate legacy FAT transfer USB) is not
            # a boot candidate. A corrupt GPT, even alongside a valid clone,
            # is a permanent failure, not a reason to wait for its removal.
            try:
                hint = _gpt_hint(disk, expected)
            except OSError as exc:
                if inventory is not None and _transient_io(exc):
                    raise MediaPending("GPT hint I/O not ready") from exc
                raise MediaInvalid("inconsistent disk I/O") from exc
            if hint:
                raise MediaInvalid("inconsistent malformed GPT")
            continue
        except OSError as exc:
            if inventory is not None and _transient_io(exc):
                raise MediaPending("disk transport not ready") from exc
            raise MediaInvalid("inconsistent disk I/O") from exc
        part_ids = {part[1] for part in parts}
        if disk_id != DISK_UUID and not (
            part_ids & {BOOT_UUID, VAULT_UUID, TRANSFER_UUID}
        ):
            continue
        if not _usb_mass_storage(entry) or disk_id != DISK_UUID:
            raise MediaDuplicate("duplicated or inconsistent trusted GPT identity")
        if not _layout_valid(parts):
            raise MediaInvalid("inconsistent trusted GPT layout")

        boot = dev_root / f"{name}1"
        vault = dev_root / f"{name}2"
        transfer = dev_root / f"{name}3" if len(parts) == 3 else None
        names = [f"{name}1", f"{name}2"] + ([f"{name}3"] if transfer else [])
        if any(
            not (sys_block / part_name).exists()
            or not (dev_root / part_name).exists()
            or (inventory is not None and part_name not in inventory)
            for part_name in names
        ):
            pending = True
            continue
        if matches:
            raise MediaDuplicate("duplicated trusted USB partitions")
        if not all(
            _partition_matches_kernel(sys_block, entry, part_name, index, parts[index - 1],
                                      allow_pending=inventory is not None)
            for index, part_name in enumerate(names, 1)
        ):
            raise MediaInvalid("inconsistent kernel partition mapping")
        if any(
            re.fullmatch(re.escape(name) + r"[0-9]+", node.name)
            and node.name not in names
            for node in sys_block.iterdir()
        ):
            raise MediaInvalid("inconsistent extra kernel partition")
        try:
            def label(path, fat32=False):
                identity = inventory[path.name] if inventory is not None else None
                return fat_label(path, require_fat32=fat32, expected=identity)
            if label(boot) != "USBCOLD_EFI" or label(vault) != "COLD_VAULT":
                raise MediaInvalid("inconsistent trusted FAT identity")
            if transfer is not None and label(transfer, True) != "TX_TRANSFER":
                raise MediaInvalid("inconsistent trusted FAT identity")
        except MediaInvalid:
            raise
        except OSError as exc:
            if inventory is not None and _transient_io(exc):
                raise MediaPending("FAT transport not ready") from exc
            raise MediaInvalid("inconsistent FAT metadata") from exc
        except (ValueError, UnicodeDecodeError) as exc:
            raise MediaInvalid("inconsistent FAT metadata") from exc
        matches.append((str(boot), str(vault), str(transfer) if transfer else None, name))
        if len(matches) > 1:
            raise MediaDuplicate("duplicated trusted USB partitions")
    if pending or not matches:
        raise MediaPending("missing or not yet enumerated trusted USB partitions")
    return matches[0]


def capture_inventory(sys_block=Path("/sys/class/block")):
    """Pin kernel ancestry, diskseq and device numbers, including partitions."""
    found = {}
    for entry in sorted(sys_block.iterdir()):
        if not re.fullmatch(r"sd[a-z]+[0-9]*", entry.name):
            continue
        try:
            node = entry.resolve(strict=True)
            is_part = (node / "partition").exists()
            disk = node.parent if is_part else node
            seq = (disk / "diskseq").read_text().strip()
            dev = (node / "dev").read_text().strip()
            if not seq.isdecimal() or int(seq) <= 0 or not re.fullmatch(r"[0-9]+:[0-9]+", dev):
                raise MediaInvalid("inconsistent sysfs disk identity")
            found[entry.name] = (str(node), seq, dev)
        except FileNotFoundError:
            # A devtmpfs/sysfs node may be created piecemeal at startup.
            # Keep it visible in the inventory rather than treating it as absent.
            found[entry.name] = None
    return found


def observe(previous, current):
    """New nodes may appear, but an observed complete identity cannot change."""
    for name, identity in previous.items():
        if identity is not None and current.get(name) != identity:
            raise MediaReplaced("inconsistent device replacement during enumeration")
    previous.update({name: value for name, value in current.items() if value is not None})


def scan(previous):
    inventory = capture_inventory()
    observe(previous, inventory)
    # Never read partially initialized devices; no accepted identity until
    # the complete inventory is stable across the full GPT/FAT scan.
    if any(value is None for value in inventory.values()):
        raise MediaPending("missing sysfs identity")
    try:
        boot, vault, transfer, parent = identify(inventory=inventory)
    finally:
        after = capture_inventory()
        observe(previous, after)
    if inventory != after:
        raise MediaPending("missing stable enumeration")
    ancestry, seq, _ = inventory[parent]
    vault_dev = inventory[Path(vault).name][2]
    fingerprint = hashlib.sha256(repr(sorted(inventory.items())).encode("ascii")).hexdigest()
    return "\n".join((boot, vault, transfer or "-", parent, ancestry, seq, vault_dev, fingerprint))


def wait_ready(seconds=60, *, scanner=scan, clock=time.monotonic, sleeper=time.sleep):
    """Two complete identical scans; only explicit pending states may retry."""
    deadline = clock() + seconds
    observed = {}
    prior = None
    while clock() < deadline:
        try:
            identity = scanner(observed)
            if clock() >= deadline:
                break
            if prior is not None:
                if identity != prior:
                    raise MediaReplaced("inconsistent identity between complete scans")
                return identity
            prior = identity
        except MediaPending:
            # Do not accept a different device once a complete identity was seen.
            if prior is not None:
                raise MediaReplaced("inconsistent identity after readiness")
        remaining = deadline - clock()
        if remaining > 0:
            sleeper(min(1, remaining))
    raise MediaTimeout("readiness timeout")


def _worker(expected):
    try:
        if expected is None:
            return 0, wait_ready()
        identity = scan({})
        if identity != expected:
            raise MediaReplaced("inconsistent boot identity at mount boundary")
        return 0, identity
    except MediaTimeout:
        return 4, ""
    except MediaDuplicate:
        return 3, ""
    except MediaReplaced:
        return 5, ""
    except (MediaInvalid, MediaPending, OSError, ValueError):
        return 2, ""


def _bounded_worker(expected):
    """Bound even a stuck USB read. The read-only child owns no mount/write."""
    limit = 60 if expected is None else 10
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        # Do not retain the shell command-substitution stdout/stderr pipe if
        # a kernel I/O operation is uninterruptible after the deadline.
        os.close(1)
        os.close(2)
        try:
            status, identity = _worker(expected)
            os.write(write_fd, (str(status) + "\n" + identity).encode("ascii"))
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        if not select.select([read_fd], [], [], limit)[0]:
            return 4, ""
        payload = os.read(read_fd, 4096).decode("ascii")
        code, _, identity = payload.partition("\n")
        if code not in ("0", "2", "3", "4", "5") or (code == "0" and not identity):
            return 2, ""
        return int(code), identity
    finally:
        os.close(read_fd)
        # Never wait for a child stuck in kernel D-state. It cannot write media.
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, os.WNOHANG)


SERIAL_MARKERS = {
    "media-wait": b"USB_WALLET_MEDIA_WAIT\n",
    "audit-ok": b"USB_WALLET_UEFI_AUDIT_OK\n",
    "audit-lockdown": b"USB_WALLET_UEFI_AUDIT_LOCKDOWN\n",
    "console-ready": b"USB_WALLET_CONSOLE_READY\n",
    "lockdown-ready": b"USB_WALLET_LOCKDOWN_CONSOLE_READY\n",
    "transfer-ready": b"USB_WALLET_TRANSFER_AUDIT_OK\n",
}


def _write_serial(path, payload):
    # A tty node can exist with no working UART; never wait for carrier or
    # flow control and never create a node. The parent has a hard watchdog.
    fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
    try:
        while payload:
            if not select.select([], [fd], [], 0.2)[1]:
                return False
            try:
                count = os.write(fd, payload)
            except BlockingIOError:
                continue
            if count <= 0:
                return False
            payload = payload[count:]
        return True
    finally:
        os.close(fd)


def _emit_serial(payload, path=Path("/dev/ttyS0"), budget=2.0):
    """Best effort, even when the physical driver is stuck in kernel I/O."""
    if not payload or len(payload) > 16384:
        return False
    try:
        pid = os.fork()
    except OSError:
        return False
    if pid == 0:
        try:
            ok = _write_serial(path, payload)
        except Exception:
            ok = False
        os._exit(0 if ok else 1)
    deadline = time.monotonic() + budget
    try:
        while time.monotonic() < deadline:
            finished, status = os.waitpid(pid, os.WNOHANG)
            if finished:
                pid = None
                return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
            time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
        return False
    finally:
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, os.WNOHANG)


def _serial_diagnostic(mode):
    marker = SERIAL_MARKERS.get(mode)
    if marker is None:
        return 2
    payload = marker
    if mode in ("audit-ok", "audit-lockdown"):
        try:
            with Path("/run/usb-wallet/boot-checks.txt").open("rb") as source:
                raw = source.read(16000)
            prefix = b"PASS:" if mode == "audit-ok" else b"FAIL:"
            payload = b"".join(line + b"\n" for line in raw.splitlines()
                               if line.startswith((prefix, b"INFO:")))
            payload += marker
        except OSError:
            return 1
    return 0 if _emit_serial(payload) else 1


def main() -> int:
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "--serial":
        return _serial_diagnostic(args[1])
    if args and (len(args) != 2 or args[0] != "--check"):
        return 2
    status, identity = _bounded_worker(args[1] if args else None)
    if status == 0:
        print(identity)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
