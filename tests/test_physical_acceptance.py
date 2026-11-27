"""Fail-closed, non-destructive journal acceptance tests (no physical USB used)."""
from __future__ import annotations

from argparse import Namespace
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "physical_acceptance.py"
SPEC = importlib.util.spec_from_file_location("physical_acceptance", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

COMMIT = "a" * 40
DIGEST = "b" * 64


def create(directory: str) -> Path:
    path = Path(directory) / "run.json"
    module.start(Namespace(file=str(path), commit=COMMIT, image_sha256=DIGEST,
                           hardware="Test PC", firmware="UEFI 1.0",
                           device_identity="redacted-usb-test-a"))
    return path


def record(path: Path, case="UEFI_BOOT", status="PASS", evidence="proof.txt",
           note="Manual test observed", command="manual UEFI check",
           exit_code=0, operator_verified=True):
    module.record(Namespace(
        file=str(path), case=case, status=status, evidence=evidence,
        note=note, command=command, exit_code=exit_code,
        operator_verified=operator_verified,
    ))


def inventory_report(**overrides) -> dict:
    data = {
        "result": "INVENTORY_VERIFIED", "physicalAcceptance": "NOT TESTED",
        "imageFileVerified": True, "deviceLayoutVerified": True,
        "writtenMediaVerified": True, "exactImageCommit": COMMIT,
        "imageSha256": DIGEST,
        "mediaReadbackSha256": "e" * 64,
        "expectedStableRegionSha256": "e" * 64,
        "mediaReadbackScope": module.MEDIA_READBACK_SCOPE,
        "collectedAtUtc": module.utc_now(),
        "observed": {
            "driveLetter": "F",
            "disk": {"busType": "USB", "partitionStyle": "GPT",
                     "diskNumber": 8, "diskGuid": "f1448aa1-28cc-54bf-8fdd-3008514c0ab5"},
            "partitions": [
                {"diskNumber": 8, "partitionNumber": index,
                 "partitionGuid": f"00000000-0000-0000-0000-{index:012x}",
                 "label": label, "filesystem": fs,
                 "driveLetter": "F" if index == 3 else ""}
                for index, label, fs in [
                    (1, "USBCOLD_EFI", "FAT"), (2, "COLD_VAULT", "FAT"),
                    (3, "TX_TRANSFER", "FAT32"),
                ]
            ],
        },
    }
    data.update(overrides)
    return data


class TestPhysicalAcceptance(unittest.TestCase):
    def test_initial_not_tested_atomic_init_exclusive(self):
        with tempfile.TemporaryDirectory() as root:
            path = create(root)
            data = module.load(path)
            self.assertEqual(data["schemaVersion"], 2)
            self.assertEqual(set(data["cases"]), set(module.CASES))
            self.assertTrue(all(c["status"] == "NOT TESTED" for c in data["cases"].values()))
            with self.assertRaises(ValueError):
                create(root)

    def test_pass_requires_manual_evidence_and_exit_success(self):
        with tempfile.TemporaryDirectory() as root:
            path = create(root)
            proof = Path(root) / "proof.txt"
            proof.write_text("Public, redacted UEFI boot evidence", encoding="utf-8")
            for changes in (
                {"evidence": None}, {"command": None}, {"note": None},
                {"exit_code": 1}, {"operator_verified": False},
                {"evidence": "../traversal"}, {"evidence": ".hidden"},
            ):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    record(path, **changes)
            record(path)
            data = module.load(path)
            obs = data["cases"]["UEFI_BOOT"]["observations"][0]
            self.assertEqual(obs["exitCode"], 0)
            self.assertTrue(obs["operatorVerified"])
            self.assertEqual(len(obs["evidenceSha256"]), 64)

    def test_tampered_and_stale_evidence_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path = create(root)
            proof = Path(root) / "proof.txt"
            proof.write_text("Public evidence", encoding="utf-8")
            record(path)
            proof.write_text("Tampered!", encoding="utf-8")
            with self.assertRaises(ValueError):
                module.load(path)
            proof.write_text("Public evidence", encoding="utf-8")
            data = module.load(path)
            data["cases"]["UEFI_BOOT"]["observations"][0]["atUtc"] = (
                dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=45)
            ).isoformat()
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Stale"):
                module.load(path)

    def test_win_inventory_rejects_fake_and_unverified_media(self):
        with tempfile.TemporaryDirectory() as root:
            path = create(root)
            proof = Path(root) / "inventory.json"
            proof.write_text("Human says USB PASS", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "machine-readable"):
                record(path, case="WIN_USB_ID", evidence=proof.name)
            for changes in (
                {"writtenMediaVerified": False},
                {"deviceLayoutVerified": False},
                {"result": "PASS"},
                {"exactImageCommit": "c" * 40},
                {"imageSha256": "d" * 64},
                {"physicalAcceptance": "PASS"},
                {"mediaReadbackSha256": "c" * 64},
                {"expectedStableRegionSha256": "c" * 64},
                {"expectedStableRegionSha256": None, "mediaReadbackSha256": None},
                {"expectedStableRegionSha256": "not-hex", "mediaReadbackSha256": "not-hex"},
                {"mediaReadbackScope": "LBA0..end"},
                {"mediaReadbackScope": None},
                {"collectedAtUtc": "2020-01-01T00:00:00+00:00"},
                {"observed": {}},
            ):
                with self.subTest(changes=changes):
                    proof.write_text(json.dumps(inventory_report(**changes)), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        record(path, case="GPT_LAYOUT", evidence=proof.name)
            proof.write_text(json.dumps(inventory_report()), encoding="utf-8")
            record(path, case="WIN_USB_ID", evidence=proof.name)
            self.assertEqual(module.load(path)["cases"]["WIN_USB_ID"]["status"], "PASS")
            proof.write_text(json.dumps(inventory_report(writtenMediaVerified=False)), encoding="utf-8")
            with self.assertRaises(ValueError):
                module.load(path)

    def test_image_hash_case_does_not_imply_physical_acceptance(self):
        with tempfile.TemporaryDirectory() as root:
            path = create(root)
            proof = Path(root) / "inventory.json"
            proof.write_text(json.dumps(inventory_report(
                deviceLayoutVerified=False, writtenMediaVerified=False,
                result="BLOCKED")), encoding="utf-8")
            record(path, case="IMAGE_SHA256", evidence=proof.name)
            cases = module.load(path)["cases"]
            self.assertEqual(cases["IMAGE_SHA256"]["status"], "PASS")
            self.assertEqual(cases["WIN_USB_ID"]["status"], "NOT TESTED")
            self.assertEqual(cases["GPT_LAYOUT"]["status"], "NOT TESTED")

    def test_status_and_case_provenance_tamper(self):
        with tempfile.TemporaryDirectory() as root:
            path = create(root)
            proof = Path(root) / "proof.txt"
            proof.write_text("evidence", encoding="utf-8")
            record(path)
            data = module.load(path)
            data["cases"]["UEFI_BOOT"]["observations"][0]["deviceIdentity"] = "different"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "provenance"):
                module.load(path)

    def test_fabricated_pass_without_observation(self):
        with tempfile.TemporaryDirectory() as root:
            path = create(root)
            data = module.load(path)
            data["cases"]["UEFI_BOOT"]["status"] = "PASS"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                module.load(path)

    def test_truncated_journal_and_interrupted_temp_update(self):
        with tempfile.TemporaryDirectory() as root:
            path = create(root)
            old = path.read_bytes()
            interrupted = Path(root) / ".acceptance-interrupted.tmp"
            interrupted.write_bytes(b'{"schemaVersion":2,"cases":')
            self.assertEqual(path.read_bytes(), old)
            self.assertEqual(module.load(path)["cases"]["UEFI_BOOT"]["status"], "NOT TESTED")
            path.write_bytes(old[:30])
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                module.load(path)

    def test_symlink_and_nested_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = create(root)
            other = Path(root) / "other"
            other.mkdir()
            link = Path(root) / "link"
            try:
                link.symlink_to(other, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable on this runner")
            with self.assertRaises(ValueError):
                module.save(link / "another.json", {"schemaVersion": 2})
            inside = other / "proof.txt"
            inside.write_text("evidence", encoding="utf-8")
            symlink_file = Path(root) / "proof.txt"
            symlink_file.symlink_to(inside)
            with self.assertRaises(ValueError):
                record(path)

    def test_auxiliary_boot_and_tx_evidence_reject_missing_or_tampered(self):
        with tempfile.TemporaryDirectory() as root:
            path = create(root)
            with self.assertRaises(ValueError):
                module.boot(Namespace(file=str(path), phase="WINDOWS_TO_USB",
                                      seconds=50, evidence="missing.txt"))
            proof = Path(root) / "boot-redacted.txt"
            proof.write_text("Boot timing output", encoding="utf-8")
            module.boot(Namespace(file=str(path), phase="WINDOWS_TO_USB",
                                  seconds=50, evidence=proof.name))
            self.assertEqual(module.load(path)["boots"][0]["durationSeconds"], 50)
            proof.write_text("Tampered", encoding="utf-8")
            with self.assertRaises(ValueError):
                module.load(path)

    def test_valid_txhash_and_invalid_txhash(self):
        with tempfile.TemporaryDirectory() as root:
            path = create(root)
            with self.assertRaises(ValueError):
                module.transaction(Namespace(file=str(path), chain="sepolia",
                                             txhash="invalid", evidence="redacted.txt"))
            (Path(root) / "redacted.txt").write_text("Public transaction evidence", encoding="utf-8")
            module.transaction(Namespace(file=str(path), chain="sepolia",
                                         txhash="0x" + "f" * 64, evidence="redacted.txt"))
            self.assertEqual(module.load(path)["transactions"]["sepolia"]["hash"],
                             "0x" + "f" * 64)


if __name__ == "__main__":
    unittest.main()


# --- Readback regression against the real capacity preparation tool -------
import shutil
import struct
import subprocess
import sys
import uuid
import zlib

ROOT = SCRIPT.parents[1]
PS_MODULE = ROOT / "scripts" / "physical_usb_inventory_core.psm1"
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")


def _load_capacity_tool():
    scripts = str(ROOT / "scripts")
    sys.path.insert(0, scripts)
    try:
        spec = importlib.util.spec_from_file_location(
            "prepare_usb_capacity_image", ROOT / "scripts" / "prepare_usb_capacity_image.py")
        assert spec and spec.loader
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        return tool
    finally:
        sys.path.remove(scripts)


def _fat(label: str, sectors: int, *, fat32: bool) -> bytes:
    sector = bytearray(512)
    struct.pack_into("<H", sector, 11, 512)
    offset = 71 if fat32 else 43
    sector[offset:offset + 11] = label.encode("ascii").ljust(11, b" ")
    if fat32:
        sector[82:90] = b"FAT32   "
        sector[13] = 8
        struct.pack_into("<HB", sector, 14, 32, 2)
        struct.pack_into("<IIHHI", sector, 32, sectors - 4, 1024, 0, 0, 2)
    else:
        sector[54:62] = b"FAT16   "
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


def _header(v, *, current, backup, first_usable, last_usable, entries_lba, entries_crc) -> bytes:
    header = bytearray(512)
    header[:8] = b"EFI PART"
    struct.pack_into("<II", header, 8, 0x00010000, 92)
    struct.pack_into("<QQQQ", header, 24, current, backup, first_usable, last_usable)
    header[56:72] = v.EXPECTED_DISK_UUID.bytes_le
    struct.pack_into("<QIII", header, 72, entries_lba, v.GPT_ENTRY_COUNT, v.GPT_ENTRY_SIZE, entries_crc)
    struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
    return bytes(header)


def _write_raw_image(v, path: Path) -> None:
    """Minimal valid single-USB raw image in the exact #76 layout."""
    entries = bytearray(v.GPT_ENTRY_COUNT * v.GPT_ENTRY_SIZE)
    specs = (
        (v.EFI_TYPE, v.EXPECTED_BOOT_UUID, v.GPT_READ_ONLY, v.BOOT_START_LBA, v.BOOT_SECTORS, "USBCOLD_EFI"),
        (v.LINUX_FS_TYPE, v.EXPECTED_VAULT_UUID, 0, v.VAULT_START_LBA, v.VAULT_SECTORS, "COLD_VAULT"),
        (v.BASIC_DATA_TYPE, v.EXPECTED_TRANSFER_UUID, 0, v.TRANSFER_START_LBA, v.TRANSFER_SECTORS, "TX_TRANSFER"),
    )
    for slot, (kind, uid, attrs, start, sectors, _) in enumerate(specs):
        offset = slot * v.GPT_ENTRY_SIZE
        entries[offset:offset + 16] = kind.bytes_le
        entries[offset + 16:offset + 32] = uid.bytes_le
        struct.pack_into("<QQQ", entries, offset + 32, start, start + sectors - 1, attrs)
    crc = zlib.crc32(entries)
    last_lba = v.TRANSFER_START_LBA + v.TRANSFER_SECTORS + 2047
    table = last_lba - v.GPT_TABLE_SECTORS
    first_usable = 2 + v.GPT_TABLE_SECTORS
    mbr = bytearray(512)
    mbr[450] = 0xEE
    struct.pack_into("<II", mbr, 454, 1, min(last_lba, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    with path.open("wb") as handle:
        handle.write(mbr)
        handle.write(_header(v, current=1, backup=last_lba, first_usable=first_usable,
                             last_usable=table - 1, entries_lba=2, entries_crc=crc))
        handle.write(entries)
        for _, _, _, start, sectors, label in specs:
            handle.seek(start * 512)
            handle.write(_fat(label, sectors, fat32=label == "TX_TRANSFER"))
            handle.write(label.encode("ascii") + b"-payload")
        handle.seek(table * 512)
        handle.write(entries)
        handle.write(_header(v, current=last_lba, backup=1, first_usable=first_usable,
                             last_usable=table - 1, entries_lba=table, entries_crc=crc))


def _ps_hash(function: str, image: Path, offset: int, capacity: int | None = None) -> str:
    extra = " -DeviceSizeBytes ([long]$env:PHYS_CAPACITY)" if capacity is not None else ""
    stream_arg = "-ImageStream" if capacity is not None else "-Stream"
    command = (
        "$ErrorActionPreference='Stop'; Import-Module $env:PHYS_MODULE -Force; "
        "$s=[System.IO.File]::OpenRead($env:PHYS_IMAGE); "
        f"try {{ {function} {stream_arg} $s{extra} -TransferOffsetBytes ([long]$env:PHYS_OFFSET) }} "
        "finally { $s.Dispose() }"
    )
    env = {**os.environ, "PHYS_MODULE": str(PS_MODULE), "PHYS_IMAGE": str(image),
           "PHYS_OFFSET": str(offset), "PHYS_CAPACITY": str(capacity or 0)}
    result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
                            env=env, capture_output=True, text=True, timeout=600)
    if result.returncode:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout.strip()


class TestCapacityImageReadback(unittest.TestCase):
    def test_expected_hash_matches_real_capacity_preparation(self):
        if not POWERSHELL:
            if os.name == "nt":
                self.fail("PowerShell is required for the Windows readback regression")
            self.skipTest("PowerShell is not installed on this host")
        tool = _load_capacity_tool()
        v = sys.modules["verify_image"]
        offset = v.TRANSFER_START_LBA * 512
        with tempfile.TemporaryDirectory() as root:
            image = Path(root) / "raw.img"
            _write_raw_image(v, image)
            with image.open("rb") as handle:
                self.assertEqual(v.verify_image_data(handle.read()), 0)
            capacity = image.stat().st_size + 2 * 1024 * 1024
            expected = _ps_hash("Get-ExpectedMediaRegionSha256", image, offset, capacity)
            raw_region = _ps_hash("Get-MediaRegionSha256", image, offset)
            self.assertNotEqual(expected, raw_region)  # MBR/GPT header really changes
            with image.open("r+b") as handle:
                tool.relocate_gpt(handle, capacity)
            self.assertEqual(_ps_hash("Get-MediaRegionSha256", image, offset), expected)
            with image.open("r+b") as handle:  # Windows rewrites TX_TRANSFER metadata
                handle.seek(offset + 600)
                handle.write(b"\x01")
            self.assertEqual(_ps_hash("Get-MediaRegionSha256", image, offset), expected)
            with image.open("r+b") as handle:  # COLD_VAULT changed after first boot
                handle.seek(v.VAULT_START_LBA * 512 + 4096)
                handle.write(b"\x01")
            self.assertNotEqual(_ps_hash("Get-MediaRegionSha256", image, offset), expected)
