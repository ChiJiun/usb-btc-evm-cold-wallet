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
