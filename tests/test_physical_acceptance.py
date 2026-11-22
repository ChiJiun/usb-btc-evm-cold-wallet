"""Unit tests for non-destructive physical acceptance journal."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "physical_acceptance.py"
SPEC = importlib.util.spec_from_file_location("physical_acceptance", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class TestPhysicalAcceptance(unittest.TestCase):
    def test_initial_not_tested_and_no_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "result.json"
            from argparse import Namespace
            arguments = Namespace(file=str(file), commit="a" * 40, image_sha256="b" * 64,
                                  hardware="Test UEFI PC", firmware="UEFI 1.0", device_identity="usb-test-001")
            module.start(arguments)
            data = module.load(file)
            self.assertEqual(len(data["cases"]), len(module.CASES))
            self.assertTrue(all(x["status"] == "NOT TESTED" for x in data["cases"].values()))
            with self.assertRaises(ValueError):
                module.start(arguments)

    def test_pass_needs_evidence_and_rejects_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "result.json"
            from argparse import Namespace
            module.start(Namespace(file=str(file), commit="a" * 40, image_sha256="b" * 64,
                                   hardware="test machine", firmware="UEFI", device_identity="usb-test-001"))
            with self.assertRaises(ValueError):
                module.record(Namespace(file=str(file), case="UEFI_BOOT", status="PASS",
                                        evidence=None, note=None, command=None))
            with self.assertRaises(ValueError):
                module.record(Namespace(file=str(file), case="UEFI_BOOT", status="PASS",
                                        evidence="mnemonic; secret", note=None, command="manual UEFI test"))
            (Path(directory) / "boot-redacted.txt").write_text("Public boot evidence", encoding="utf-8")
            module.record(Namespace(file=str(file), case="UEFI_BOOT", status="PASS",
                                    evidence="boot-redacted.txt", note="UEFI boot observed", command="manual UEFI test"))
            self.assertEqual(module.load(file)["cases"]["UEFI_BOOT"]["status"], "PASS")
            self.assertEqual(len(module.load(file)["cases"]["UEFI_BOOT"]["observations"]), 1)

    def test_unsupported_status_and_bad_txhash(self) -> None:
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "result.json"
            module.start(Namespace(file=str(file), commit="a" * 40, image_sha256="b" * 64,
                                   hardware="test machine", firmware="UEFI", device_identity="usb-test-001"))
            with self.assertRaises(ValueError):
                module.record(Namespace(file=str(file), case="UEFI_BOOT", status="SUCCESS",
                                        evidence="log.txt", note=None, command=None))
            with self.assertRaises(ValueError):
                module.transaction(Namespace(file=str(file), chain="sepolia",
                                             txhash="invalid", evidence="log.txt"))
            module.transaction(Namespace(file=str(file), chain="sepolia",
                                         txhash="0x" + "b" * 64, evidence="tx-redacted.txt"))
            self.assertEqual(module.load(file)["transactions"]["sepolia"]["hash"], "0x" + "b" * 64)

    def test_pass_artifact_is_required_and_tampering_fails_closed(self) -> None:
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "result.json"
            module.start(Namespace(file=str(file), commit="a" * 40, image_sha256="b" * 64,
                                   hardware="test machine", firmware="UEFI", device_identity="usb-test-001"))
            with self.assertRaises(ValueError):
                module.record(Namespace(file=str(file), case="UEFI_BOOT", status="PASS",
                                        evidence="missing.txt", note=None, command="manual UEFI test"))
            evidence = Path(directory) / "boot.txt"
            evidence.write_text("boot output", encoding="utf-8")
            module.record(Namespace(file=str(file), case="UEFI_BOOT", status="PASS",
                                    evidence="boot.txt", note=None, command="manual UEFI test"))
            assert module.load(file)["cases"]["UEFI_BOOT"]["status"] == "PASS"
            evidence.write_text("tampered", encoding="utf-8")
            with self.assertRaises(ValueError):
                module.load(file)

    def test_injected_pass_rejected(self) -> None:
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "result.json"
            module.start(Namespace(file=str(file), commit="a" * 40, image_sha256="b" * 64,
                                   hardware="test machine", firmware="UEFI", device_identity="usb-test-001"))
            payload = json.loads(file.read_text(encoding="utf-8"))
            payload["cases"]["UEFI_BOOT"]["status"] = "PASS"
            file.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValueError):
                module.load(file)

    def test_symlink_evidence_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            other = folder / "other"
            other.mkdir()
            link = folder / "link"
            try:
                link.symlink_to(other, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with self.assertRaises(ValueError):
                module.save(link / "result.json", {"schemaVersion": 1})


if __name__ == "__main__":
    unittest.main()
