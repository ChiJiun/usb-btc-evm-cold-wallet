#!/usr/bin/env python3
"""Local-only, non-secret, cross-reboot physical acceptance journal.

Never opens a block device, alters a USB, signs transactions or broadcasts.
A separate trusted local evidence directory must be supplied explicitly.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

STATUSES = {"PASS", "FAIL", "BLOCKED", "NOT TESTED"}
CASES = (
    "WIN_USB_ID", "IMAGE_SHA256", "UEFI_BOOT", "GPT_LAYOUT",
    "VAULT_PERSISTENCE", "MOUNT_AUDIT", "NETWORK_ISOLATION",
    "BTC_REQUEST", "BTC_COLD_REVIEW", "BTC_SIGN", "BTC_IMPORT_VERIFY",
    "BTC_BROADCAST", "BTC_CONFIRM",
    "SEPOLIA_REQUEST", "SEPOLIA_COLD_REVIEW", "SEPOLIA_SIGN",
    "SEPOLIA_IMPORT_VERIFY", "SEPOLIA_BROADCAST", "SEPOLIA_RECEIPT",
    "REPLACE_REQUEST", "REPLACE_RESPONSE", "REPLAY_REQUEST",
    "REPLAY_RESPONSE", "WRONG_CHAIN", "WRONG_ACCOUNT",
    "USB_UNPLUG", "USB_REPLUG", "WRONG_DISK", "MALFORMED_TRANSFER",
    "POWER_INTERRUPTION", "RECOVERY",
)
HEX40 = re.compile(r"^[a-fA-F0-9]{40}$")
HEX64 = re.compile(r"^[a-fA-F0-9]{64}$")
TXHASH = re.compile(r"^(?:0x)?[a-fA-F0-9]{64}$")
SAFE = re.compile(r"^[A-Za-z0-9 _.,:/+@()#=-]{1,300}$")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def clean(value: str, name: str, max_length: int = 300) -> str:
    if not value or len(value) > max_length or not SAFE.fullmatch(value):
        raise ValueError(f"{name}: invalid public metadata; no secrets or arbitrary text allowed")
    return value



MAX_JOURNAL_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_BYTES = 100 * 1024 * 1024
MAX_EVIDENCE_AGE = dt.timedelta(days=30)
CLOCK_SKEW = dt.timedelta(minutes=5)


def _utc(value: str) -> dt.datetime:
    when = dt.datetime.fromisoformat(value)
    if when.tzinfo is None:
        raise ValueError("Evidence timestamp must include UTC offset")
    return when.astimezone(dt.timezone.utc)


def _safe_directory(parent: Path) -> None:
    if not parent.is_dir():
        raise ValueError("Evidence directory does not exist")
    for candidate in (parent, *parent.parents):
        if candidate.is_symlink() or (
            hasattr(candidate, "is_junction") and candidate.is_junction()
        ):
            raise ValueError("Symlink/junction in evidence directory ancestry")
    if os.name == "nt":
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(str(parent.resolve().anchor)) != 3:
            raise ValueError("Evidence directory must be on an internal fixed drive")


def _read_regular(path: Path, limit: int) -> bytes:
    _safe_directory(path.parent)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or unsafe regular evidence file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        import stat
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_size <= 0 or meta.st_size > limit:
            raise ValueError("Empty, oversized or non-regular evidence file")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != meta.st_size or len(data) > limit:
            raise ValueError("Truncated or changed evidence file")
        after = os.stat(path, follow_symlinks=False)
        if (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise ValueError("Evidence replaced during read")
        return bytes(data)
    finally:
        os.close(fd)


def save(path: Path, data: dict, *, create: bool = False) -> None:
    """Atomic update of a bounded journal on a pre-existing fixed local directory."""
    _safe_directory(path.parent)
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise ValueError("Journal path must not be a symlink/junction")
    if create and path.exists():
        raise ValueError("Journal already exists; refusing overwrite")
    fd, temp = tempfile.mkstemp(prefix=".acceptance-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(data, out, ensure_ascii=False, sort_keys=True, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        if os.stat(temp).st_size > MAX_JOURNAL_BYTES:
            raise ValueError("Journal too large")
        if create:
            # Hard-linking a completed fsynced file publishes it atomically
            # without replacing a concurrently-created journal.
            os.link(temp, path)
        else:
            os.replace(temp, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def verify_evidence(journal_path: Path, observation: dict) -> None:
    if (
        not isinstance(observation, dict)
        or not observation.get("command")
        or observation.get("exitCode") != 0
        or observation.get("sourceKind") != "physical-hardware"
        or observation.get("operatorVerified") is not True
        or not observation.get("note")
    ):
        raise ValueError("Physical PASS requires executed command, exit=0 and manual observation")
    reference = clean(str(observation.get("evidence", "")), "evidence")
    if Path(reference).name != reference or reference.startswith("."):
        raise ValueError("Evidence must be a non-hidden local basename")
    artifact = journal_path.parent / reference
    data = _read_regular(artifact, MAX_EVIDENCE_BYTES)
    if hashlib.sha256(data).hexdigest() != observation.get("evidenceSha256"):
        raise ValueError("Evidence hash mismatch")
    timestamp = _utc(str(observation.get("atUtc", "")))
    now = dt.datetime.now(dt.timezone.utc)
    age = now - timestamp
    if age < -CLOCK_SKEW or age > MAX_EVIDENCE_AGE:
        raise ValueError("Stale or future PASS evidence")
    mtime = dt.datetime.fromtimestamp(artifact.stat().st_mtime, dt.timezone.utc)
    if timestamp - mtime > MAX_EVIDENCE_AGE or mtime - timestamp > CLOCK_SKEW:
        raise ValueError("Evidence artifact timestamp inconsistent with observation")
    # For hardware identity/layout PASS, a plain text claim is insufficient:
    # the inventory must have verified exact image, layout and media readback.
    if observation.get("case") in ("WIN_USB_ID", "GPT_LAYOUT"):
        try:
            report = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Hardware case requires machine-readable inventory evidence") from exc
        if (
            report.get("result") != "INVENTORY_VERIFIED"
            or report.get("physicalAcceptance") != "NOT TESTED"
            or not all(report.get(k) is True for k in (
                "imageFileVerified", "deviceLayoutVerified", "writtenMediaVerified"
            ))
            or report.get("exactImageCommit") != observation.get("imageCommit")
            or report.get("imageSha256") != observation.get("imageSha256")
        ):
            raise ValueError("Hardware case evidence does not bind verified media and image")
        snapshot = report.get("observed")
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("disk"), dict):
            raise ValueError("Physical inventory parent disk/drive evidence missing")
        disk = snapshot["disk"]
        partitions = snapshot.get("partitions")
        if (
            disk.get("busType") != "USB"
            or disk.get("partitionStyle") != "GPT"
            or not isinstance(disk.get("diskNumber"), int)
            or disk.get("diskGuid") is None
            or not isinstance(partitions, list) or len(partitions) != 3
            or not isinstance(snapshot.get("driveLetter"), str)
            or len(snapshot["driveLetter"]) != 1
            or report.get("mediaReadbackSha256") != observation["imageSha256"]
        ):
            raise ValueError("Physical media inventory/readback provenance incomplete")
        part_ids = set()
        expected_labels = ("USBCOLD_EFI", "COLD_VAULT", "TX_TRANSFER")
        expected_fs = ("FAT", "FAT", "FAT32")
        for index, partition in enumerate(partitions, 1):
            if not isinstance(partition, dict):
                raise ValueError("Corrupt physical partition evidence")
            part_id = str(partition.get("partitionGuid", "")).strip("{}").lower()
            if (
                not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", part_id)
                or part_id in part_ids
                or partition.get("diskNumber") != disk["diskNumber"]
                or partition.get("partitionNumber") != index
                or partition.get("label") != expected_labels[index - 1]
                or partition.get("filesystem") != expected_fs[index - 1]
                or (index == 3 and partition.get("driveLetter") != snapshot["driveLetter"])
                or (index < 3 and partition.get("driveLetter"))
            ):
                raise ValueError("Physical partition/drive ancestry evidence inconsistent")
            part_ids.add(part_id)
        collected = _utc(str(report.get("collectedAtUtc", "")))
        if not (-CLOCK_SKEW <= dt.datetime.now(dt.timezone.utc) - collected <= dt.timedelta(hours=1)):
            raise ValueError("Physical inventory snapshot stale; rediscover after replug")

    elif observation.get("case") == "IMAGE_SHA256":
        try:
            report = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Image case requires machine-readable inventory evidence") from exc
        if (
            report.get("imageFileVerified") is not True
            or report.get("exactImageCommit") != observation.get("imageCommit")
            or report.get("imageSha256") != observation.get("imageSha256")
        ):
            raise ValueError("Unverified or unbound host image hash")




def _aux_evidence(path: Path, reference: str) -> str:
    reference = clean(reference, "evidence")
    if Path(reference).name != reference or reference.startswith("."):
        raise ValueError("Evidence must be a local basename")
    return hashlib.sha256(_read_regular(path.parent / reference, MAX_EVIDENCE_BYTES)).hexdigest()


def _verify_aux(path: Path, entry: dict, parent: dict, time_key: str) -> None:
    if not isinstance(entry, dict):
        raise ValueError("Invalid auxiliary evidence")
    if (entry.get("imageCommit"), entry.get("imageSha256"), entry.get("deviceIdentity")) != (
        parent["imageCommit"], parent["imageSha256"], parent["deviceIdentity"]
    ):
        raise ValueError("Boot/transaction provenance mismatch")
    timestamp = _utc(str(entry.get(time_key, "")))
    if not (-CLOCK_SKEW <= dt.datetime.now(dt.timezone.utc) - timestamp <= MAX_EVIDENCE_AGE):
        raise ValueError("Stale boot/transaction evidence")
    if entry.get("evidenceSha256") != _aux_evidence(path, str(entry.get("evidence", ""))):
        raise ValueError("Boot/transaction evidence hash mismatch")


def load(path: Path) -> dict:
    data = json.loads(_read_regular(path, MAX_JOURNAL_BYTES).decode("utf-8"))
    if not isinstance(data, dict) or data.get("schemaVersion") != 2 or not isinstance(data.get("cases"), dict):
        raise ValueError("Unknown journal schema")
    if set(data["cases"]) != set(CASES) or not HEX40.fullmatch(str(data.get("imageCommit", ""))) or not HEX64.fullmatch(str(data.get("imageSha256", ""))):
        raise ValueError("Invalid image binding or incomplete matrix")
    clean(str(data.get("deviceIdentity", "")), "deviceIdentity")
    for name, case in data["cases"].items():
        if not isinstance(case, dict) or case.get("status") not in STATUSES or not isinstance(case.get("observations"), list):
            raise ValueError(f"Corrupt case {name}")
        if case["observations"] and case["status"] != case["observations"][-1].get("status"):
            raise ValueError(f"Case status/observation mismatch for {name}")
        if case["status"] == "PASS" and not case["observations"]:
            raise ValueError(f"Unaudited PASS for {name}")
        for entry in case["observations"]:
            if not isinstance(entry, dict) or entry.get("status") not in STATUSES:
                raise ValueError(f"Invalid observation for {name}")
            if entry.get("imageCommit") != data["imageCommit"] or entry.get("imageSha256") != data["imageSha256"] or entry.get("deviceIdentity") != data["deviceIdentity"]:
                raise ValueError(f"Observation provenance mismatch for {name}")
            if entry.get("status") == "PASS":
                if entry.get("case") != name:
                    raise ValueError("PASS case identity mismatch")
                verify_evidence(path, entry)
    if not isinstance(data.get("boots"), list) or not isinstance(data.get("transactions"), dict):
        raise ValueError("Corrupted boot/transaction evidence")
    for entry in data["boots"]:
        _verify_aux(path, entry, data, "atUtc")
        if entry.get("phase") not in ("WINDOWS_TO_USB", "USB_TO_WINDOWS") or not (0 <= entry.get("durationSeconds", -1) <= 86400):
            raise ValueError("Invalid boot phase/duration")
    for chain, entry in data["transactions"].items():
        if chain not in ("btc-testnet", "sepolia") or not TXHASH.fullmatch(str(entry.get("hash", ""))):
            raise ValueError("Invalid transaction evidence")
        _verify_aux(path, entry, data, "recordedUtc")
    return data


def start(args: argparse.Namespace) -> None:
    path = Path(args.file).absolute()
    if path.exists():
        raise ValueError("Journal already exists; refusing overwrite")
    if not HEX40.fullmatch(args.commit) or not HEX64.fullmatch(args.image_sha256):
        raise ValueError("Require exact 40-hex commit and 64-hex image SHA-256")
    data = {
        "schemaVersion": 2,
        "createdUtc": utc_now(),
        "updatedUtc": utc_now(),
        "imageCommit": args.commit.lower(),
        "imageSha256": args.image_sha256.lower(),
        "hardwareModel": clean(args.hardware, "hardware"),
        "deviceIdentity": clean(args.device_identity, "deviceIdentity"),
        "firmware": clean(args.firmware, "firmware"),
        "partitions": [],
        "boots": [],
        "transactions": {},
        "cases": {name: {"status": "NOT TESTED", "observations": []} for name in CASES},
    }
    save(path, data, create=True)


def record(args: argparse.Namespace) -> None:
    path = Path(args.file).absolute()
    data = load(path)
    if args.case not in CASES or args.status not in STATUSES:
        raise ValueError("Unknown case or status")
    if args.status == "PASS" and (
        not args.evidence or not args.command or not args.note
        or getattr(args, "exit_code", None) != 0
        or not getattr(args, "operator_verified", False)
    ):
        raise ValueError("PASS needs evidence, command, successful exit code and operator observation")
    evidence = clean(args.evidence, "evidence") if args.evidence else None
    note = clean(args.note, "note") if args.note else None
    observation = {
        "case": args.case, "atUtc": utc_now(), "status": args.status,
        "evidence": evidence, "note": note,
        "command": clean(args.command, "command") if args.command else None,
        "exitCode": getattr(args, "exit_code", None),
        "operatorVerified": bool(getattr(args, "operator_verified", False)),
        "sourceKind": "physical-hardware",
        "imageCommit": data["imageCommit"], "imageSha256": data["imageSha256"],
        "deviceIdentity": data["deviceIdentity"],
    }
    if args.status == "PASS":
        if Path(evidence).name != evidence or evidence.startswith("."):
            raise ValueError("Evidence must be a non-hidden local basename")
        observation["evidenceSha256"] = hashlib.sha256(
            _read_regular(path.parent / evidence, MAX_EVIDENCE_BYTES)
        ).hexdigest()
        verify_evidence(path, observation)
    case = data["cases"][args.case]
    case["status"] = args.status
    case["observations"].append(observation)
    data["updatedUtc"] = utc_now()
    save(path, data)


def boot(args: argparse.Namespace) -> None:
    path = Path(args.file).absolute()
    data = load(path)
    if args.phase not in ("WINDOWS_TO_USB", "USB_TO_WINDOWS") or not 0 <= args.seconds <= 86400:
        raise ValueError("Invalid boot evidence")
    data["boots"].append({
        "atUtc": utc_now(), "phase": args.phase, "durationSeconds": args.seconds,
        "evidence": clean(args.evidence, "evidence"),
        "evidenceSha256": _aux_evidence(path, args.evidence),
        "imageCommit": data["imageCommit"], "imageSha256": data["imageSha256"],
        "deviceIdentity": data["deviceIdentity"],
    })
    data["updatedUtc"] = utc_now()
    save(path, data)


def transaction(args: argparse.Namespace) -> None:
    path = Path(args.file).absolute()
    data = load(path)
    if args.chain not in ("btc-testnet", "sepolia") or not TXHASH.fullmatch(args.txhash):
        raise ValueError("Invalid transaction chain or hash")
    data["transactions"][args.chain] = {
        "hash": args.txhash.lower(), "recordedUtc": utc_now(),
        "evidence": clean(args.evidence, "evidence"),
        "evidenceSha256": _aux_evidence(path, args.evidence),
        "imageCommit": data["imageCommit"], "imageSha256": data["imageSha256"],
        "deviceIdentity": data["deviceIdentity"],
    }
    data["updatedUtc"] = utc_now()
    save(path, data)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--file", required=True)
    init.add_argument("--commit", required=True)
    init.add_argument("--image-sha256", required=True)
    init.add_argument("--hardware", required=True)
    init.add_argument("--firmware", required=True)
    init.add_argument("--device-identity", required=True)
    init.set_defaults(fn=start)
    rec = sub.add_parser("record")
    rec.add_argument("--file", required=True)
    rec.add_argument("--case", choices=CASES, required=True)
    rec.add_argument("--status", choices=sorted(STATUSES), required=True)
    rec.add_argument("--evidence")
    rec.add_argument("--note")
    rec.add_argument("--command")
    rec.add_argument("--exit-code", type=int)
    rec.add_argument("--operator-verified", action="store_true")
    rec.set_defaults(fn=record)
    b = sub.add_parser("boot")
    b.add_argument("--file", required=True)
    b.add_argument("--phase", choices=["WINDOWS_TO_USB", "USB_TO_WINDOWS"], required=True)
    b.add_argument("--seconds", type=int, required=True)
    b.add_argument("--evidence", required=True)
    b.set_defaults(fn=boot)
    t = sub.add_parser("tx")
    t.add_argument("--file", required=True)
    t.add_argument("--chain", choices=["btc-testnet", "sepolia"], required=True)
    t.add_argument("--txhash", required=True)
    t.add_argument("--evidence", required=True)
    t.set_defaults(fn=transaction)
    s = sub.add_parser("show")
    s.add_argument("--file", required=True)
    s.set_defaults(fn=lambda args: print(json.dumps(load(Path(args.file)), indent=2, ensure_ascii=False)))
    args = parser.parse_args(argv)
    if hasattr(args, "seconds") and not (0 <= args.seconds <= 86400):
        parser.error("duration out of range")
    try:
        args.fn(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(2, f"BLOCKED: {exc}\n")


if __name__ == "__main__":
    main()
