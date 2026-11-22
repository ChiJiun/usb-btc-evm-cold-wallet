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
    "USB_UNPLUG", "POWER_INTERRUPTION", "RECOVERY",
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


def save(path: Path, data: dict) -> None:
    """Persist only to an explicitly selected pre-existing local directory."""
    if not path.parent.is_dir() or path.parent.is_symlink() or path.is_symlink():
        raise ValueError("Evidence directory must exist and must not be a symlink")
    # A local evidence directory is required: do not use a drive root or FAT/USB drive.
    if os.name == "nt":
        import ctypes
        root = path.resolve().anchor
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)
        if drive_type != 3:  # DRIVE_FIXED
            raise ValueError("Evidence path must be on a fixed local drive")
    fd, temp = tempfile.mkstemp(prefix=".acceptance-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(data, out, ensure_ascii=False, sort_keys=True, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def load(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Evidence file missing or symlink")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schemaVersion") != 1 or set(data.get("cases", {})) != set(CASES):
        raise ValueError("Unknown journal schema or incomplete matrix")
    return data


def start(args: argparse.Namespace) -> None:
    path = Path(args.file).absolute()
    if path.exists():
        raise ValueError("Journal already exists; refusing overwrite")
    if not HEX40.fullmatch(args.commit) or not HEX64.fullmatch(args.image_sha256):
        raise ValueError("Require exact 40-hex commit and 64-hex image SHA-256")
    data = {
        "schemaVersion": 1,
        "createdUtc": utc_now(),
        "updatedUtc": utc_now(),
        "imageCommit": args.commit.lower(),
        "imageSha256": args.image_sha256.lower(),
        "hardwareModel": clean(args.hardware, "hardware"),
        "firmware": clean(args.firmware, "firmware"),
        "partitions": [],
        "boots": [],
        "transactions": {},
        "cases": {name: {"status": "NOT TESTED", "observations": []} for name in CASES},
    }
    save(path, data)


def record(args: argparse.Namespace) -> None:
    path = Path(args.file).absolute()
    data = load(path)
    if args.case not in CASES or args.status not in STATUSES:
        raise ValueError("Unknown case or status")
    # Do not allow PASS without independent human-readable evidence reference.
    if args.status == "PASS" and not args.evidence:
        raise ValueError("PASS requires --evidence")
    evidence = clean(args.evidence, "evidence") if args.evidence else None
    note = clean(args.note, "note") if args.note else None
    case = data["cases"][args.case]
    case["status"] = args.status
    case["observations"].append({
        "atUtc": utc_now(), "status": args.status, "evidence": evidence,
        "note": note,
    })
    data["updatedUtc"] = utc_now()
    save(path, data)


def boot(args: argparse.Namespace) -> None:
    path = Path(args.file).absolute()
    data = load(path)
    data["boots"].append({
        "atUtc": utc_now(),
        "phase": args.phase,
        "durationSeconds": args.seconds,
        "evidence": clean(args.evidence, "evidence"),
    })
    data["updatedUtc"] = utc_now()
    save(path, data)


def transaction(args: argparse.Namespace) -> None:
    path = Path(args.file).absolute()
    data = load(path)
    if not TXHASH.fullmatch(args.txhash):
        raise ValueError("Transaction hash must be 32-byte hex (optional 0x)")
    data["transactions"][args.chain] = {
        "hash": args.txhash.lower(), "recordedUtc": utc_now(),
        "evidence": clean(args.evidence, "evidence"),
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
    init.set_defaults(fn=start)
    rec = sub.add_parser("record")
    rec.add_argument("--file", required=True)
    rec.add_argument("--case", choices=CASES, required=True)
    rec.add_argument("--status", choices=sorted(STATUSES), required=True)
    rec.add_argument("--evidence")
    rec.add_argument("--note")
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
