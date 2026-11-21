"""Produce and verify an offline-only wheel from the combined development wheel.

The default wheel supports the explicitly connected Online Companion. The
bootable offline image MUST install only the output of this build step.
Fail closed if the expected module layout changes: an added module requires
a deliberate review and manifest update before inclusion in the cold TCB.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
from pathlib import Path
import re
import zipfile

PACKAGE = "usb_cold_wallet/"
ALLOWED_OFFLINE_MODULES = frozenset({
    "__init__.py", "btc.py", "cli.py", "evm.py", "exchange.py",
    "keys.py", "recovery.py", "vault.py", "policy.py", "gui.py", "review.py",
    "signer_session.py",
})
ONLINE_MODULES = frozenset({"companion_core.py", "companion_btc.py", "companion_web.py"})
ONLINE_ENTRY = re.compile(r"^\s*usb-cold-companion\s*=", re.MULTILINE)


def _offline_files(entries: dict[str, bytes], *, from_combined: bool) -> dict[str, bytes]:
    names = tuple(entries)
    if len(names) != len(set(names)) or any(name.endswith("/") for name in names):
        raise ValueError("Duplicate or non-file wheel members")
    modules = {name[len(PACKAGE):] for name in names
               if name.startswith(PACKAGE) and name.endswith(".py") and "/" not in name[len(PACKAGE):]}
    unknown = modules - ALLOWED_OFFLINE_MODULES - ONLINE_MODULES
    if unknown or not ALLOWED_OFFLINE_MODULES <= modules:
        raise ValueError(f"Unexpected offline wallet Python modules: {sorted(unknown)}")
    unexpected_package_files = {
        name for name in names if name.startswith(PACKAGE)
        and name[len(PACKAGE):] not in ALLOWED_OFFLINE_MODULES | ONLINE_MODULES
        and not name[len(PACKAGE):].startswith("companion_static/")
    }
    if unexpected_package_files:
        raise ValueError(f"Unreviewed code or assets in cold package: {sorted(unexpected_package_files)}")
    if from_combined and not ONLINE_MODULES <= modules:
        raise ValueError("Input must contain the full connected Companion before stripping")
    records = [name for name in names if name.endswith(".dist-info/RECORD")]
    entries_meta = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
    if len(records) != 1 or len(entries_meta) != 1:
        raise ValueError("Expected exactly one wheel RECORD and entry_points file")

    result = {}
    for name, data in entries.items():
        relative = name[len(PACKAGE):] if name.startswith(PACKAGE) else ""
        if relative.startswith("companion_static/") or relative in ONLINE_MODULES:
            continue
        if name == entries_meta[0]:
            text = data.decode("utf-8")
            if from_combined and not ONLINE_ENTRY.search(text):
                raise ValueError("Connected Companion console command missing")
            text = "\n".join(line for line in text.splitlines()
                              if not ONLINE_ENTRY.match(line)) + "\n"
            if ONLINE_ENTRY.search(text):
                raise ValueError("Online entry point remains")
            if "usb-cold-wallet =" not in text:
                raise ValueError("Offline signing CLI entry point is missing")
            data = text.encode("utf-8")
        result[name] = data
    if any("companion" in name.lower() for name in result if name.startswith(PACKAGE)):
        raise ValueError("Online network modules leaked into offline image")
    return result


def _record(entries: dict[str, bytes], record_path: str) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    for name, data in entries.items():
        if name == record_path:
            continue
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        writer.writerow((name, "sha256=" + digest, str(len(data))))
    writer.writerow((record_path, "", ""))
    return buffer.getvalue().encode("utf-8")


def build_offline_wheel(source: Path, output_dir: Path) -> Path:
    if not source.is_file() or source.suffix != ".whl":
        raise ValueError("Expected an existing wheel archive")
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / source.name
    if source.resolve() == target.resolve():
        raise ValueError("Refusing to overwrite the combined wheel")
    with zipfile.ZipFile(source) as archive:
        infos = archive.infolist()
        if len({item.filename for item in infos}) != len(infos):
            raise ValueError("Duplicate archive members")
        entries = {item.filename: archive.read(item.filename) for item in infos}
    result = _offline_files(entries, from_combined=True)
    record_path = next(name for name in result if name.endswith(".dist-info/RECORD"))
    result[record_path] = _record(result, record_path)
    with zipfile.ZipFile(target, "w") as archive:
        for item in infos:
            if item.filename in result:
                archive.writestr(item, result[item.filename])
    verify_offline_wheel(target)
    return target


def verify_offline_wheel(source: Path) -> None:
    with zipfile.ZipFile(source) as archive:
        entries = {item.filename: archive.read(item.filename) for item in archive.infolist()}
    validated = _offline_files(entries, from_combined=False)
    if set(entries) != set(validated) or any(entries[name] != value for name, value in validated.items()):
        raise ValueError("Offline wheel still includes network components")
    record_path = next(name for name in entries if name.endswith(".dist-info/RECORD"))
    if entries[record_path] != _record(entries, record_path):
        raise ValueError("Offline wheel RECORD is inconsistent")


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a verified network-free offline signing wheel")
    parser.add_argument("source", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    result = build_offline_wheel(args.source, args.output_dir)
    print(f"Verified offline-only wheel: {result}")


if __name__ == "__main__":
    main()
