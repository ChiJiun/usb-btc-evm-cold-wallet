#!/usr/bin/env python3
"""Regenerate the Linux x86_64 hash lock used by GitHub Actions.

The project supports CPython 3.12 and 3.13 in CI.  pip-tools resolves the full
transitive dependency set; this script then records SHA-256 hashes for source
distributions plus wheels relevant to those two CPython versions on x86_64
Linux.  Keeping the platform scope narrow avoids a very large all-platform
lock while preserving pip --require-hashes verification in CI.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "requirements" / "ci.lock"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def resolve_pins(destination: Path) -> list[tuple[str, str]]:
    cmd = [
        sys.executable,
        "-m",
        "piptools",
        "compile",
        str(ROOT / "pyproject.toml"),
        "--extra",
        "dev",
        "--strip-extras",
        "--allow-unsafe",
        "--no-annotate",
        "--no-header",
        "--output-file",
        str(destination),
    ]
    subprocess.run(cmd, cwd=ROOT, check=True)

    pins: list[tuple[str, str]] = []
    for raw in destination.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise RuntimeError(f"unexpected unresolved requirement: {line}")
        name, version = line.split("==", 1)
        pins.append((name, version))
    return pins


def artifact_is_supported(filename: str, package_type: str) -> bool:
    filename = filename.lower()
    if package_type == "sdist":
        return True
    if package_type != "bdist_wheel":
        return False
    if filename.endswith("-none-any.whl"):
        return True
    if "x86_64" not in filename:
        return False
    return any(
        token in filename
        for token in ("cp312", "cp313", "abi3", "-py3-", "-py2.py3-")
    )


def hashes_for(name: str, version: str) -> list[str]:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    request = urllib.request.Request(url, headers={"User-Agent": "usb-cold-wallet-lock/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)

    selected: list[tuple[str, str]] = []
    for artifact in data.get("urls", []):
        if artifact_is_supported(artifact["filename"], artifact.get("packagetype", "")):
            selected.append((artifact["filename"], artifact["digests"]["sha256"]))

    if not selected:
        raise RuntimeError(f"no supported artifacts found for {name}=={version}")

    hashes: list[str] = []
    seen: set[str] = set()
    for _filename, digest in sorted(selected):
        if digest not in seen:
            hashes.append(digest)
            seen.add(digest)
    return hashes


def render_lock(pins: list[tuple[str, str]]) -> str:
    lines = [
        "# Hash-locked CI dependencies for CPython 3.12/3.13 on Linux x86_64.",
        "# Generated from pyproject.toml with pip-tools 7.7.0.",
        "# Hashes include relevant Linux x86_64/universal wheels plus sdist fallback.",
        "# Regenerate intentionally after dependency review; do not hand-edit versions.",
        "",
    ]
    for name, version in pins:
        hashes = hashes_for(name, version)
        lines.append(f"{name}=={version} \\")
        for index, digest in enumerate(hashes):
            continuation = " \\" if index < len(hashes) - 1 else ""
            lines.append(f"    --hash=sha256:{digest}{continuation}")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="usb-wallet-lock-") as tmpdir:
        pins = resolve_pins(Path(tmpdir) / "pins.txt")

    output.write_text(render_lock(pins), encoding="utf-8")
    print(f"wrote {output} ({len(pins)} pinned packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
