"""Fail closed if the real Windows EXE contains offline signing modules.

PyInstaller's recursive brief viewer inspects modules inside PYZ (not just
entrypoint source code). The output is an archive listing, not executable code.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Public-only components are the sole allowed local package runtime modules.
ALLOW = {
    "usb_cold_wallet",
    "usb_cold_wallet.companion_portable",
    "usb_cold_wallet.companion_web",
    "usb_cold_wallet.companion_core",
    "usb_cold_wallet.companion_btc",
}
DENY = {
    "vault", "keys", "btc", "evm", "recovery", "cli", "gui", "gui_qr_bridge",
    "policy", "review", "signer_session", "qr_cli", "qr_workflow", "qr_session",
    "keystone_public", "exchange",
}


def examine_listing(listing: str) -> set[str]:
    # Brief viewer may print Python literals or multiple archive sections.
    # Extract local packages from either dotted PYZ or slash-separated paths.
    pattern = r"usb_cold_wallet(?:[./\\][a-zA-Z_][a-zA-Z_0-9]*)*"
    found = {
        re.sub(r"[/\\]", ".", m.group())
        for m in re.finditer(pattern, listing)
    }
    required = ALLOW - {"usb_cold_wallet"}
    if not required <= found:
        raise AssertionError(f"Missing watch-only module(s): {sorted(required - found)}")
    unexpected = found - ALLOW
    if unexpected:
        raise AssertionError(f"Offline or unknown module(s) in packaged EXE: {sorted(unexpected)}")
    if any("usb_cold_wallet." + forbidden in found for forbidden in DENY):
        raise AssertionError("Offline signer modules leaked into Windows EXE")
    return found


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_windows_companion_archive.py PATH_TO_EXE")
    exe = Path(sys.argv[1]).resolve(strict=True)
    if exe.suffix.lower() != ".exe":
        raise ValueError("Expected real Windows EXE")
    cmd = [
        sys.executable, "-m", "PyInstaller.utils.cliutils.archive_viewer",
        "--brief", "--recursive", str(exe),
    ]
    output = subprocess.run(cmd, capture_output=True, text=True, check=True,
                            timeout=60)
    found = examine_listing(output.stdout)
    print("Windows EXE archive contains only approved package modules:", ", ".join(sorted(found)))


if __name__ == "__main__":
    main()
