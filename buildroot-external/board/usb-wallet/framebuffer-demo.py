#!/usr/bin/python3
"""Public test-vector framebuffer acceptance demo.

The demo uses one fixed Sepolia ReviewPlan produced by the existing backend.
It does not load user wallet material and it never invokes signing.
"""
from __future__ import annotations

import os
from pathlib import Path
import resource

from usb_cold_wallet.exchange import package
from usb_cold_wallet.framebuffer_poc import run_vt
from usb_cold_wallet.gui import runtime_audit
from usb_cold_wallet.keys import root_from_mnemonic
from usb_cold_wallet.recovery import PUBLIC_TEST_MNEMONIC
from usb_cold_wallet.review import build_review_plan

FONT = Path("/usr/share/usb-cold-wallet/font8x16.psf")
SERIAL = Path("/dev/ttyS0")


def _serial(message: str) -> None:
    fd = None
    try:
        fd = os.open(SERIAL, os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY)
        os.write(fd, (message + "\n").encode("ascii"))
    except OSError:
        pass
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _audit() -> bool:
    return runtime_audit()[0]


def _plan():
    tx = {
        "type": 2,
        "chainId": 11155111,
        "nonce": 7,
        "to": "0x000000000000000000000000000000000000dEaD",
        "value": 1_000_000_000_000,
        "gas": 21_000,
        "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000,
        "data": "0x",
        "accessList": [],
    }
    root = root_from_mnemonic(PUBLIC_TEST_MNEMONIC)
    return build_review_plan(package("evm-request", tx), root, "evm-request")


def main() -> int:
    os.environ["HISTFILE"] = "/dev/null"
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    ok, _ = runtime_audit()
    if not ok:
        _serial("USB_WALLET_FB_POC_BLOCKED audit=failed")
        return 2

    plan = _plan()

    def ready() -> None:
        boot_ms = round(float(Path("/proc/uptime").read_text(encoding="ascii").split()[0]) * 1000)
        rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        _serial(f"USB_WALLET_FB_POC_READY boot_ms={boot_ms} rss_kb={rss_kb}")

    try:
        intent = run_vt(plan, FONT, audit=_audit, on_ready=ready)
    except Exception as exc:
        _serial("USB_WALLET_FB_POC_ERROR class=" + type(exc).__name__)
        return 2

    _serial(
        "USB_WALLET_FB_POC_INTENT "
        f"reviewed={1 if intent.reviewed else 0} reason={intent.reason}"
    )
    return 0 if intent.reviewed else 1


if __name__ == "__main__":
    raise SystemExit(main())
