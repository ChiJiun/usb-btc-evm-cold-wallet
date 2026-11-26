#!/usr/bin/env python3
"""Real QEMU guest boot with delayed USB hotplug and absent-media timeout.

Direct kernel boot is intentional: UEFI itself needs the USB to load the
kernel. The normal OVMF image boot remains a separate required check.
"""
from pathlib import Path
import json
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT / "build/output/images"


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def wait_for(log, process, predicate, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = log.read_text(errors="replace") if log.exists() else ""
        if predicate(data):
            return data
        if process.poll() is not None:
            raise RuntimeError("QEMU exited before expected guest evidence")
        time.sleep(0.2)
    raise RuntimeError("QEMU guest evidence deadline expired")


def hotplug(path, bus):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10)
        sock.connect(str(path))
        with sock.makefile("rwb") as stream:
            json.loads(stream.readline())
            for command in (
                {"execute": "qmp_capabilities"},
                {"execute": "device_add", "arguments": {
                    "driver": "usb-storage", "bus": bus,
                    "drive": "walletdisk", "id": "delayed-usb",
                }},
            ):
                stream.write(json.dumps(command).encode() + b"\n")
                stream.flush()
                while True:
                    response = json.loads(stream.readline())
                    if "error" in response:
                        raise RuntimeError("QMP command failed: " + str(response["error"]))
                    if "return" in response:
                        break


def exercise(attach, *, delay=5, controller='qemu-xhci', bus='xhci'):
    with tempfile.TemporaryDirectory(prefix="wallet-delayed-") as directory:
        temp = Path(directory)
        serial = temp / "serial.log"
        qmp = temp / "qmp.sock"
        with (temp / "qemu.log").open("wb") as qemu_log:
            command = [
                "qemu-system-x86_64", "-machine", "q35,accel=tcg", "-cpu", "max",
                "-smp", "2", "-m", "1536", "-display", "none", "-monitor", "none",
                "-net", "none", "-no-reboot", "-serial", f"file:{serial}",
                "-qmp", f"unix:{qmp},server=on,wait=off", "-device", f"{controller},id={bus}",
                "-kernel", str(IMAGES / "bzImage"), "-append",
                "console=tty1 console=ttyS0,115200 loglevel=7 rdinit=/sbin/init",
                "-drive", f"if=none,id=walletdisk,format=raw,snapshot=on,file={IMAGES / 'usb-cold-wallet.img'}",
            ]
            process = subprocess.Popen(command, stdout=qemu_log, stderr=qemu_log)
            try:
                wait_for(serial, process, lambda data: "USB_WALLET_MEDIA_WAIT" in data, 180)
                if attach:
                    time.sleep(delay)
                    before = serial.read_text(errors="replace")
                    require("USB_WALLET_UEFI_AUDIT_" not in before, "guest decided before hotplug")
                    hotplug(qmp, f'{bus}.0')
                data = wait_for(serial, process, lambda log: (
                    "USB_WALLET_UEFI_AUDIT_LOCKDOWN" in log or (
                        "USB_WALLET_UEFI_AUDIT_OK" in log and "USB_WALLET_CONSOLE_READY" in log
                    )
                ), 100)
                if attach:
                    require("USB_WALLET_UEFI_AUDIT_LOCKDOWN" not in data, "missing or contradictory guest evidence")
                    require("USB_WALLET_UEFI_AUDIT_OK" in data, "missing or contradictory guest evidence")
                    require("PASS: USB readiness: two complete stable scans" in data, "missing or contradictory guest evidence")
                    require("PASS: COLD_VAULT restrictive mount options verified" in data, "missing or contradictory guest evidence")
                    require("PASS: /proc/net absent" in data, "missing or contradictory guest evidence")
                    require("PASS: no active swap" in data, "missing or contradictory guest evidence")
                    require("PASS: root filesystem is RAM-backed" in data, "missing or contradictory guest evidence")
                    print("PASS: real kernel boot accepted delayed USB and audited mount")
                else:
                    require("USB_WALLET_UEFI_AUDIT_OK" not in data, "missing or contradictory guest evidence")
                    require("USB_WALLET_UEFI_AUDIT_LOCKDOWN" in data, "missing or contradictory guest evidence")
                    require("USB readiness: enumeration or I/O deadline expired" in data, "missing or contradictory guest evidence")
                    print("PASS: real kernel boot timed out without USB and locked down")
            except BaseException:
                if serial.exists():
                    print(serial.read_text(errors="replace")[-32768:])
                print((temp / "qemu.log").read_text(errors="replace")[-8192:])
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    exercise(True)
    exercise(True, delay=15, controller="usb-ehci", bus="ehci")
    exercise(True, delay=30)
    exercise(False)
