#!/usr/bin/env python3
"""Resolve the external Buildroot defconfig without requiring GNU make.

This is a static Kconfig validation aid. The real Buildroot make invocation is
still authoritative for a production image build.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import subprocess
import tempfile

import kconfiglib


ROOT = Path(__file__).resolve().parents[1]
BUILDROOT = ROOT / "build/buildroot"
EXTERNAL = ROOT / "buildroot-external"
DEFCONFIG = EXTERNAL / "configs/usb_wallet_x86_64_defconfig"


def _ensure_external_kconfig(out: Path) -> None:
    subprocess.run(
        [
            str(BUILDROOT / "support/scripts/br2-external"),
            "-d",
            str(out),
            str(EXTERNAL),
        ],
        cwd=BUILDROOT,
        check=True,
    )


def _kconfiglib_config(source: str) -> str:
    rows: list[str] = []
    for line in source.splitlines():
        if line.startswith("BR2_"):
            rows.append("CONFIG_" + line)
        elif line.startswith("# BR2_"):
            rows.append("# CONFIG_" + line[2:])
        else:
            rows.append(line)
    return "\n".join(rows) + "\n"


def main() -> int:
    if not (BUILDROOT / "Config.in").is_file():
        raise SystemExit("Buildroot source missing; run scripts/fetch_buildroot.sh first")

    with tempfile.TemporaryDirectory(prefix="usb-wallet-kconfig-") as tmp:
        out = Path(tmp)
        _ensure_external_kconfig(out)
        env = os.environ
        hostarch = platform.machine()
        env["srctree"] = str(BUILDROOT)
        env["BR2_BASE_DIR"] = str(out)
        env["BASE_DIR"] = str(out)
        env["BR2_EXTERNAL_USB_WALLET_PATH"] = str(EXTERNAL)
        env["HOSTARCH"] = hostarch
        env["BR2_HOSTARCH"] = hostarch
        env["BR2_VERSION_FULL"] = "2026.08.2"
        env["BR2_VERSION"] = "2026.08.2"
        # Static validation only: expose choices that require a modern host
        # compiler. The real Buildroot build checks the actual compiler.
        env["HOST_GCC_VERSION"] = "12 0"

        transformed = out / "defconfig.kconfiglib"
        transformed.write_text(_kconfiglib_config(DEFCONFIG.read_text()), encoding="utf-8")
        kconf = kconfiglib.Kconfig(str(BUILDROOT / "Config.in"), warn=False)
        kconf.load_config(str(transformed))

        expected_y = [
            "BR2_x86_64",
            "BR2_REPRODUCIBLE",
            "BR2_TOOLCHAIN_BUILDROOT",
            "BR2_TOOLCHAIN_BUILDROOT_GLIBC",
            "BR2_KERNEL_HEADERS_AS_KERNEL",
            "BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_6_12",
            "BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_DEVTMPFS",
            "BR2_TARGET_ROOTFS_INITRAMFS",
            "BR2_PACKAGE_PYTHON3",
            "BR2_PACKAGE_USB_WALLET_APP",
            "BR2_TARGET_GRUB2_X86_64_EFI",
        ]
        failed: list[str] = []
        for name in expected_y:
            symbol = kconf.syms.get(name)
            value = "<missing>" if symbol is None else symbol.str_value
            print(f"{name}={value}")
            if value != "y":
                failed.append(name)
        for name in ("BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_MDEV", "BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_EUDEV"):
            symbol = kconf.syms.get(name)
            if symbol is not None and symbol.str_value == "y":
                failed.append(name + " must be disabled")
        if failed:
            raise SystemExit("Kconfig selections did not resolve: " + ", ".join(failed))

    print("Buildroot Kconfig static resolution: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
