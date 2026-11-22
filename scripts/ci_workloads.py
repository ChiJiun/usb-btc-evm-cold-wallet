"""Conservative dependency-aware GitHub Actions workload selection.

The image installs only ALLOWED_OFFLINE_MODULES (install_target_python.py).
Any unknown executable/build path falls back to every validation workload.
This file is a security gate: change it with adversarial tests and review.
"""
from __future__ import annotations

from dataclasses import dataclass

# Mirrored from scripts/build_offline_wheel.py. Drift must fail closed below.
OFFLINE_MODULES = frozenset((
    "__init__.py", "appliance.py", "btc.py", "cli.py", "evm.py",
    "evm_erc20.py", "evm_eip712.py", "exchange.py", "cross_boot.py",
    "transaction_state.py", "keys.py", "recovery.py", "vault.py",
    "policy.py", "gui.py", "review.py", "signer_session.py",
    "qr_session.py", "qr_workflow.py", "qr_cli.py",
    "keystone_public.py", "gui_qr_bridge.py",
))
ONLINE_MODULES = frozenset((
    "companion_core.py", "companion_btc.py", "companion_web.py",
    "companion_portable.py", "companion_envelope.py",
))
IMAGE_SCRIPTS = frozenset((
    "build_image.sh", "build_offline_wheel.py", "check_host.sh",
    "check_reproducible.sh", "configure_buildroot.sh", "fetch_buildroot.sh",
    "fetch_sources.sh", "fetch_wheelhouse.sh", "install_target_python.py",
    "launch_locked_signer.sh", "validate_buildroot_config.py",
    "verify_image.py", "verify_image.sh", "verify_uefi_boot.sh",
))
WINDOWS_SCRIPTS = frozenset((
    "windows_companion.py", "check_windows_companion_archive.py",
    "smoke_windows_companion.py", "smoke_windows_companion_flow.py",
))
OTHER_SCRIPTS = frozenset((
    "refresh_ci_lock.py", "verify_release_assets.py",
    "verify_usb_vfat_atomic.py",
))
SAFE_WORKFLOWS = frozenset((
    "live-usb-fast.yml", "live-usb-pr-close.yml",
    "windows-companion.yml", "usb-vfat-atomic.yml",
    "btc-core-e2e.yml", "btc-psbt-fuzz.yml", "metamask-snap.yml",
))


@dataclass(frozen=True)
class Workloads:
    qr: bool = False
    native_qr: bool = False
    windows: bool = False
    snap: bool = False
    live_usb: bool = False
    btc_core: bool = False
    btc_fuzz: bool = False
    vfat: bool = False


FULL = Workloads(True, True, True, True, True, True, True, True)
NONE = Workloads()


def classify_workloads(paths: list[str]) -> Workloads:
    flags: set[str] = set()

    def add(*names: str) -> None:
        flags.update(names)

    for path in paths:
        # Documentation and examples cannot be executed or copied to the image.
        if (path.startswith(("docs/", ".github/ISSUE_TEMPLATE/"))
                or path.startswith((".github/PULL_REQUEST_TEMPLATE", "README.", "LICENSE."))
                or path in {"README", "README.md", "LICENSE", "NOTICE", "SECURITY.md", "AGENTS.md"}
                or path.startswith(("CHANGELOG", "CONTRIBUTING"))):
            continue

        if path.startswith(("buildroot-external/", "infra/")):
            add("live_usb")
        elif path == ".github/workflows/live-usb-build.yml":
            add("live_usb")
        elif path in {".github/workflows/ci.yml", "scripts/ci_checks.py",
                      "scripts/ci_workloads.py"}:
            add(*Workloads.__dataclass_fields__)
        elif path.startswith(".github/workflows/"):
            name = path.split("/")[-1]
            if name not in SAFE_WORKFLOWS and name != "release.yml":
                add(*Workloads.__dataclass_fields__)
            elif name == "release.yml":
                add("live_usb")
            elif name == "windows-companion.yml":
                add("windows")
            elif name == "metamask-snap.yml":
                add("snap")
            elif name == "usb-vfat-atomic.yml":
                add("vfat")
            elif name == "btc-core-e2e.yml":
                add("btc_core")
            elif name == "btc-psbt-fuzz.yml":
                add("btc_fuzz")
        elif path.startswith("src/usb_cold_wallet/"):
            relative = path[len("src/usb_cold_wallet/"):]
            if relative.startswith("companion_static/") or relative in ONLINE_MODULES:
                add("windows")
            elif relative in OFFLINE_MODULES:
                add("live_usb")
                if relative in {
                    "__init__.py", "btc.py", "evm.py", "keys.py", "exchange.py",
                    "cross_boot.py", "transaction_state.py", "policy.py",
                    "qr_cli.py", "qr_session.py", "qr_workflow.py",
                    "gui_qr_bridge.py", "gui.py", "review.py",
                    "keystone_public.py",
                }:
                    add("qr", "native_qr", "windows", "snap")
                if relative in {"btc.py", "keys.py", "cross_boot.py"}:
                    add("btc_core", "btc_fuzz")
                if relative in {"vault.py", "gui.py", "exchange.py",
                                "cross_boot.py", "transaction_state.py",
                                "keys.py", "policy.py"}:
                    add("vfat")
            else:
                # New, moved or renamed module: the target installer rejects it.
                add(*Workloads.__dataclass_fields__)
        elif path.startswith("src/"):
            add(*Workloads.__dataclass_fields__)
        elif path.startswith("scripts/"):
            name = path[len("scripts/"):]
            if name in IMAGE_SCRIPTS:
                add("live_usb")
            elif name in WINDOWS_SCRIPTS:
                add("windows")
            elif name == "verify_usb_vfat_atomic.py":
                add("vfat")
            elif name in OTHER_SCRIPTS:
                pass
            else:
                add(*Workloads.__dataclass_fields__)
        elif path.startswith("tests/"):
            # No test file is read by Buildroot/QEMU; pytest always runs via
            # the ordinary code scope. Select additional interoperability jobs.
            if path.startswith("tests/test_btc") or "btc_psbt_crashes/" in path:
                add("btc_core", "btc_fuzz")
            if path.startswith("tests/test_companion") or path.startswith(
                ("tests/test_cross_boot", "tests/test_exchange")):
                add("windows")
            if path.startswith(("tests/test_qr", "tests/test_gui_qr")):
                add("qr", "native_qr", "snap")
            if path.startswith(("tests/test_keystone", "tests/test_metamask")):
                add("native_qr", "snap")
            if path.startswith(("tests/test_atomic", "tests/test_appliance_mount",
                                "tests/test_boot_media", "tests/test_vfat")):
                add("vfat")
        elif path.startswith("qr-transport/"):
            add("qr")
        elif path.startswith("qr-metamask/"):
            add("native_qr")
        elif path.startswith("metamask-snap/"):
            add("snap")
        elif path.startswith("review_only/"):
            # Review-only tooling is excluded from the cold image, but its\n            # decoders and policies can affect signing and transport safety.\n            add("qr", "native_qr", "windows", "snap")
        elif path in {"pyproject.toml", "Makefile", "requirements/ci.lock"}:
            # Pyproject changes build/runtime dependency contracts; Makefile is
            # conservatively treated as a boot build entry point.
            if path in {"Makefile", "pyproject.toml"}:
                add("live_usb")
            add("qr", "native_qr", "windows", "snap", "btc_core", "btc_fuzz", "vfat")
        elif path.startswith("requirements/"):
            add("qr", "native_qr", "windows", "snap", "btc_core", "btc_fuzz", "vfat")
        elif path.startswith("tools/"):
            if path == "tools/generate_core_bip84_psbt_e2e.py":
                add("btc_core")
            elif path == "tools/fuzz_btc_psbt.py":
                add("btc_fuzz")
            else:
                add(*Workloads.__dataclass_fields__)
        else:
            # Anything unclassified is security-sensitive until audited.
            add(*Workloads.__dataclass_fields__)

    return Workloads(**{name: name in flags for name in Workloads.__dataclass_fields__})
