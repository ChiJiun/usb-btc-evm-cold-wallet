from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from tools.build_live_iso import BOOT_TOKENS
from tools.image_common import ImageBuildError, sha256_file


def _run(command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, text=True, capture_output=True, check=False, env=env)
    if completed.returncode != 0:
        raise ImageBuildError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return completed


def _xorriso_env(xorriso: str) -> dict[str, str]:
    env = os.environ.copy()
    binary = Path(xorriso).resolve()
    lib_root = binary.parent.parent / "lib"
    candidates = sorted(path for path in lib_root.glob("*-linux-gnu") if path.is_dir())
    if len(candidates) == 1:
        prior = env.get("LD_LIBRARY_PATH")
        env["LD_LIBRARY_PATH"] = str(candidates[0]) + (f":{prior}" if prior else "")
    return env


def _active_live_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if "boot=live" in line and not line.lstrip().startswith("#")
    ]


def _check_boot_config(name: str, text: str) -> dict[str, object]:
    lines = _active_live_lines(text)
    missing: list[str] = []
    forbidden: list[str] = []
    for line in lines:
        words = line.split()
        for token in BOOT_TOKENS:
            if token not in words:
                missing.append(f"{token} in {line}")
        if "persistence" in words:
            forbidden.append(f"persistence in {line}")
        if "swap=true" in words:
            forbidden.append(f"swap=true in {line}")
    ok = bool(lines) and not missing and not forbidden
    return {
        "name": name,
        "ok": ok,
        "detail": (
            f"{len(lines)} live boot line(s) hardened"
            if ok
            else f"lines={len(lines)} missing={missing or 'none'} forbidden={forbidden or 'none'}"
        ),
    }


def _cat_squashfs(unsquashfs: str, squashfs: Path, path: str) -> str:
    return _run([unsquashfs, "-cat", str(squashfs), path]).stdout


def audit_iso(iso: Path, xorriso: str, unsquashfs: str, expected_sha256: str | None = None) -> dict:
    if not iso.is_file():
        raise ImageBuildError(f"ISO not found: {iso}")
    actual_sha = sha256_file(iso)
    checks: list[dict[str, object]] = []
    if expected_sha256:
        checks.append(
            {
                "name": "sha256",
                "ok": actual_sha == expected_sha256.lower(),
                "detail": f"actual={actual_sha} expected={expected_sha256.lower()}",
            }
        )

    env = _xorriso_env(xorriso)
    report = _run([xorriso, "-indev", str(iso), "-report_el_torito", "plain"], env=env)
    combined = report.stdout + "\n" + report.stderr
    bios = "El Torito boot img" in combined and "BIOS" in combined
    uefi = "El Torito boot img" in combined and "UEFI" in combined
    hybrid = "MBR isohybrid" in combined
    checks.extend(
        [
            {"name": "bios_boot", "ok": bios, "detail": "BIOS El Torito entry present" if bios else "missing BIOS El Torito entry"},
            {"name": "uefi_boot", "ok": uefi, "detail": "UEFI El Torito entry present" if uefi else "missing UEFI El Torito entry"},
            {"name": "usb_hybrid", "ok": hybrid, "detail": "MBR isohybrid present" if hybrid else "missing MBR isohybrid marker"},
        ]
    )

    with tempfile.TemporaryDirectory(prefix="usbwallet-iso-audit-") as temp:
        directory = Path(temp)
        grub = directory / "grub.cfg"
        isolinux = directory / "live.cfg"
        squashfs = directory / "filesystem.squashfs"
        _run(
            [
                xorriso,
                "-osirrox",
                "on",
                "-indev",
                str(iso),
                "-extract",
                "/boot/grub/grub.cfg",
                str(grub),
                "-extract",
                "/isolinux/live.cfg",
                str(isolinux),
                "-extract",
                "/live/filesystem.squashfs",
                str(squashfs),
            ],
            env=env,
        )
        checks.append(_check_boot_config("grub_boot_policy", grub.read_text(encoding="utf-8")))
        checks.append(_check_boot_config("isolinux_boot_policy", isolinux.read_text(encoding="utf-8")))

        expected_files = (
            "opt/usb-cold-wallet/runtime-policy.json",
            "opt/usb-cold-wallet/BUILD-METADATA.json",
            "opt/usb-cold-wallet/site-packages/USB_COLD_WALLET_ARTIFACTS.json",
            "usr/local/bin/usb-cold-wallet",
            "usr/local/sbin/usb-cold-wallet-airgap",
            "usr/local/sbin/usb-cold-wallet-offline-audit",
        )
        for path in expected_files:
            listing = subprocess.run(
                [unsquashfs, "-ll", str(squashfs), path],
                text=True,
                capture_output=True,
                check=False,
            )
            ok = listing.returncode == 0 and path in listing.stdout
            checks.append(
                {
                    "name": "squashfs_" + Path(path).name.replace(".", "_"),
                    "ok": ok,
                    "detail": path if ok else f"missing {path}",
                }
            )

        metadata_text = _cat_squashfs(
            unsquashfs, squashfs, "opt/usb-cold-wallet/BUILD-METADATA.json"
        )
        artifact_text = _cat_squashfs(
            unsquashfs,
            squashfs,
            "opt/usb-cold-wallet/site-packages/USB_COLD_WALLET_ARTIFACTS.json",
        )
        try:
            metadata = json.loads(metadata_text)
            artifact_manifest = json.loads(artifact_text)
        except json.JSONDecodeError as exc:
            raise ImageBuildError(f"embedded JSON metadata is invalid: {exc}") from exc
        checks.append(
            {
                "name": "testnet_only",
                "ok": metadata.get("testnet_only") is True,
                "detail": f"testnet_only={metadata.get('testnet_only')!r}",
            }
        )
        artifacts = artifact_manifest.get("artifacts")
        checks.append(
            {
                "name": "artifact_manifest",
                "ok": isinstance(artifacts, list) and len(artifacts) == 27,
                "detail": f"artifact_count={len(artifacts) if isinstance(artifacts, list) else 'invalid'}",
            }
        )

    failed = [check["name"] for check in checks if not check["ok"]]
    return {
        "ok": not failed,
        "iso": str(iso),
        "sha256": actual_sha,
        "failed": failed,
        "checks": checks,
    }


def _read_expected_hash(sidecar: Path, iso: Path) -> str:
    fields = sidecar.read_text(encoding="ascii").strip().split()
    if len(fields) != 2 or fields[1].lstrip("*") != iso.name:
        raise ImageBuildError(f"malformed SHA-256 sidecar: {sidecar}")
    digest = fields[0].lower()
    if len(digest) != 64:
        raise ImageBuildError(f"malformed SHA-256 digest in {sidecar}")
    int(digest, 16)
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description="Post-build audit of a generated Live USB ISO")
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--sha256-sidecar", type=Path)
    parser.add_argument("--xorriso", default=shutil.which("xorriso"))
    parser.add_argument("--unsquashfs", default=shutil.which("unsquashfs"))
    args = parser.parse_args()
    if not args.xorriso or not args.unsquashfs:
        parser.error("xorriso and unsquashfs are required")
    try:
        expected = (
            _read_expected_hash(args.sha256_sidecar, args.iso)
            if args.sha256_sidecar
            else None
        )
        result = audit_iso(args.iso, args.xorriso, args.unsquashfs, expected)
    except (ImageBuildError, OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
