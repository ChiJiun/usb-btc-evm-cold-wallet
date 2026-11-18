from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from tools.fetch_python_artifacts import verify_artifacts
from tools.image_common import ImageBuildError, load_json, sha256_file
from tools.install_python_artifacts import install_artifacts

BOOT_TOKENS = ("nopersistence", "ipv6.disable=1", "module_blacklist=cfg80211,mac80211,bluetooth,btusb")


def _run(command: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None) -> None:
    shown = " ".join(command)
    print(f"+ {shown}", flush=True)
    completed = subprocess.run(command, env=env, cwd=cwd, check=False)
    if completed.returncode != 0:
        raise ImageBuildError(f"command failed ({completed.returncode}): {shown}")


def _capture(command: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        raise ImageBuildError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _require_tool(name: str, override: str | None = None) -> str:
    candidate = override or shutil.which(name)
    if not candidate:
        raise ImageBuildError(f"required build tool not found: {name}")
    return candidate


def _tool_version(command: str, name: str) -> str:
    completed = subprocess.run(
        [command, "-version"],
        text=True,
        capture_output=True,
        check=False,
    )
    output = (completed.stdout + "\n" + completed.stderr).strip()
    for line in output.splitlines():
        fields = line.strip().split()
        if (
            len(fields) >= 3
            and fields[0].lower().startswith(name.lower())
            and fields[1].lower() == "version"
        ):
            return fields[2]
        if len(fields) >= 2 and fields[0].lower() == name.lower():
            return fields[1]
    raise ImageBuildError(f"could not determine {name} version from: {output[:200]!r}")


def _verify_build_tool_versions(tools_config: Path, tools: dict[str, str]) -> dict[str, str]:
    expected = load_json(tools_config)
    if expected.get("schema") != 1:
        raise ImageBuildError("unsupported build-tools schema")
    actual: dict[str, str] = {}
    for name, command in tools.items():
        version = _tool_version(command, name)
        actual[name] = version
        if version != expected.get(name):
            raise ImageBuildError(
                f"{name} version mismatch: expected {expected.get(name)!r}, got {version!r}"
            )
    return actual


def _git_state(repo: Path) -> tuple[str, bool, int]:
    commit = _capture(["git", "rev-parse", "HEAD"], repo)
    dirty = bool(_capture(["git", "status", "--porcelain"], repo))
    timestamp = int(_capture(["git", "show", "-s", "--format=%ct", "HEAD"], repo))
    return commit, dirty, timestamp


def _source_date_epoch(repo: Path, explicit: int | None, allow_dirty: bool) -> tuple[int, str, bool]:
    commit, dirty, commit_epoch = _git_state(repo)
    if dirty and not allow_dirty:
        raise ImageBuildError(
            "repository is dirty; commit the image inputs or pass --allow-dirty for a non-release smoke build"
        )
    if explicit is not None:
        epoch = explicit
    elif os.environ.get("SOURCE_DATE_EPOCH"):
        try:
            epoch = int(os.environ["SOURCE_DATE_EPOCH"])
        except ValueError as exc:
            raise ImageBuildError("SOURCE_DATE_EPOCH must be an integer") from exc
    else:
        epoch = commit_epoch
    if epoch <= 0:
        raise ImageBuildError("SOURCE_DATE_EPOCH must be positive")
    return epoch, commit, dirty


def _copy(src: Path, dst: Path, mode: int | None = None) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.is_symlink() or dst.is_file():
        dst.unlink()
    shutil.copyfile(src, dst)
    if mode is not None:
        dst.chmod(mode)


def _replace_symlink(path: Path, target: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        raise ImageBuildError(f"refusing to replace directory with symlink: {path}")
    path.symlink_to(target)


def _install_runtime(repo: Path, rootfs: Path, artifact_dir: Path, epoch: int, metadata: dict) -> None:
    runtime = repo / "image/runtime"
    policy_src = repo / "image/runtime-policy.json"
    policy = load_json(policy_src)

    opt = rootfs / "opt/usb-cold-wallet"
    site_packages = opt / "site-packages"
    if opt.exists():
        raise ImageBuildError("/opt/usb-cold-wallet unexpectedly exists in base image")
    site_packages.mkdir(parents=True)
    install_artifacts(repo / "image/python-artifacts.lock.json", artifact_dir, site_packages)

    source_package = repo / "src/usb_cold_wallet"
    shutil.copytree(source_package, site_packages / "usb_cold_wallet")
    for cache in (site_packages / "usb_cold_wallet").rglob("__pycache__"):
        shutil.rmtree(cache)

    _copy(runtime / "entry.py", opt / "entry.py", 0o644)
    _copy(policy_src, opt / "runtime-policy.json", 0o644)
    (opt / "BUILD-METADATA.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (opt / "BUILD-METADATA.json").chmod(0o644)

    _copy(runtime / "usb-cold-wallet", rootfs / "usr/local/bin/usb-cold-wallet", 0o755)
    _copy(
        runtime / "usb-cold-wallet-airgap",
        rootfs / "usr/local/sbin/usb-cold-wallet-airgap",
        0o755,
    )
    _copy(
        runtime / "usb-cold-wallet-net-down",
        rootfs / "usr/local/sbin/usb-cold-wallet-net-down",
        0o755,
    )
    _copy(
        runtime / "offline_audit.py",
        rootfs / "usr/local/sbin/usb-cold-wallet-offline-audit",
        0o755,
    )

    _copy(
        runtime / "00-usb-cold-wallet-airgap.rules",
        rootfs / "etc/udev/rules.d/00-usb-cold-wallet-airgap.rules",
        0o644,
    )
    _copy(
        runtime / "usb-cold-wallet-airgap.conf",
        rootfs / "etc/modprobe.d/90-usb-cold-wallet-airgap.conf",
        0o644,
    )
    _copy(runtime / "interfaces", rootfs / "etc/network/interfaces", 0o644)
    resolv = rootfs / "etc/resolv.conf"
    if resolv.is_symlink() or resolv.is_file():
        resolv.unlink()
    _copy(runtime / "resolv.conf", resolv, 0o644)
    _copy(
        runtime / "90-usb-cold-wallet-limits.conf",
        rootfs / "etc/security/limits.d/90-usb-cold-wallet.conf",
        0o644,
    )
    _copy(
        runtime / "90-usb-cold-wallet-sysctl.conf",
        rootfs / "etc/sysctl.d/90-usb-cold-wallet.conf",
        0o644,
    )
    _copy(
        runtime / "coredump-disable.conf",
        rootfs / "etc/systemd/coredump.conf.d/90-usb-cold-wallet.conf",
        0o644,
    )
    _copy(
        runtime / "usb-cold-wallet-banner.sh",
        rootfs / "etc/profile.d/usb-cold-wallet-banner.sh",
        0o644,
    )
    _copy(
        runtime / "usb-cold-wallet-airgap.service",
        rootfs / "etc/systemd/system/usb-cold-wallet-airgap.service",
        0o644,
    )
    _copy(
        runtime / "usb-cold-wallet-offline-audit.service",
        rootfs / "etc/systemd/system/usb-cold-wallet-offline-audit.service",
        0o644,
    )

    for unit in policy.get("masked_units", []):
        if not isinstance(unit, str) or "/" in unit:
            raise ImageBuildError(f"unsafe masked unit in runtime policy: {unit!r}")
        _replace_symlink(rootfs / "etc/systemd/system" / unit, "/dev/null")

    _replace_symlink(
        rootfs / "etc/systemd/system/multi-user.target.wants/usb-cold-wallet-airgap.service",
        "../usb-cold-wallet-airgap.service",
    )
    _replace_symlink(
        rootfs
        / "etc/systemd/system/multi-user.target.wants/usb-cold-wallet-offline-audit.service",
        "../usb-cold-wallet-offline-audit.service",
    )

    # Keep copied/build-generated content deterministic before SquashFS creation.
    for base, dirs, files in os.walk(rootfs):
        for name in dirs + files:
            path = Path(base) / name
            if path.is_symlink():
                continue
            try:
                os.utime(path, (epoch, epoch), follow_symlinks=False)
            except PermissionError:
                pass


def _make_writable(path: Path) -> None:
    if path.exists() and not path.is_symlink():
        path.chmod(path.stat().st_mode | 0o200)


def _make_directories_writable(root: Path) -> None:
    _make_writable(root)
    for path in root.rglob("*"):
        if path.is_dir() and not path.is_symlink():
            _make_writable(path)


def _harden_boot_file(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    _make_writable(path)
    found_live = False
    output: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if not stripped.startswith("#") and "boot=live" in line:
            found_live = True
            ending = "\n" if line.endswith("\n") else ""
            body = line[:-1] if ending else line
            words = body.split()
            missing = [token for token in BOOT_TOKENS if token not in words]
            if missing:
                body = body + " " + " ".join(missing)
                line = body + ending
        output.append(line)
    if not found_live:
        raise ImageBuildError(f"no live boot line found in {path}")
    path.write_text("".join(output), encoding="utf-8")


def _harden_boot_menus(iso_tree: Path) -> None:
    grub = iso_tree / "boot/grub/grub.cfg"
    isolinux_live = iso_tree / "isolinux/live.cfg"
    isolinux_menu = iso_tree / "isolinux/menu.cfg"
    _harden_boot_file(grub)
    _harden_boot_file(isolinux_live)

    grub_text = grub.read_text(encoding="utf-8")
    _make_writable(grub)
    grub_text = grub_text.replace(
        'menuentry "Live system (amd64)" --hotkey=l {',
        'menuentry "USB Cold Wallet (amd64, TESTNET)" --hotkey=l {',
        1,
    )
    grub_text = grub_text.replace("\nif true; then\n\nsource\t/boot/grub/install_start.cfg", "\nif false; then\n\nsource\t/boot/grub/install_start.cfg", 1)
    grub.write_text(grub_text, encoding="utf-8")

    menu_text = isolinux_menu.read_text(encoding="utf-8")
    _make_writable(isolinux_menu)
    menu_text = menu_text.replace("menu title Boot menu", "menu title USB Cold Wallet - TESTNET")
    menu_text = menu_text.replace("include install.cfg\n", "")
    isolinux_menu.write_text(menu_text, encoding="utf-8")


def _tree_checksums(root: Path) -> None:
    excluded = {"md5sum.txt", "sha256sum.txt", "isolinux/boot.cat"}
    files = [
        path
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink() and path.relative_to(root).as_posix() not in excluded
    ]
    files.sort(key=lambda item: item.relative_to(root).as_posix())

    md5_lines: list[str] = []
    sha_lines: list[str] = []
    for path in files:
        rel = "./" + path.relative_to(root).as_posix()
        md5 = hashlib.md5(usedforsecurity=False)
        sha = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                md5.update(chunk)
                sha.update(chunk)
        md5_lines.append(f"{md5.hexdigest()}  {rel}\n")
        sha_lines.append(f"{sha.hexdigest()}  {rel}\n")
    _make_writable(root / "md5sum.txt")
    _make_writable(root / "sha256sum.txt")
    (root / "md5sum.txt").write_text("".join(md5_lines), encoding="utf-8")
    (root / "sha256sum.txt").write_text("".join(sha_lines), encoding="utf-8")


def _xorriso_uuid(epoch: int) -> str:
    stamp = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    return stamp.strftime("%Y%m%d%H%M%S") + "00"


def build_image(args: argparse.Namespace) -> dict[str, object]:
    repo = Path(__file__).resolve().parents[1]
    base_config = load_json(args.config)
    expected_base_hash = str(base_config["sha256"]).lower()
    base_iso = args.base_iso.resolve()
    if not base_iso.is_file():
        raise ImageBuildError(f"base ISO not found: {base_iso}")
    actual_base_hash = sha256_file(base_iso)
    if actual_base_hash != expected_base_hash:
        raise ImageBuildError(
            f"base ISO does not match pinned hash: expected {expected_base_hash}, got {actual_base_hash}"
        )

    verify_artifacts(args.lock, args.artifact_dir)
    xorriso = _require_tool("xorriso", args.xorriso)
    unsquashfs = _require_tool("unsquashfs", args.unsquashfs)
    mksquashfs = _require_tool("mksquashfs", args.mksquashfs)
    build_tool_versions = _verify_build_tool_versions(
        args.tools_config,
        {
            "xorriso": xorriso,
            "unsquashfs": unsquashfs,
            "mksquashfs": mksquashfs,
        },
    )

    epoch, commit, dirty = _source_date_epoch(repo, args.source_date_epoch, args.allow_dirty)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        if not args.force:
            raise ImageBuildError(f"output already exists: {output}; use --force to replace it")
        output.unlink()

    work_parent = args.work_parent.resolve()
    work_parent.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="image-", dir=work_parent))
    iso_tree = work_dir / "iso"
    rootfs = work_dir / "rootfs"
    iso_tree.mkdir()

    metadata = {
        "schema": 1,
        "project_commit": commit,
        "dirty_build": dirty,
        "source_date_epoch": epoch,
        "base_iso": base_config["iso_filename"],
        "base_iso_sha256": expected_base_hash,
        "python_artifact_lock_sha256": sha256_file(args.lock),
        "build_tools": build_tool_versions,
        "testnet_only": True,
    }

    try:
        _run([xorriso, "-osirrox", "on", "-indev", str(base_iso), "-extract", "/", str(iso_tree)])
        _make_directories_writable(iso_tree)
        squashfs = iso_tree / "live/filesystem.squashfs"
        if not squashfs.is_file():
            raise ImageBuildError("base ISO has no /live/filesystem.squashfs")

        _run([unsquashfs, "-d", str(rootfs), str(squashfs)])
        _install_runtime(repo, rootfs, args.artifact_dir, epoch, metadata)

        audit_script = repo / "image/runtime/offline_audit.py"
        _run(
            [
                sys.executable,
                str(audit_script),
                "--static-root",
                str(rootfs),
                "--policy",
                str(rootfs / "opt/usb-cold-wallet/runtime-policy.json"),
            ]
        )

        squashfs.unlink()
        _run(
            [
                mksquashfs,
                str(rootfs),
                str(squashfs),
                "-noappend",
                "-comp",
                "zstd",
                "-b",
                "1048576",
                "-Xcompression-level",
                "15",
                "-processors",
                str(max(1, args.squashfs_processors)),
                "-all-root",
                "-all-time",
                str(epoch),
                "-mkfs-time",
                str(epoch),
            ],
        )

        _harden_boot_menus(iso_tree)
        _tree_checksums(iso_tree)

        uuid = _xorriso_uuid(epoch)
        mbr_interval = (
            "--interval:local_fs:0s-15s:zero_mbrpt,zero_gpt,zero_apm:"
            + str(base_iso)
        )
        _run(
            [
                xorriso,
                "-as",
                "mkisofs",
                "-R",
                "-J",
                "-joliet-long",
                "-iso-level",
                "3",
                "-V",
                "USB_COLD_WALLET",
                f"--modification-date={uuid}",
                "--set_all_file_dates",
                uuid,
                "-isohybrid-mbr",
                mbr_interval,
                "-partition_cyl_align",
                "on",
                "-partition_offset",
                "16",
                "-partition_hd_cyl",
                "121",
                "-partition_sec_hd",
                "32",
                "--mbr-force-bootable",
                "-apm-block-size",
                "2048",
                "-iso_mbr_part_type",
                "0x00",
                "-c",
                "isolinux/boot.cat",
                "-b",
                "isolinux/isolinux.bin",
                "-no-emul-boot",
                "-boot-load-size",
                "4",
                "-boot-info-table",
                "-eltorito-alt-boot",
                "-e",
                "boot/grub/efi.img",
                "-no-emul-boot",
                "-boot-load-size",
                "6656",
                "-isohybrid-gpt-basdat",
                "-isohybrid-apm-hfsplus",
                "-o",
                str(output),
                str(iso_tree),
            ]
        )
        _run([xorriso, "-indev", str(output), "-report_el_torito", "plain"])

        digest = sha256_file(output)
        sidecar = output.with_name(output.name + ".sha256")
        sidecar.write_text(f"{digest}  {output.name}\n", encoding="ascii")
        result = {
            "output": str(output),
            "sha256": digest,
            "source_date_epoch": epoch,
            "project_commit": commit,
            "dirty_build": dirty,
            "work_dir": str(work_dir) if args.keep_workdir else None,
        }
        return result
    finally:
        if not args.keep_workdir:
            shutil.rmtree(work_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Reproducibly remaster the pinned Debian Live ISO")
    parser.add_argument("--config", type=Path, default=Path("image/base-image.json"))
    parser.add_argument("--lock", type=Path, default=Path("image/python-artifacts.lock.json"))
    parser.add_argument("--tools-config", type=Path, default=Path("image/build-tools.json"))
    parser.add_argument("--base-iso", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("dist/usb-btc-evm-cold-wallet-amd64.iso"))
    parser.add_argument("--work-parent", type=Path, default=Path("build/image-work"))
    parser.add_argument("--xorriso")
    parser.add_argument("--unsquashfs")
    parser.add_argument("--mksquashfs")
    parser.add_argument("--source-date-epoch", type=int)
    parser.add_argument("--squashfs-processors", type=int, default=1)
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--keep-workdir", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    try:
        result = build_image(args)
    except (ImageBuildError, OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
