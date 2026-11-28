from pathlib import Path
import re
import struct

from scripts.install_target_python import (
    TARGET_EMBIT_PREBUILT,
    _keep_target_embit_prebuilt,
)
from scripts.generate_framebuffer_font import build_psf2

ROOT = Path(__file__).resolve().parents[1]


def test_buildroot_version_hash_and_signature_are_pinned():
    text = (ROOT / "infra/buildroot.env").read_text()
    assert "BUILDROOT_VERSION=2026.08.2" in text
    assert re.search(r"BUILDROOT_SHA256=([0-9a-f]{64})", text)
    assert re.search(r"BUILDROOT_SIG_SHA256=([0-9a-f]{64})", text)
    assert re.search(r"BUILDROOT_RELEASE_KEY_FINGERPRINT=([0-9A-F]{40})", text)
    assert re.search(r"BUILDROOT_RELEASE_KEY_SHA256=([0-9a-f]{64})", text)
    assert (ROOT / "infra/buildroot-release-key.asc").read_text().startswith(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    )


def test_kernel_removes_network_and_internal_storage():
    text = (ROOT / "buildroot-external/board/usb-wallet/linux.config").read_text()
    assert "# CONFIG_NET is not set" in text
    assert "CONFIG_USB_STORAGE=y" in text
    assert "CONFIG_VFAT_FS=y" in text
    assert "CONFIG_DRM_FBDEV_EMULATION=y" in text
    # Initramfs cannot load missing FAT charset modules at boot.
    assert "CONFIG_NLS_CODEPAGE_437=y" in text
    assert "CONFIG_NLS_ISO8859_1=y" in text
    for forbidden in (
        "CONFIG_ATA=y",
        "CONFIG_BLK_DEV_NVME=y",
        "CONFIG_MMC=y",
        "CONFIG_VIRTIO_BLK=y",
    ):
        assert forbidden not in text


def test_rootfs_device_management_does_not_force_kernel_networking():
    config = (ROOT / "buildroot-external/configs/usb_wallet_x86_64_defconfig").read_text()
    assert "BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_DEVTMPFS=y" in config
    assert "BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_MDEV=y" not in config
    assert "BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_EUDEV=y" not in config
    validator = (ROOT / "scripts/validate_buildroot_config.py").read_text()
    assert '"BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_DEVTMPFS"' in validator
    assert '"BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_MDEV"' in validator
    verifier = (ROOT / "scripts/verify_image.sh").read_text()
    assert "BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_DEVTMPFS=y$" in verifier
    assert "BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_(MDEV|EUDEV)=y$" in verifier


def test_initramfs_mounts_devtmpfs_before_boot_audit():
    init_dir = ROOT / "buildroot-external/board/usb-wallet/rootfs-overlay/etc/init.d"
    early_mount = (init_dir / "S00devtmpfs").read_text()
    audit = init_dir / "S01airgap"
    assert "mount -t devtmpfs" in early_mount
    assert "test -c /dev/console" in early_mount
    assert "test -c /dev/ttyS0" not in early_mount  # physical PCs may lack a serial port
    assert (init_dir / "S00devtmpfs").name < audit.name


def test_image_verifier_audits_the_kernel_used_for_shipped_bzimage():
    verifier = (ROOT / "scripts/verify_image.sh").read_text()
    assert 'set -- "$OUT"/build/linux-*/.config' in verifier
    assert '"$#" -ne 1' in verifier
    assert 'cmp -s "$BUILT_KERNEL" "$OUT/images/bzImage"' in verifier
    assert "grep -q '^# CONFIG_NET is not set$'" in verifier
    assert "Auditing built kernel config:" in verifier
    assert "required local display/input kernel capability missing" in verifier
    assert "CONFIG_DRM_FBDEV_EMULATION" in verifier


def test_image_has_single_usb_boot_vault_and_transfer_partitions():
    text = (ROOT / "buildroot-external/board/usb-wallet/genimage.cfg").read_text()
    assert 'label = "USBCOLD_EFI"' in text
    assert 'label = "COLD_VAULT"' in text
    assert 'label = "TX_TRANSFER"' in text
    vault_config = text.split("image cold-vault.vfat {", 1)[1].split("vfat {", 1)[0]
    assert "empty = true" in vault_config
    assert "partition boot" in text
    assert "partition vault" in text
    assert "partition transfer" in text
    assert 'partition-type-uuid = L' in text
    assert 'partition-uuid = "42f6f5d4-9310-5ac3-b5d4-1540cbe7d6b4"' in text
    assert "size = 512M" in text
    boot_config = text.split("partition boot {", 1)[1].split("}", 1)[0]
    assert "read-only = true" in boot_config
    # genimage's GPT bootable flag adds attribute bit 2. The ESP must carry
    # exactly the UEFI read-only attribute (bit 60), with no legacy bit 2.
    assert "bootable = true" not in boot_config


def test_uefi_smoke_uses_matched_flash_firmware_and_serial_audit():
    script = (ROOT / "scripts/verify_uefi_boot.sh").read_text()
    grub = (ROOT / "buildroot-external/board/usb-wallet/grub.cfg").read_text()
    boot_audit = (
        ROOT
        / "buildroot-external/board/usb-wallet/rootfs-overlay/etc/init.d/S01airgap"
    ).read_text()
    assert "OVMF_CODE_4M.fd" in script and "VARS_4M.fd" in script
    assert 'cp "$OVMF_VARS" "$TMP/ovmf-vars.fd"' in script
    assert "-drive if=pflash,unit=0,format=raw,readonly=on" in script
    assert "-drive if=pflash,unit=1,format=raw" in script
    assert '\n    -bios ' not in script
    assert "console=tty1 console=ttyS0,115200" in grub
    assert "earlyprintk=serial,ttyS0,115200" in grub
    assert "loglevel=7" in grub
    assert "--serial audit-lockdown" in boot_audit
    assert "--serial audit-ok" in boot_audit
    assert "USB_WALLET_UEFI_AUDIT_LOCKDOWN" in boot_audit
    assert "USB_WALLET_CONSOLE_READY" in script
    assert 'python3 "$ROOT/scripts/verify_delayed_usb.py"' in script
    assert "guest audit marker present but required evidence is missing" in script
    assert "boot partition is not mounted in cold runtime" in script
    assert "-net none" in script


def test_target_exposes_only_single_purpose_appliance_on_interactive_tty():
    defconfig = (ROOT / "buildroot-external/configs/usb_wallet_x86_64_defconfig").read_text()
    postbuild = (ROOT / "buildroot-external/board/usb-wallet/post-build.sh").read_text()
    assert 'BR2_TARGET_GENERIC_GETTY_PORT=""' in defconfig
    assert "tty1::respawn:/usr/bin/usb-wallet-gui-session" in postbuild
    assert "interactive getty or shell survived appliance lockdown" in postbuild
    assert "unexpected interactive inittab entry survived appliance lockdown" in postbuild
    assert "tty1::respawn:/usr/bin/usb-wallet-gui-session" in postbuild
    assert ":(askfirst|respawn):.*\\/bin\\/(a|ba|z)?sh" in postbuild


def test_image_generation_is_deterministic():
    defconfig = (ROOT / "buildroot-external/configs/usb_wallet_x86_64_defconfig").read_text()
    image = (ROOT / "buildroot-external/board/usb-wallet/genimage.cfg").read_text()
    repro = (ROOT / "infra/reproducible.env").read_text()
    assert "BR2_REPRODUCIBLE=y" in defconfig
    assert image.count('extraargs = "--invariant"') == 2
    assert 'extraargs = "--invariant -F 32"' in image
    assert 'disk-uuid = "f1448aa1-28cc-54bf-8fdd-3008514c0ab5"' in image
    assert 'partition-uuid = "e2bd6d1b-8de5-502d-a897-c53a8e60f46b"' in image
    assert 'partition-uuid = "18f1c36f-d5c0-5052-9cd2-03e9c2a48f00"' in image
    assert 'partition-uuid = "42f6f5d4-9310-5ac3-b5d4-1540cbe7d6b4"' in image
    assert re.search(r"^SOURCE_DATE_EPOCH=[1-9][0-9]+$", repro, re.MULTILINE)


def test_buildroot_fetch_verifies_signed_manifest_before_archive_hash():
    text = (ROOT / "scripts/fetch_buildroot.sh").read_text()
    assert "--import-options show-only" in text
    assert "gpgv --keyring" in text
    assert "SIGNED_SHA256" in text
    assert "BUILDROOT_RELEASE_KEY_FINGERPRINT" in text


def test_boot_audit_binds_vault_to_unique_partuuid_and_boot_device():
    init = (
        ROOT
        / "buildroot-external/board/usb-wallet/rootfs-overlay/etc/init.d/S01airgap"
    ).read_text()
    helper = (ROOT / "buildroot-external/board/usb-wallet/identify_media.py").read_text()
    postbuild = (ROOT / "buildroot-external/board/usb-wallet/post-build.sh").read_text()
    assert 'BOOT_UUID = uuid.UUID("e2bd6d1b-8de5-502d-a897-c53a8e60f46b")' in helper
    assert 'VAULT_UUID = uuid.UUID("18f1c36f-d5c0-5052-9cd2-03e9c2a48f00")' in helper
    assert "zlib.crc32" in helper
    assert "class MediaPending" in helper
    assert "class MediaInvalid" in helper
    assert "class MediaDuplicate" in helper
    assert "class MediaReplaced" in helper
    assert "class MediaTimeout" in helper
    assert "BLKGETDISKSEQ" in helper
    assert ' --check "$MEDIA_IDENTITY"' in init
    assert 'ro,noexec,nodev,nosuid,sync,fmask=0177,dmask=0077' in init
    assert 'remount,rw,noexec,nodev,nosuid,sync,fmask=0177,dmask=0077' in init
    assert "usb-wallet-identify-media" in postbuild
    assert "/usr/libexec/usb-wallet-identify-media" in init
    assert "blkid -t" not in init and "blkid -s" not in init
    assert "boot and vault partitions share verified block parent" in init
    assert 'BOOT_MAJMIN=' in init
    assert '/proc/self/mountinfo' in init
    assert '$3 == dev' in init
    assert '"$VAULT_DEVICE" /mnt/cold-vault' in init
    assert "COLD_VAULT mount source matches verified PARTUUID device" in init
    assert "-L COLD_VAULT" not in init


def test_boot_audit_covers_memory_swap_and_persistence_and_fails_closed():
    init = (
        ROOT
        / "buildroot-external/board/usb-wallet/rootfs-overlay/etc/init.d/S01airgap"
    ).read_text()
    appliance = (ROOT / "src/usb_cold_wallet/appliance.py").read_text()
    assert "root filesystem is RAM-backed" in init
    assert "no active swap" in init
    assert "no unexpected writable persistent filesystem mounted" in init
    assert "UNEXPECTED_PERSISTENT=" in init
    assert 'hasopt($4, "rw")' not in init
    assert 'LOCKDOWN=/run/usb-wallet/lockdown' in init
    assert 'BOOT_PARENT_FILE=/run/usb-wallet/boot-parent' in init
    assert 'VAULT_DEVICE_FILE=/run/usb-wallet/vault-device' in init
    assert 'TRANSFER_DEVICE_FILE=/run/usb-wallet/transfer-device' in init
    assert "single-USB TX_TRANSFER partition bound to verified boot parent" in init
    assert "_security_locked" in appliance
    assert "wallet creation/signing is disabled" in appliance


def test_target_dependency_lock_matches_main_cryptography_version():
    requirements = (ROOT / "infra/wheelhouse-requirements.txt").read_text()
    manifest = (ROOT / "infra/wheelhouse.sha256").read_text()
    project = (ROOT / "pyproject.toml").read_text()
    assert '"cryptography==50.0.2"' in project
    assert "cryptography==50.0.2 " in requirements
    assert "cryptography-50.0.2-cp311-abi3-manylinux2014_x86_64" in manifest
    assert "cryptography==47.0.0" not in requirements
    assert "cryptography-47.0.0" not in manifest


def test_wheelhouse_manifest_is_unique_and_includes_embit():
    rows = [
        line.split(None, 1)
        for line in (ROOT / "infra/wheelhouse.sha256").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    hashes = [digest for digest, _ in rows]
    names = [name.strip() for _, name in rows]
    assert len(names) == len(set(names))
    assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in hashes)
    assert "embit-0.8.0.tar.gz" in names
    assert len(names) >= 20


def test_busybox_network_clients_are_explicitly_disabled():
    text = (ROOT / "buildroot-external/board/usb-wallet/busybox.fragment").read_text()
    for symbol in ("PING", "PING6", "WGET", "NC", "NETCAT", "IP", "IFCONFIG",
                   "ROUTE", "UDHCPC", "UDHCPD", "TELNET", "TELNETD", "FTPGET", "FTPPUT"):
        assert f"# CONFIG_{symbol} is not set" in text
    postbuild = (ROOT / "buildroot-external/board/usb-wallet/post-build.sh").read_text()
    assert "networking tool survived image construction" in postbuild
    for applet in ("telnet", "ftpget", "ftpput"):
        assert applet in postbuild


def test_target_installer_keeps_only_x86_64_embit_binary(tmp_path):
    prebuilt = tmp_path / "util/prebuilt"
    prebuilt.mkdir(parents=True)
    for name in (
        TARGET_EMBIT_PREBUILT,
        "libsecp256k1_linux_aarch64.so",
        "libsecp256k1_linux_armv7l.so",
        "libsecp256k1_linux_armv6l.so",
        "libsecp256k1_darwin_x86_64.dylib",
        "libsecp256k1_darwin_arm64.dylib",
        "libsecp256k1_windows_amd64.dll",
    ):
        (prebuilt / name).write_bytes(b"fixture")

    _keep_target_embit_prebuilt(tmp_path)

    assert [path.name for path in prebuilt.iterdir()] == [TARGET_EMBIT_PREBUILT]


def test_buildroot_device_manager_preserves_offline_kernel_policy():
    config = (ROOT / "buildroot-external/configs/usb_wallet_x86_64_defconfig").read_text()
    validator = (ROOT / "scripts/validate_buildroot_config.py").read_text()
    verifier = (ROOT / "scripts/verify_image.sh").read_text()
    assert "BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_DEVTMPFS=y" in config
    assert "BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_MDEV=y" not in config
    assert '"BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_DEVTMPFS"' in validator
    assert "BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_MDEV" in validator
    assert "BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_DEVTMPFS=y" in verifier
    assert "BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_(MDEV|EUDEV)=y" in verifier


def test_framebuffer_guest_path_is_explicit_dormant_and_network_free():
    kernel = (ROOT / "buildroot-external/board/usb-wallet/linux.config").read_text()
    postbuild = (ROOT / "buildroot-external/board/usb-wallet/post-build.sh").read_text()
    appliance = (ROOT / "src/usb_cold_wallet/appliance.py").read_text()
    verifier = (ROOT / "scripts/verify_framebuffer_qemu.sh").read_text()
    workflow = (ROOT / ".github/workflows/live-usb-build.yml").read_text()
    package = (ROOT / "buildroot-external/package/usb-wallet-app/usb-wallet-app.mk").read_text()

    assert "# CONFIG_NET is not set" in kernel
    assert "CONFIG_DRM_FBDEV_EMULATION=y" in kernel
    assert "framebuffer-demo.py" in postbuild
    assert "EXPERIMENTAL framebuffer review demo" in appliance
    assert "subprocess.run([sys.executable, str(FRAMEBUFFER_DEMO)]" in appliance
    assert "-net none" in verifier
    assert "screendump" in verifier
    assert "reviewed=1 reason=reviewed" in verifier
    assert "reviewed=0 reason=cancelled" in verifier
    assert "verify_framebuffer_qemu.sh" in workflow
    assert "generate_framebuffer_font.py" in package
    assert 'tty1::respawn:/usr/bin/usb-wallet-gui-session' in postbuild
    assert 'tty1::respawn:/usr/libexec/usb-wallet-framebuffer-demo' not in postbuild


def test_generated_framebuffer_font_is_fixed_psf2():
    data = build_psf2()
    assert len(data) == 32 + 256 * 16
    magic, version, header, flags, length, charsize, height, width = struct.unpack_from("<8I", data)
    assert (magic, version, header, flags) == (0x864AB572, 0, 32, 0)
    assert (length, charsize, height, width) == (256, 16, 16, 8)
    assert any(data[32 + 32 * 16:32 + 128 * 16])


def test_reproducibility_builds_keep_isolated_output_trees_at_one_canonical_path():
    repro = (ROOT / "scripts/check_reproducible.sh").read_text()
    configure = (ROOT / "scripts/configure_buildroot.sh").read_text()
    build = (ROOT / "scripts/build_image.sh").read_text()
    verify = (ROOT / "scripts/verify_image.sh").read_text()
    assert 'OUT="$ROOT/build/output"' in repro
    assert 'OUT1="$ROOT/build/output-repro-1"' in repro
    assert 'rm -rf "$OUT"' in repro
    assert 'test ! -e "$OUT"' in repro
    assert 'mv "$OUT" "$OUT1"' in repro
    assert "build_clean 1" in repro and "build_clean 2" in repro
    assert 'BUILD_OUTPUT_DIR="$out"' not in repro
    for script in (configure, build, verify):
        assert 'BUILD_OUTPUT_DIR:-$ROOT/build/output' in script


def test_no_network_runtime_uses_socket_free_vt_fbcon_session():
    config = (ROOT / "buildroot-external/configs/usb_wallet_x86_64_defconfig").read_text()
    kernel = (ROOT / "buildroot-external/board/usb-wallet/linux.config").read_text()
    external = (ROOT / "buildroot-external/external.mk").read_text()
    postbuild = (ROOT / "buildroot-external/board/usb-wallet/post-build.sh").read_text()
    launcher_path = (
        ROOT
        / "buildroot-external/board/usb-wallet/rootfs-overlay/usr/bin/usb-wallet-gui-session"
    )
    launcher = launcher_path.read_text()

    # Buildroot preserves rootfs-overlay file modes. Losing this executable bit
    # makes the fail-closed post-build launcher check abort target-finalize.
    assert launcher_path.stat().st_mode & 0o111
    assert "# CONFIG_NET is not set" in kernel
    for symbol in (
        "CONFIG_VT=y",
        "CONFIG_FRAMEBUFFER_CONSOLE=y",
        "CONFIG_DRM_SIMPLEDRM=y",
        "CONFIG_DRM_FBDEV_EMULATION=y",
    ):
        assert symbol in kernel
    for forbidden in (
        "BR2_PACKAGE_XORG7=y",
        "BR2_PACKAGE_XSERVER_XORG_SERVER=y",
        "BR2_PACKAGE_XSERVER_XORG_SERVER_KDRIVE=y",
        "BR2_PACKAGE_XAPP_XINIT=y",
        "BR2_PACKAGE_TK=y",
    ):
        assert forbidden not in config
    assert "--enable-tk" not in external
    assert "PYTHON3_DEPENDENCIES += tk" not in external
    assert "X11 runtime present while CONFIG_NET=n" in postbuild
    assert "_tkinter" in postbuild
    assert "/usr/bin/xinit" not in launcher
    assert "Xfbdev" not in launcher
    assert "exec /usr/bin/usb-wallet-console" in launcher
    assert "test -c /dev/tty1" in launcher


def test_media_identifier_checks_primary_and_backup_gpt():
    helper = (ROOT / "buildroot-external/board/usb-wallet/identify_media.py").read_text()
    verifier = (ROOT / "scripts/verify_image.py").read_text()
    for text in (helper, verifier):
        assert "primary/backup GPT" in text
        assert "GPT_TABLE_SECTORS" in text
        assert "entries_crc" in text
    assert "primary/backup GPT partition tables differ" in helper
    assert "primary/backup GPT partition tables differ" in verifier

def test_post_build_has_valid_posix_shell_syntax():
    import subprocess

    script = ROOT / "buildroot-external/board/usb-wallet/post-build.sh"
    assert script.stat().st_mode & 0o111
    check = subprocess.run(["sh", "-n", str(script)], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr


def test_post_build_enforces_single_appliance_tty_and_fails_closed(tmp_path):
    import os
    import subprocess

    script = ROOT / "buildroot-external/board/usb-wallet/post-build.sh"
    target = tmp_path / "target"
    images = tmp_path / "images"
    (target / "etc").mkdir(parents=True)
    (target / "root").mkdir()
    (target / "usr/bin").mkdir(parents=True)
    images.mkdir()
    for name in ("usb-wallet-console", "usb-wallet-gui-session"):
        executable = target / "usr/bin" / name
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
    inittab = target / "etc/inittab"
    env = {**os.environ, "TARGET_DIR": str(target), "BINARIES_DIR": str(images)}

    # Existing getty/shell entries are removed, leaving only the appliance.
    inittab.write_text("::sysinit:/etc/init.d/rcS\ntty1::respawn:/bin/sh\ntty2::respawn:/sbin/getty\n")
    result = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert inittab.read_text().count("tty1::respawn:/usr/bin/usb-wallet-gui-session") == 1
    assert "/bin/sh" not in inittab.read_text()
    assert "getty" not in inittab.read_text()

    # Any second interactive daemon must block the build.
    inittab.write_text("::sysinit:/etc/init.d/rcS\ntty2::respawn:/usr/bin/unapproved\n")
    result = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert "unexpected interactive inittab entry" in result.stderr

    # A one-shot unapproved terminal program must not bypass respawn filtering.
    inittab.write_text("::sysinit:/etc/init.d/rcS\ntty2::once:/usr/bin/unapproved\n")
    result = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert "unexpected interactive inittab entry" in result.stderr

    # Missing init policy must not silently produce an unguarded Live OS.
    inittab.unlink()
    result = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert "missing /etc/inittab" in result.stderr

    # A missing appliance launcher must also block the build.
    inittab.write_text("::sysinit:/etc/init.d/rcS\n")
    (target / "usr/bin/usb-wallet-gui-session").unlink()
    result = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert "required appliance launcher missing" in result.stderr


def test_boot_media_wait_survives_unusable_serial_character_device(tmp_path):
    """Execute the real startup prefix with an actual failing character sink."""
    import shutil
    import subprocess
    import pytest

    if not Path("/dev/full").is_char_device() or not shutil.which("sh"):
        pytest.skip("requires POSIX shell and /dev/full")
    script = (
        ROOT / "buildroot-external/board/usb-wallet/rootfs-overlay/etc/init.d/S01airgap"
    ).read_text()
    prefix, separator, _ = script.partition('if MEDIA_IDENTITY=')
    assert separator
    # Execute only the pre-discovery prefix: no real mounts, device access,
    # swap changes or modifications to the host's /run.
    prefix = (
        prefix.replace("/run/usb-wallet", str(tmp_path / "run"))
        .replace("/mnt/cold-vault", str(tmp_path / "vault"))
        .replace("/mnt/transfer", str(tmp_path / "transfer"))
        .replace("/dev/ttyS0", "/dev/full")
    )
    # Stub the bounded helper's failed exit; real device/watchdog behavior is
    # exercised separately in test_boot_media.
    prefix = prefix.replace("/usr/bin/python3 /usr/libexec/usb-wallet-identify-media", "false")
    prefix = "swapoff() { :; }\n" + prefix
    result = subprocess.run(
        ["sh", "-c", prefix + '\nprintf "MEDIA_SCAN_REACHED\\n"\n'],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "MEDIA_SCAN_REACHED" in result.stdout
    assert (tmp_path / "run/lockdown").exists()

    # Genuine startup failure must still lock down and leave a public reason.
    result = subprocess.run(
        ["sh", "-c", prefix + "\nexit 7\n"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 7
    assert (tmp_path / "run/lockdown").exists()
    assert "FAIL: boot security audit aborted unexpectedly (exit 7)" in (
        tmp_path / "run/boot-checks.txt"
    ).read_text()


def test_boot_final_serial_diagnostics_cannot_change_audit_result(tmp_path):
    import shutil
    import subprocess
    import pytest

    if not Path("/dev/full").is_char_device() or not shutil.which("sh"):
        pytest.skip("requires POSIX shell and /dev/full")
    script = (
        ROOT / "buildroot-external/board/usb-wallet/rootfs-overlay/etc/init.d/S01airgap"
    ).read_text()
    _, separator, tail = script.partition("# Report only the final audit result")
    assert separator
    checks = tmp_path / "checks"
    checks.write_text("PASS: test audit\nFAIL: test failure\n")
    tail = (separator + tail).replace("/usr/bin/python3 /usr/libexec/usb-wallet-identify-media", "false")
    for failed in (0, 1):
        result = subprocess.run(
            ["sh", "-efuc", 'CHECKS=$1\nFAILED=$2\n' + tail,
             "audit", str(checks), str(failed)],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, result.stderr


def test_boot_audit_stop_does_not_reset_or_restart_discovery(tmp_path):
    import shutil
    import subprocess
    import pytest
    if not shutil.which("sh"):
        pytest.skip("requires POSIX shell")
    script = (
        ROOT / "buildroot-external/board/usb-wallet/rootfs-overlay/etc/init.d/S01airgap"
    ).read_text()
    run = tmp_path / "run"
    run.mkdir()
    checks = run / "boot-checks.txt"
    checks.write_text("PASS: previous completed boot audit\n")
    identity = run / "boot-device"
    identity.write_text("/dev/sda1\n")
    # If execution incorrectly reaches the normal boot body, fail without
    # executing any host mounts, swaps, or actual device discovery.
    prefix, sep, _ = script.partition("FAILED=0")
    assert sep
    prefix = prefix.replace("/run/usb-wallet", str(run))
    code = prefix + "\nexit 97\n"
    result = subprocess.run(["sh", "-c", code, "audit", "stop"],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert (run / "lockdown").exists()
    assert checks.read_text() == "PASS: previous completed boot audit\n"
    assert identity.read_text() == "/dev/sda1\n"
    result = subprocess.run(["sh", "-c", code, "audit", "restart"],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 1


def test_verify_image_tty1_session_matches_post_build():
    """Regression for CI run 46045030811: a stale tty1 check fails silently under set -e."""
    postbuild = (ROOT / "buildroot-external/board/usb-wallet/post-build.sh").read_text()
    verify = (ROOT / "scripts/verify_image.sh").read_text()
    written = re.findall(r"tty1::respawn:(/[\w/.-]+)", postbuild)
    checked = re.findall(r"grep -q '\^tty1::respawn:(/[\w/.-]+)\$'", verify)
    assert written and checked
    assert set(checked) == set(written) == {"/usr/bin/usb-wallet-gui-session"}
