from pathlib import Path
import re

from scripts.install_target_python import (
    TARGET_EMBIT_PREBUILT,
    _keep_target_embit_prebuilt,
)

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
    for forbidden in (
        "CONFIG_ATA=y",
        "CONFIG_BLK_DEV_NVME=y",
        "CONFIG_MMC=y",
        "CONFIG_VIRTIO_BLK=y",
    ):
        assert forbidden not in text


def test_image_has_separate_boot_and_cold_vault_partitions():
    text = (ROOT / "buildroot-external/board/usb-wallet/genimage.cfg").read_text()
    assert 'label = "USBCOLD_EFI"' in text
    assert 'label = "COLD_VAULT"' in text
    assert "partition boot" in text
    assert "partition vault" in text
    assert "read-only = true" in text


def test_image_generation_is_deterministic():
    defconfig = (ROOT / "buildroot-external/configs/usb_wallet_x86_64_defconfig").read_text()
    image = (ROOT / "buildroot-external/board/usb-wallet/genimage.cfg").read_text()
    repro = (ROOT / "infra/reproducible.env").read_text()
    assert "BR2_REPRODUCIBLE=y" in defconfig
    assert image.count('extraargs = "--invariant"') == 2
    assert 'disk-uuid = "f1448aa1-28cc-54bf-8fdd-3008514c0ab5"' in image
    assert 'partition-uuid = "e2bd6d1b-8de5-502d-a897-c53a8e60f46b"' in image
    assert 'partition-uuid = "18f1c36f-d5c0-5052-9cd2-03e9c2a48f00"' in image
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
    assert "BOOT_PARTUUID=e2bd6d1b-8de5-502d-a897-c53a8e60f46b" in init
    assert "VAULT_PARTUUID=18f1c36f-d5c0-5052-9cd2-03e9c2a48f00" in init
    assert 'blkid -t "PARTUUID=$partuuid" -o device' in init
    assert "boot and vault partitions share verified block parent" in init
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
    assert 'LOCKDOWN=/run/usb-wallet/lockdown' in init
    assert 'BOOT_PARENT_FILE=/run/usb-wallet/boot-parent' in init
    assert 'VAULT_DEVICE_FILE=/run/usb-wallet/vault-device' in init
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
