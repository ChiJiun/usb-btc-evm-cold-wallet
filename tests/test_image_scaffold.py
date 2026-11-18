from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def test_buildroot_version_and_hash_are_pinned():
    text = (ROOT / "infra/buildroot.env").read_text()
    assert "BUILDROOT_VERSION=2026.08.2" in text
    match = re.search(r"BUILDROOT_SHA256=([0-9a-f]{64})", text)
    assert match


def test_kernel_removes_network_and_internal_storage():
    text = (ROOT / "buildroot-external/board/usb-wallet/linux.config").read_text()
    assert "# CONFIG_NET is not set" in text
    assert "CONFIG_USB_STORAGE=y" in text
    assert "CONFIG_VFAT_FS=y" in text
    for forbidden in ("CONFIG_ATA=y", "CONFIG_BLK_DEV_NVME=y", "CONFIG_MMC=y", "CONFIG_VIRTIO_BLK=y"):
        assert forbidden not in text


def test_image_has_separate_boot_and_cold_vault_partitions():
    text = (ROOT / "buildroot-external/board/usb-wallet/genimage.cfg").read_text()
    assert 'label = "USBCOLD_EFI"' in text
    assert 'label = "COLD_VAULT"' in text
    assert "partition boot" in text
    assert "partition vault" in text


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
    for symbol in ("PING", "WGET", "NC", "IP", "IFCONFIG", "UDHCPC"):
        assert f"# CONFIG_{symbol} is not set" in text
