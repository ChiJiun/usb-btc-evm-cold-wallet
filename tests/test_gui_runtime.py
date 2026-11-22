from pathlib import Path

from usb_cold_wallet.gui import _is_public_test_root, runtime_audit
from usb_cold_wallet.keys import root_from_mnemonic


PUBLIC_TEST_MNEMONIC = "abandon " * 11 + "about"


def _boot_checks(path: Path):
    path.write_text(
        "\n".join(
            [
                "PASS: network stack absent",
                "PASS: no active swap",
                "PASS: root filesystem is RAM-backed (rootfs)",
                "PASS: boot partition is not mounted in cold runtime",
                "PASS: COLD_VAULT mounted as vfat",
                "PASS: COLD_VAULT restrictive mount options verified",
                "PASS: no unexpected writable persistent filesystem mounted",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _live_mounts(tmp_path: Path):
    mountinfo = tmp_path / "mountinfo"
    vault_device = tmp_path / "vault-device"
    vault_device.write_text("/dev/sdb2\n", encoding="ascii")
    mountinfo.write_text(
        "1 0 0:1 / / rw - rootfs rootfs rw\n"
        "2 1 8:18 / /mnt/cold-vault rw,nodev,nosuid,noexec,sync,fmask=0177,dmask=0077 - vfat /dev/sdb2 rw,sync\n"
        "3 1 0:3 / /proc rw - proc proc rw\n",
        encoding="utf-8",
    )
    # Stand-in for /sys/dev/block/<major>:<minor> symbolic links: sdb2 and
    # sdb3 belong to the same physical USB, while sdc2 belongs to another.
    sys_root = tmp_path / "sys-dev-block"
    sys_root.mkdir()
    devices = tmp_path / "devices" / "block"
    for disk, parts in {"sdb": ("sdb2", "sdb3"), "sdc": ("sdc2",)}.items():
        disk_dir = devices / disk
        disk_dir.mkdir(parents=True, exist_ok=True)
        (disk_dir / "diskseq").write_text("101" if disk == "sdb" else "202", encoding="ascii")
        for part in parts:
            partition_dir = disk_dir / part
            partition_dir.mkdir(parents=True)
            (partition_dir / "partition").write_text("2", encoding="ascii")
    for devno, part in (("8:18", "sdb2"), ("8:19", "sdb3"), ("8:34", "sdc2")):
        disk = part[:3]
        (sys_root / devno).symlink_to(devices / disk / part)
    boot_sysfs_path = tmp_path / "boot-sysfs-path"
    boot_sysfs_path.write_text(str((devices / "sdb").resolve()) + "\n", encoding="utf-8")
    boot_diskseq = tmp_path / "boot-diskseq"
    boot_diskseq.write_text("101\n", encoding="ascii")
    return {
        "proc_mountinfo": mountinfo,
        "vault_device": vault_device,
        "boot_sysfs_path": boot_sysfs_path,
        "boot_diskseq": boot_diskseq,
        "sys_dev_block": sys_root,
    }


def test_runtime_audit_requires_complete_boot_evidence(tmp_path):
    checks = tmp_path / "boot-checks.txt"
    _boot_checks(checks)
    swaps = tmp_path / "swaps"
    swaps.write_text("Filename Type Size Used Priority\n", encoding="utf-8")

    ok, findings = runtime_audit(
        boot_checks=checks,
        lockdown=tmp_path / "no-lockdown",
        proc_net=tmp_path / "no-proc-net",
        proc_swaps=swaps,
        **_live_mounts(tmp_path),
    )
    assert ok
    assert not any(line.startswith("FAIL:") for line in findings)


def test_runtime_audit_fails_closed_on_missing_result_lockdown_or_swap(tmp_path):
    checks = tmp_path / "boot-checks.txt"
    _boot_checks(checks)
    checks.write_text(
        checks.read_text(encoding="utf-8").replace(
            "PASS: no unexpected writable persistent filesystem mounted\n",
            "",
        ),
        encoding="utf-8",
    )
    swaps = tmp_path / "swaps"
    swaps.write_text(
        "Filename Type Size Used Priority\n/dev/sda2 partition 1 0 -2\n",
        encoding="utf-8",
    )
    lockdown = tmp_path / "lockdown"
    lockdown.write_text("LOCKDOWN\n", encoding="utf-8")
    proc_net = tmp_path / "net"
    proc_net.mkdir()

    ok, findings = runtime_audit(
        boot_checks=checks,
        lockdown=lockdown,
        proc_net=proc_net,
        proc_swaps=swaps,
        **_live_mounts(tmp_path),
    )
    assert not ok
    assert any("lockdown" in line for line in findings)
    assert any("writable persistent" in line for line in findings)
    assert any("active swap" in line for line in findings)
    assert any("/proc/net" in line for line in findings)


def test_development_audit_bypass_is_limited_to_public_test_wallet():
    public = root_from_mnemonic(PUBLIC_TEST_MNEMONIC)
    other = root_from_mnemonic(
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
    )
    assert _is_public_test_root(public)
    assert not _is_public_test_root(other)


def test_live_mount_revalidation_rejects_remount_and_media_swap(tmp_path):
    checks = tmp_path / "boot-checks.txt"
    _boot_checks(checks)
    swaps = tmp_path / "swaps"
    swaps.write_text("Filename Type Size Used Priority\n", encoding="utf-8")
    live = _live_mounts(tmp_path)
    kwargs = dict(boot_checks=checks, lockdown=tmp_path / "no-lockdown",
                  proc_net=tmp_path / "no-net", proc_swaps=swaps, **live)
    assert runtime_audit(**kwargs)[0]

    original = live["proc_mountinfo"].read_text(encoding="utf-8")
    attacks = [
        original.replace("/dev/sdb2", "/dev/sdc2"),
        original.replace("rw,nodev,nosuid,noexec,sync,fmask=0177,dmask=0077", "rw,nodev,nosuid"),
        original.replace("fmask=0177", "fmask=0000"),
        original.replace("dmask=0077", "dmask=0000"),
        original.replace("vfat /dev/sdb2", "ext4 /dev/sdb2"),
        original.replace("rootfs rootfs", "ext4 /dev/sda1"),
        original + "4 1 8:40 / /mnt/other rw - ext4 /dev/sdc1 rw\n",
        original + "4 1 8:18 / /mnt/transfer rw,nodev,nosuid,noexec,sync,fmask=0177,dmask=0077 - vfat /dev/sdb2 rw,sync\n",
        original.replace("2 1 8:18 / /mnt/cold-vault", "2 1 8:18 / /not-vault"),
    ]
    for corrupted in attacks:
        live["proc_mountinfo"].write_text(corrupted, encoding="utf-8")
        ok, reasons = runtime_audit(**kwargs)
        assert not ok
        assert any("FAIL: live" in line or "FAIL: unexpected live" in line for line in reasons)


def test_live_mount_allows_only_boot_verified_same_device_transfer(tmp_path):
    checks = tmp_path / "boot-checks.txt"
    _boot_checks(checks)
    swaps = tmp_path / "swaps"
    swaps.write_text("Filename Type Size Used Priority\n", encoding="utf-8")
    live = _live_mounts(tmp_path)
    transfer_device = tmp_path / "transfer-device"
    kwargs = dict(
        boot_checks=checks,
        lockdown=tmp_path / "no-lockdown",
        proc_net=tmp_path / "no-net",
        proc_swaps=swaps,
        transfer_device=transfer_device,
        **live,
    )
    mountinfo = live["proc_mountinfo"]
    original = mountinfo.read_text(encoding="utf-8")

    same_disk = (
        original
        + "4 1 8:19 / /mnt/transfer rw,nodev,nosuid,noexec,sync,fmask=0177,dmask=0077 "
          "- vfat /dev/sdb3 rw,sync\n"
    )
    mountinfo.write_text(same_disk, encoding="utf-8")
    ok, reasons = runtime_audit(**kwargs)
    assert not ok
    assert any("exact single-USB partition" in reason for reason in reasons)

    transfer_device.write_text("/dev/sdb3\n", encoding="ascii")
    assert runtime_audit(**kwargs)[0]

    transfer_device.write_text("/dev/sdb4\n", encoding="ascii")
    assert not runtime_audit(**kwargs)[0]

    transfer_device.unlink()
    mountinfo.write_text(
        original + "4 1 8:34 / /mnt/transfer rw,nodev,nosuid,noexec,sync,fmask=0177,dmask=0077 "
                   "- vfat /dev/sdc2 rw,sync\n",
        encoding="utf-8",
    )
    assert runtime_audit(**kwargs)[0]

    mountinfo.write_text(
        original + "4 1 8:19 / /mnt/transfer rw,nodev,nosuid,noexec,sync,fmask=0177,dmask=0077 "
                   "- vfat /dev/sdc2 rw,sync\n",
        encoding="utf-8",
    )
    assert not runtime_audit(**kwargs)[0]

    (live["sys_dev_block"] / "8:34").unlink()
    mountinfo.write_text(
        original + "4 1 8:34 / /mnt/transfer rw,nodev,nosuid,noexec,sync,fmask=0177,dmask=0077 "
                   "- vfat /dev/sdc2 rw,sync\n",
        encoding="utf-8",
    )
    assert not runtime_audit(**kwargs)[0]


def test_runtime_audit_rejects_usb_replacement_even_if_device_name_is_reused(tmp_path):
    checks = tmp_path / "boot-checks.txt"
    _boot_checks(checks)
    swaps = tmp_path / "swaps"
    swaps.write_text("Filename Type Size Used Priority\n", encoding="utf-8")
    live = _live_mounts(tmp_path)
    kwargs = dict(
        boot_checks=checks,
        lockdown=tmp_path / "no-lockdown",
        proc_net=tmp_path / "no-net",
        proc_swaps=swaps,
        **live,
    )
    assert runtime_audit(**kwargs)[0]

    disk = tmp_path / "devices" / "block" / "sdb"
    (disk / "diskseq").write_text("102", encoding="ascii")
    ok, findings = runtime_audit(**kwargs)
    assert not ok
    assert any("device instance changed" in line for line in findings)
