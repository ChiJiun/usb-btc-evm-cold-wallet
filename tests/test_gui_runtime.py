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
                "PASS: COLD_VAULT mounted as vfat",
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
        "2 1 8:18 / /mnt/cold-vault rw,nodev,nosuid,noexec,sync - vfat /dev/sdb2 rw,sync\n"
        "3 1 0:3 / /proc rw - proc proc rw\n",
        encoding="utf-8",
    )
    return {"proc_mountinfo": mountinfo, "vault_device": vault_device}


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
        original.replace("rw,nodev,nosuid,noexec,sync", "rw,nodev,nosuid"),
        original.replace("vfat /dev/sdb2", "ext4 /dev/sdb2"),
        original.replace("rootfs rootfs", "ext4 /dev/sda1"),
        original + "4 1 8:40 / /mnt/other rw - ext4 /dev/sdc1 rw\n",
        original + "4 1 8:18 / /mnt/transfer rw,nodev,nosuid,noexec,sync - vfat /dev/sdb2 rw,sync\n",
        original.replace("2 1 8:18 / /mnt/cold-vault", "2 1 8:18 / /not-vault"),
    ]
    for corrupted in attacks:
        live["proc_mountinfo"].write_text(corrupted, encoding="utf-8")
        ok, reasons = runtime_audit(**kwargs)
        assert not ok
        assert any("FAIL: live" in line or "FAIL: unexpected live" in line for line in reasons)
