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
