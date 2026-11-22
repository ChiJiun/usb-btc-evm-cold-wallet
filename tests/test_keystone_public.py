"""Only public BIP32 metadata may leave the physically offline signer."""
import json

from usb_cold_wallet import cli
from usb_cold_wallet.keystone_public import export_keystone_public
from usb_cold_wallet.keys import evm_account, root_from_mnemonic

# The BIP39 standard "abandon ... about" vector is publicly compromised.
ROOT = root_from_mnemonic("abandon " * 11 + "about")


def test_export_keystone_public_has_correct_bip32_path_and_no_secrets():
    data = export_keystone_public(ROOT)
    assert data["format"] == "usb-cold-keystone-public-v1"
    assert data["chain_id"] == 11155111
    assert data["address_derivation"] == "m/44h/60h/0h/0/0"
    assert data["account_derivation"] == "m/44h/60h/0h"
    assert data["address"] == evm_account(ROOT).address
    account = ROOT.derive("m/44h/60h/0h")
    address_node = ROOT.derive("m/44h/60h/0h/0/0")
    assert data["master_fingerprint"] == ROOT.my_fingerprint.hex()
    assert data["account_public_key"] == account.to_public().key.sec().hex()
    assert data["account_chain_code"] == account.to_public().chain_code.hex()
    assert data["address_public_key"] == address_node.to_public().key.sec().hex()
    assert data["address_chain_code"] == address_node.to_public().chain_code.hex()
    assert len(data["master_fingerprint"]) == 8
    assert not any("mnemonic" in k or "private" in k or "seed" in k or "vault" in k for k in data)
    assert "abandon" not in json.dumps(data)


def test_cli_can_export_public_only_to_new_file(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_wallet_root", lambda _args: ROOT)
    monkeypatch.setattr(cli, "_approve", lambda challenge: None)
    target = tmp_path / "public-evm.json"
    assert cli.main(["export-keystone-public", "--out", str(target)]) == 0
    data = json.loads(target.read_text())
    assert data["address"] == evm_account(ROOT).address
    assert cli.main(["export-keystone-public", "--out", str(target)]) == 1


def test_public_export_requires_explicit_confirmation_and_never_writes_on_cancel(
        monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_wallet_root", lambda _args: ROOT)
    monkeypatch.setattr(
        cli, "_approve", lambda challenge: (_ for _ in ()).throw(ValueError("Canceled"))
    )
    target = tmp_path / "not-created.json"
    assert cli.main(["export-keystone-public", "--out", str(target)]) == 1
    assert not target.exists()

def test_native_qr_required_ci_guard_fails_if_manifest_or_lockfile_missing(tmp_path):
    """Exercise the actual GitHub Actions preflight for missing files."""
    import re
    import subprocess
    import textwrap
    from pathlib import Path

    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
    assert "      - metamask_native_qr\n" in workflow
    gate = (Path(__file__).resolve().parents[1] / "scripts/ci_checks.py").read_text()
    assert 'NATIVE_QR: ${{ needs.metamask_native_qr.result }}' in workflow
    assert 'require("NATIVE_QR", "success" if env.get("NATIVE_REQUIRED") == "true" else "skipped")' in gate
    assert 'NATIVE_REQUIRED: ${{ needs.changes.outputs.native_qr }}' in workflow
    assert "steps.native-qr.outputs.present" not in workflow
    match = re.search(
        r"      - name: Require native MetaMask QR app files \(fail closed\)\n"
        r"        run: \|\n((?:          [^\n]*\n)+)", workflow
    )
    assert match, "Required MetaMask QR preflight must be present"
    script = textwrap.dedent(match.group(1))
    folder = tmp_path / "qr-metamask"
    folder.mkdir()
    for manifest in (False, True):
        for lock in (False, True):
            for name, present in (("package.json", manifest), ("package-lock.json", lock)):
                path = folder / name
                if present:
                    path.write_text("{}", encoding="utf-8")
                else:
                    path.unlink(missing_ok=True)
            result = subprocess.run(["bash", "-c", script], cwd=tmp_path,
                                    capture_output=True, text=True)
            assert (result.returncode == 0) == (manifest and lock)


def test_keystone_and_qr_offline_modules_are_all_shipped():
    from scripts.build_offline_wheel import ALLOWED_OFFLINE_MODULES
    assert {"keystone_public.py", "qr_session.py", "qr_workflow.py",
            "qr_cli.py"} <= ALLOWED_OFFLINE_MODULES
