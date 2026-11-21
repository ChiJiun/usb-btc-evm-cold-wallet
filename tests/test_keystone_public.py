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
