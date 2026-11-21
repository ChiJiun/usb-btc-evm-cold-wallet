"""QR CLI behavior with public compromised BIP39 fixture only."""
import hashlib
import json

import pytest

from usb_cold_wallet import qr_cli
from usb_cold_wallet.keys import evm_account, root_from_mnemonic
from usb_cold_wallet.policy import default_profile, save_profile, set_limit
from usb_cold_wallet.qr_workflow import sign_offline
from usb_cold_wallet.vault import encrypt_mnemonic, save_vault

PUBLIC_TEST_MNEMONIC = "abandon " * 11 + "about"
PASSWORD = "long-fictional-test-only-password"
DESTINATION = "0x000000000000000000000000000000000000dEaD"


def unsigned():
    return {
        "type": 2, "chainId": 11155111, "nonce": 7,
        "to": DESTINATION, "value": 1_000_000,
        "gas": 21000, "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000, "data": "0x",
    }


def test_qr_cli_evm_roundtrip(tmp_path, monkeypatch, capsys):
    root = root_from_mnemonic(PUBLIC_TEST_MNEMONIC)
    txfile = tmp_path / "unsigned.json"
    txfile.write_text(json.dumps(unsigned()))
    inbound = tmp_path / "request.json"
    outbound = tmp_path / "response.json"
    vault = tmp_path / "public-test.vault"
    save_vault(vault, encrypt_mnemonic(PUBLIC_TEST_MNEMONIC, PASSWORD))
    policy_path = vault.with_name(vault.name + ".policy")
    save_profile(policy_path, default_profile(root), root, PASSWORD)
    anchor = hashlib.sha256(policy_path.read_bytes()).hexdigest()

    prepare = ["prepare-evm", "--tx", str(txfile), "--account",
               evm_account(root).address, "--to", DESTINATION,
               "--wei", str(unsigned()["value"]), "--out", str(inbound)]
    assert qr_cli.main(prepare) == 0
    assert json.loads(inbound.read_text())["direction"] == "unsigned"

    # The offline operator confirms independently supplied values.
    monkeypatch.setattr(qr_cli.getpass, "getpass",
                        lambda prompt: PASSWORD if prompt.startswith(("Vault", "Policy")) else "")
    monkeypatch.setattr("builtins.input", lambda prompt:
                        prompt.split("type '", 1)[1].split("'", 1)[0])
    sign = ["offline-sign", "--offline-ack", "--vault", str(vault),
            "--expected-policy-sha256", anchor,
            "--request", str(inbound), "--to", DESTINATION,
            "--amount", str(unsigned()["value"]), "--out", str(outbound)]
    assert qr_cli.main(sign) == 0
    assert qr_cli.main(["verify-evm", "--request", str(inbound),
                        "--response", str(outbound)]) == 0
    assert "Broadcast remains manual" not in capsys.readouterr().err



@pytest.mark.parametrize("create_policy", [False, True])
def test_qr_bad_or_missing_policy_never_unlocks(tmp_path, monkeypatch, create_policy):
    root = root_from_mnemonic(PUBLIC_TEST_MNEMONIC)
    request = tmp_path / "request.json"
    request.write_text(json.dumps(
        qr_cli.prepare_evm_qr(unsigned(), evm_account(root).address,
                             DESTINATION, unsigned()["value"])
    ), encoding="utf-8")
    vault = tmp_path / "test-only.vault"
    if create_policy:
        policy = tmp_path / "test-only.vault.policy"
        save_profile(policy, default_profile(root), root, PASSWORD)
    monkeypatch.setattr(qr_cli, "load_vault",
                        lambda *_: pytest.fail("Policy must fail before vault unlock"))
    output = tmp_path / "must-not-sign.json"
    assert qr_cli.main([
        "offline-sign", "--offline-ack", "--vault", str(vault),
        "--expected-policy-sha256", "0" * 64,
        "--request", str(request), "--to", DESTINATION,
        "--amount", str(unsigned()["value"]), "--out", str(output),
    ]) == 1
    assert not output.exists()


def test_qr_policy_amount_limit_rejected_before_writing_signature(tmp_path, monkeypatch):
    root = root_from_mnemonic(PUBLIC_TEST_MNEMONIC)
    request = tmp_path / "request.json"
    assert qr_cli.main([
        "prepare-evm", "--tx", str(tmp_path / "nonexistent.json"),
        "--account", evm_account(root).address, "--to", DESTINATION,
        "--wei", str(unsigned()["value"]), "--out", str(request),
    ]) == 1
    tx_path = tmp_path / "tx.json"
    tx_path.write_text(json.dumps(unsigned()))
    assert qr_cli.main([
        "prepare-evm", "--tx", str(tx_path),
        "--account", evm_account(root).address, "--to", DESTINATION,
        "--wei", str(unsigned()["value"]), "--out", str(request),
    ]) == 0
    vault = tmp_path / "test-only.vault"
    save_vault(vault, encrypt_mnemonic(PUBLIC_TEST_MNEMONIC, PASSWORD))
    policy_path = tmp_path / "test-only.vault.policy"
    save_profile(policy_path,
                 set_limit(default_profile(root), root, "evm_max_value_wei", 1),
                 root, PASSWORD)
    anchor = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    monkeypatch.setattr(qr_cli.getpass, "getpass",
                        lambda prompt: PASSWORD if prompt.startswith(("Vault", "Policy")) else "")
    monkeypatch.setattr("builtins.input", lambda prompt:
                        prompt.split("type '", 1)[1].split("'", 1)[0])
    output = tmp_path / "must-not-sign.json"
    assert qr_cli.main([
        "offline-sign", "--offline-ack", "--vault", str(vault),
        "--expected-policy-sha256", anchor,
        "--request", str(request), "--to", DESTINATION,
        "--amount", str(unsigned()["value"]), "--out", str(output),
    ]) == 1
    assert not output.exists()


def test_no_offline_ack_stops_before_unlock(tmp_path, monkeypatch):
    monkeypatch.setattr(qr_cli.getpass, "getpass",
                        lambda _: pytest.fail("must not unlock wallet"))
    assert qr_cli.main(["offline-sign", "--vault", str(tmp_path / "x"),
                        "--expected-policy-sha256", "0" * 64,
                        "--request", str(tmp_path / "nonexistent"),
                        "--to", DESTINATION, "--amount", "1",
                        "--out", str(tmp_path / "output")]) == 1


def test_duplicate_json_rejected_before_qr_sign(tmp_path):
    request = tmp_path / "duplicate.json"
    request.write_text('{"version":1,"version":2}')
    with pytest.raises(ValueError, match="Duplicate"):
        qr_cli._read(request)


def test_qr_cli_rejects_symlink_request(tmp_path):
    original = tmp_path / "original.json"
    original.write_text("{}")
    link = tmp_path / "link.json"
    link.symlink_to(original)
    with pytest.raises(OSError):
        qr_cli._read(link)
