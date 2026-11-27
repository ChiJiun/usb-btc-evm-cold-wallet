"""Issue #5 regression tests use only the PUBLIC, compromised BIP39 vector."""
import hashlib
import json
from pathlib import Path

import pytest
from embit import psbt, script, transaction

from usb_cold_wallet import cli
from usb_cold_wallet.exchange import package, read, read_bounded, read_envelope, verify, write
from usb_cold_wallet.keys import root_from_mnemonic, watch_only
from usb_cold_wallet.policy import default_profile, save_profile
from usb_cold_wallet.recovery import PUBLIC_TEST_MNEMONIC, rehearsal, restore_paper_wallet
from usb_cold_wallet.vault import load_vault

PASSWORD = "fictional-test-encryption-password"
PUBLIC = watch_only(root_from_mnemonic(PUBLIC_TEST_MNEMONIC), 1)
BTC = PUBLIC["bitcoin"]["receive_addresses"][0]
EVM = PUBLIC["evm"]["address"]


def _test_policy_anchor(vault):
    root = root_from_mnemonic(PUBLIC_TEST_MNEMONIC)
    policy = vault.with_name(vault.name + ".policy")
    save_profile(policy, default_profile(root), root, PASSWORD)
    return hashlib.sha256(policy.read_bytes()).hexdigest()


def test_rehearsal_deletes_and_restores_only_temporary_test_vault():
    result = rehearsal(PASSWORD)
    assert result["result"] == "test-only recovery rehearsal passed"
    assert result["btc_address"] == BTC
    assert result["evm_address"] == EVM


def test_recover_from_paper_and_no_overwrite(tmp_path):
    vault = tmp_path / "restored.vault"
    result = restore_paper_wallet(vault, PUBLIC_TEST_MNEMONIC, "", BTC, EVM, PASSWORD)
    assert result["evm"]["address"] == EVM
    assert load_vault(vault, PASSWORD) == PUBLIC_TEST_MNEMONIC
    prior = vault.read_bytes()
    with pytest.raises(FileExistsError):
        restore_paper_wallet(vault, PUBLIC_TEST_MNEMONIC, "", BTC, EVM, PASSWORD)
    assert vault.read_bytes() == prior


@pytest.mark.parametrize("wrong_btc,wrong_evm,phrase", [
    ("tb1q000000000000000000000000000000000000", EVM, ""),
    (BTC, "0x0000000000000000000000000000000000000000", ""),
    (BTC, EVM, "mismatch"),
])
def test_recovery_mismatch_leaves_no_vault(tmp_path, wrong_btc, wrong_evm, phrase):
    path = tmp_path / "do-not-create.vault"
    with pytest.raises(ValueError):
        restore_paper_wallet(path, PUBLIC_TEST_MNEMONIC, phrase, wrong_btc, wrong_evm, PASSWORD)
    assert not path.exists()


def test_invalid_mnemonic_rejected_without_write(tmp_path):
    path = tmp_path / "invalid.vault"
    with pytest.raises(ValueError):
        restore_paper_wallet(path, "abandon " * 12, "", BTC, EVM, PASSWORD)
    assert not path.exists()


@pytest.mark.parametrize("kind,payload", [
    ("watch-only", PUBLIC),
    ("evm-request", {"type": 2, "chainId": 11155111, "nonce": 0,
                     "to": "0x000000000000000000000000000000000000dEaD", "value": 1000,
                     "gas": 21000, "maxFeePerGas": 2000000000, "maxPriorityFeePerGas": 1000000000}),
    ("btc-request", None),
])
def test_exchange_roundtrip(tmp_path, kind, payload):
    if kind == "btc-request":
        root = root_from_mnemonic(PUBLIC_TEST_MNEMONIC)
        prev = transaction.Transaction(
            vin=[transaction.TransactionInput(b"\x21" * 32, 0)],
            vout=[transaction.TransactionOutput(100_000,
                        script.p2wpkh(root.derive("m/84h/1h/0h/0/0").key))],
        )
        unsigned = transaction.Transaction(
            version=2, vin=[transaction.TransactionInput(prev.txid(), 0)],
            vout=[transaction.TransactionOutput(99_000, script.address_to_scriptpubkey(BTC))],
        )
        data = psbt.PSBT(unsigned)
        data.inputs[0].witness_utxo = prev.vout[0]
        data.inputs[0].non_witness_utxo = prev
        payload = data.to_base64()
    filepath = tmp_path / "public.json"
    write(filepath, kind, payload)
    assert read(filepath, kind) == payload
    parsed = json.loads(filepath.read_text())
    assert parsed["network"] == package(kind, payload)["network"]
    with pytest.raises(FileExistsError):
        write(filepath, kind, payload)
    with pytest.raises(ValueError, match="mismatch"):
        read(filepath, "btc-request" if kind != "btc-request" else "evm-request")


def test_exchange_integrity_tamper_and_network_swap():
    intent = {"type": 2, "chainId": 11155111, "nonce": 1,
              "to": "0x000000000000000000000000000000000000dEaD", "value": 1234,
              "gas": 21000, "maxFeePerGas": 2000000000, "maxPriorityFeePerGas": 1000000000}
    data = package("evm-request", intent)
    altered = dict(data, payload={**intent, "nonce": 2})
    with pytest.raises(ValueError, match="integrity"):
        verify(altered)
    altered = dict(data, network="ethereum-mainnet")
    with pytest.raises(ValueError, match="network"):
        verify(altered)
    altered = dict(data, kind="watch-only")
    with pytest.raises(ValueError):
        verify(altered)


@pytest.mark.parametrize("payload", [
    {"mnemonic": PUBLIC_TEST_MNEMONIC},
    {"profile": {"private_key": "abc"}},
    {"records": [{"passphrase": "test"}]},
])
def test_exchange_blocks_sensitive_fields(payload):
    with pytest.raises(ValueError, match="Secret"):
        package("evm-request", {"chainId": 11155111, **payload})


def test_exchange_rejects_nonfinite_oversize_extra_fields_and_wrong_chain(tmp_path):
    with pytest.raises(ValueError):
        package("evm-request", {"chainId": 1})
    with pytest.raises(ValueError):
        package("btc-request", "x" * 190000)
    with pytest.raises(ValueError):
        verify(dict(package("evm-request", {"chainId": 11155111}), extra=3))
    with pytest.raises(ValueError):
        package("evm-request", {**{"type": 2, "chainId": 11155111, "nonce": 1,
                                    "to": "0x000000000000000000000000000000000000dEaD", "value": 1,
                                    "gas": 21000, "maxFeePerGas": 2000000000,
                                    "maxPriorityFeePerGas": 1000000000}, "x": float("nan")})
    file = tmp_path / "data.json"
    file.write_text('{"format": "test", "payload": NaN}')
    with pytest.raises(ValueError):
        read(file)


def test_cli_rehearsal(capsys):
    assert cli.main(["rehearse-recovery"]) == 0
    assert "test-only recovery rehearsal passed" in capsys.readouterr().out


def test_cli_pack_and_inspect(tmp_path, capsys):
    raw = tmp_path / "unsigned.json"
    raw.write_text(json.dumps({"type": 2, "chainId": 11155111, "nonce": 0,
                               "to": "0x000000000000000000000000000000000000dEaD", "value": 1000,
                               "gas": 21000, "maxFeePerGas": 2000000000,
                               "maxPriorityFeePerGas": 1000000000}))
    transport = tmp_path / "transport.json"
    assert cli.main(["pack-request", "--kind", "evm-request", "--input", str(raw),
                     "--out", str(transport)]) == 0
    assert cli.main(["inspect-transfer", "--input", str(transport)]) == 0
    assert "NOT authenticated" in capsys.readouterr().out


def test_watch_only_export_works_without_vault(tmp_path, capsys):
    transport = tmp_path / "public-watch.json"
    write(transport, "watch-only", PUBLIC)
    assert cli.main(["show-watch-only", "--input", str(transport)]) == 0
    shown = capsys.readouterr().out
    assert BTC in shown and EVM in shown
    assert "PUBLIC ONLY" in shown


def test_exchange_rejects_duplicate_json_properties(tmp_path):
    file = tmp_path / "dup.json"
    file.write_text('{"a": 1, "a": 2}')
    with pytest.raises(ValueError, match="Duplicate"):
        read(file)


def test_cli_approved_sepolia_envelope_signing_roundtrip(tmp_path, monkeypatch):
    from eth_account import Account
    from usb_cold_wallet.vault import encrypt_mnemonic, save_vault
    from usb_cold_wallet.exchange import read as load_exchange

    vault = tmp_path / "test-only.vault"
    save_vault(vault, encrypt_mnemonic(PUBLIC_TEST_MNEMONIC, PASSWORD))
    anchor = _test_policy_anchor(vault)
    tx = {
        "type": 2, "chainId": 11155111, "nonce": 0,
        "to": "0x000000000000000000000000000000000000dEaD",
        "value": 1000000000000, "gas": 21000, "maxFeePerGas": 2000000000,
        "maxPriorityFeePerGas": 1000000000, "data": "0x"
    }
    inbound = tmp_path / "unsigned.json"
    outbound = tmp_path / "signed.json"
    write(inbound, "evm-request", tx)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: PASSWORD if prompt.startswith("Vault") else "")
    challenges = []
    def approve(prompt):
        challenge = prompt.split("type '", 1)[1].split("'", 1)[0]
        challenges.append(challenge)
        return challenge
    monkeypatch.setattr("builtins.input", approve)
    args = ["--vault", str(vault), "sign-evm", "--request", str(inbound),
            "--to", tx["to"], "--wei", str(tx["value"]), "--out", str(outbound),
            "--expected-policy-sha256", anchor]
    assert cli.main(args) == 0
    signed = load_exchange(outbound, "evm-signed")
    assert Account.recover_transaction(signed["signed_raw_transaction"]) == EVM
    assert challenges == ["UNVERIFIED RECIPIENT", "SEPOLIA 0000dEaD 1000000000000"]

    inbound_data = json.loads(inbound.read_text())
    inbound_data["payload"]["value"] = 2000000000000
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(inbound_data))
    fail_output = tmp_path / "must-not-sign.json"
    assert cli.main(["--vault", str(vault), "sign-evm", "--request", str(tampered),
                     "--to", tx["to"], "--wei", str(tx["value"]),
                     "--out", str(fail_output)]) == 1
    assert not fail_output.exists()


def test_cli_approved_btc_envelope_signing_roundtrip(tmp_path, monkeypatch):
    from embit import bip32, psbt, script, transaction
    from usb_cold_wallet.keys import btc_key, btc_address
    from usb_cold_wallet.vault import encrypt_mnemonic, save_vault
    from usb_cold_wallet.exchange import read as load_exchange

    root = root_from_mnemonic(PUBLIC_TEST_MNEMONIC)
    signing_key = btc_key(root, 0, 0)
    dest = btc_address(root, 0, 1)
    output = transaction.TransactionOutput(120000, script.p2wpkh(signing_key.key))
    prev_tx = transaction.Transaction(
        vin=[transaction.TransactionInput(bytes.fromhex("11" * 32), 0)],
        vout=[output],
    )
    tx = transaction.Transaction(
        vin=[transaction.TransactionInput(prev_tx.txid(), 0)],
        vout=[
            transaction.TransactionOutput(60000, script.address_to_scriptpubkey(dest)),
            transaction.TransactionOutput(58800, script.p2wpkh(btc_key(root, 1, 0).key)),
        ],
    )
    p = psbt.PSBT(tx)
    p.unknown = {}
    # embit 0.8.0 shares a mutable default unknown dict between scope instances.
    p.inputs[0].unknown = {}
    for scope in p.outputs:
        scope.unknown = {}
    p.inputs[0].witness_utxo = output
    p.inputs[0].non_witness_utxo = prev_tx
    p.inputs[0].bip32_derivations[signing_key.key.get_public_key()] = psbt.DerivationPath(
        root.my_fingerprint, bip32.parse_path("m/84h/1h/0h/0/0")
    )
    vault = tmp_path / "public-test-only.vault"
    save_vault(vault, encrypt_mnemonic(PUBLIC_TEST_MNEMONIC, PASSWORD))
    anchor = _test_policy_anchor(vault)
    inbound = tmp_path / "unsigned-btc.json"
    outbound = tmp_path / "signed-btc.json"
    # Decode the fixture before putting it in the USB envelope.
    psbt.PSBT.from_base64(p.to_base64())
    write(inbound, "btc-request", p.to_base64())
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: PASSWORD if prompt.startswith("Vault") else "")
    def approve(prompt):
        return prompt.split("type '", 1)[1].split("'", 1)[0]
    monkeypatch.setattr("builtins.input", approve)
    args = ["--vault", str(vault), "sign-btc", "--request", str(inbound),
            "--to", dest, "--sats", "60000", "--max-fee-sats", "1500",
            "--change-index", "0", "--out", str(outbound),
            "--expected-policy-sha256", anchor]
    assert cli.main(args) == 0
    signed = load_exchange(outbound, "btc-signed")
    assert signed["signature_count"] == 1
    assert signed["fee_sats"] == 1200
    assert len(psbt.PSBT.parse(__import__("base64").b64decode(signed["signed_psbt_base64"])).inputs[0].partial_sigs) == 1


def test_transfer_rejects_symlinks_and_nonregular_files(tmp_path):
    real = tmp_path / "valid.json"
    write(real, "watch-only", PUBLIC)
    link = tmp_path / "symlink.json"
    link.symlink_to(real)
    with pytest.raises(OSError):
        read(link)
    with pytest.raises(ValueError, match="regular file"):
        read(tmp_path)
    assert read(real, "watch-only") == PUBLIC


def test_bounded_transfer_read_blocks_large_file(tmp_path):
    file = tmp_path / "large.json"
    file.write_bytes(b"x" * 210_000)
    with pytest.raises(ValueError, match="too large"):
        read(file)
    with pytest.raises(ValueError, match="too large"):
        read_bounded(file)


def test_single_pass_inspection_uses_verified_envelope(tmp_path, monkeypatch, capsys):
    envelope = tmp_path / "single-pass.json"
    write(envelope, "watch-only", PUBLIC)
    from usb_cold_wallet import exchange
    original = exchange.read_bounded
    calls = []
    def capture(path, *args, **kwargs):
        calls.append(path)
        if len(calls) > 1:
            raise AssertionError("Re-reading attacker-controlled USB after verifying it")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(exchange, "read_bounded", capture)
    assert cli.main(["inspect-transfer", "--input", str(envelope)]) == 0
    assert len(calls) == 1
    assert "integrity_only_not_authenticated" in capsys.readouterr().out


def test_cli_pack_rejects_duplicate_json_fields_and_oversize(tmp_path):
    file = tmp_path / "unsigned.json"
    out = tmp_path / "transport.json"
    file.write_text('{"chainId":11155111,"chainId":1}')
    assert cli.main(["pack-request", "--kind", "evm-request", "--input", str(file),
                     "--out", str(out)]) == 1
    assert not out.exists()
    file.write_bytes(b"x" * 210_000)
    assert cli.main(["pack-request", "--kind", "evm-request", "--input", str(file),
                     "--out", str(out)]) == 1
    assert not out.exists()


def test_cli_recover_no_overwrite(tmp_path, monkeypatch):
    existing = tmp_path / "existing.vault"
    existing.write_text("original")
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("Should never prompt"))
    assert cli.main(["--vault", str(existing), "recover", "--offline-ack",
                     "--i-have-paper-backup", "--expected-btc", BTC,
                     "--expected-evm", EVM]) == 1
    assert existing.read_text() == "original"
