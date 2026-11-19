"""Adversarial USB-transfer schema/size tests using a public compromised seed."""
import copy
from pathlib import Path

import pytest
from embit import bip32, psbt, script, transaction

from usb_cold_wallet import cli
from usb_cold_wallet.btc import sign_btc_psbt
from usb_cold_wallet.evm import sign_evm
from usb_cold_wallet.exchange import MAX_BYTES, package, read, write
from usb_cold_wallet.keys import btc_key, btc_address, root_from_mnemonic, watch_only

ROOT = root_from_mnemonic("abandon " * 11 + "about")
DEST = "0x000000000000000000000000000000000000dEaD"
TX = {
    "type": 2, "chainId": 11155111, "nonce": 0,
    "to": DEST, "value": 1000000000000, "gas": 21000,
    "maxFeePerGas": 2000000000, "maxPriorityFeePerGas": 1000000000,
    "data": "0x", "accessList": [],
}


def _real_signed_btc():
    key = btc_key(ROOT, 0, 0)
    recipient = btc_address(ROOT, 0, 1)
    prev = transaction.Transaction(
        vin=[transaction.TransactionInput(b"\x21" * 32, 0)],
        vout=[transaction.TransactionOutput(100000, script.p2wpkh(key.key))],
    )
    tx = transaction.Transaction(
        vin=[transaction.TransactionInput(prev.txid(), 0)],
        vout=[
            transaction.TransactionOutput(60000, script.address_to_scriptpubkey(recipient)),
            transaction.TransactionOutput(39000, script.p2wpkh(btc_key(ROOT, 1, 0).key)),
        ],
    )
    p = psbt.PSBT(tx)
    p.unknown = {}
    p.inputs[0].unknown = {}
    for out in p.outputs:
        out.unknown = {}
    p.inputs[0].witness_utxo = prev.vout[0]
    p.inputs[0].non_witness_utxo = prev
    p.inputs[0].bip32_derivations[key.key.get_public_key()] = psbt.DerivationPath(
        ROOT.my_fingerprint, bip32.parse_path("m/84h/1h/0h/0/0")
    )
    return sign_btc_psbt(ROOT, p.to_base64(), recipient, 60000, 1500, 0)


def test_all_unsigned_transaction_fields_must_match_allowlist():
    assert package("evm-request", TX)["payload"] == TX
    attacks = [
        {**TX, "note": "abandon " * 11 + "about"},  # innocuous field hides secret
        {**TX, "meta": {"address": "abandon " * 11 + "about"}},
        {**TX, "to": "0x123"},
        {**TX, "value": True},
        {**TX, "gas": 21001},
        {**TX, "maxFeePerGas": 1_000_000_000_001},
        {**TX, "chainId": 1},
        {**TX, "data": "0xdeadbeef"},
        {**TX, "accessList": [{"address": DEST}]},
        {**TX, "nonce": 2 ** 64},
        {key: value for key, value in TX.items() if key != "nonce"},
    ]
    for payload in attacks:
        with pytest.raises(ValueError):
            package("evm-request", payload)


def test_watch_only_export_exact_nested_schema_and_canonical_values():
    public = watch_only(ROOT, count=2)
    assert read_written("watch-only", public) == public
    attacks = [
        {**public, "annotations": {"session": "abandon " * 11 + "about"}},
        {**public, "bitcoin": {**public["bitcoin"], "note": "abandon " * 11 + "about"}},
        {**public, "bitcoin": {**public["bitcoin"], "account_tpub": "tpub" + "z" * 108}},
        {**public, "bitcoin": {**public["bitcoin"], "receive_addresses": [public["evm"]["address"]]}},
        {**public, "evm": {**public["evm"], "network": "Ethereum"}},
        {**public, "evm": {**public["evm"], "comments": "secret disguised"}},
        {**public, "evm": {**public["evm"], "address": "not-an-address"}},
    ]
    for payload in attacks:
        with pytest.raises(ValueError):
            package("watch-only", payload)


def read_written(kind, payload):
    envelope = package(kind, payload)
    from usb_cold_wallet.exchange import verify
    return verify(envelope, kind)


def test_signed_evm_payload_is_exact_and_matches_raw_signature():
    signed = sign_evm(ROOT, TX, DEST, TX["value"])
    assert read_written("evm-signed", signed) == signed
    attacks = [
        {**signed, "extra": {"history": "abandon " * 11 + "about"}},
        {**signed, "decoded_transaction": {**signed["decoded_transaction"], "note": "private phrase"}},
        {**signed, "decoded_transaction": {**signed["decoded_transaction"], "nonce": 2}},
        {**signed, "to": "0x000000000000000000000000000000000000bEEF"},
        {**signed, "transaction_hash": "0x" + "a" * 64},
        {**signed, "value_wei": 1},
        {**signed, "max_fee_wei": 0},
    ]
    for payload in attacks:
        with pytest.raises(ValueError):
            package("evm-signed", payload)


def test_signed_btc_payload_rejects_extra_and_mismatched_outpoint_data():
    signed = _real_signed_btc()
    assert read_written("btc-signed", signed) == signed
    attacks = [
        {**signed, "profile": {"notes": "abandon " * 11 + "about"}},
        {**signed, "finalized_tx_hex": "00"},
        {**signed, "recipient": btc_address(ROOT, 0, 0)},
        {**signed, "amount_sats": signed["amount_sats"] + 1},
        {**signed, "fee_sats": signed["fee_sats"] - 1},
        {**signed, "signature_count": signed["signature_count"] + 1},
        {**signed, "signed_psbt_base64": "cHNidP8BAA=="},
    ]
    for payload in attacks:
        with pytest.raises((ValueError, IndexError)):
            package("btc-signed", payload)


@pytest.mark.parametrize("kind,command", [
    ("evm", "sign-evm"),
    ("btc", "sign-btc"),
])
def test_legacy_signing_rejects_oversize_untrusted_usb_before_vault_unlock(tmp_path, monkeypatch, kind, command):
    inbound = tmp_path / "attacker.bin"
    inbound.write_bytes(b"A" * (MAX_BYTES + 1))
    outbound = tmp_path / "must-not-sign.json"
    monkeypatch.setattr(cli, "_wallet_root", lambda args: pytest.fail("Do not unlock for unvalidated USB data"))
    argv = (
        ["--vault", str(tmp_path / "do-not-read.vault"), command]
        + (["--tx", str(inbound), "--to", DEST, "--wei", "1000"] if kind == "evm"
           else ["--psbt", str(inbound), "--to", btc_address(ROOT, 0, 1), "--sats", "1000",
                 "--max-fee-sats", "1000"])
        + ["--out", str(outbound)]
    )
    assert cli.main(argv) == 1
    assert not outbound.exists()


def test_legacy_evm_rejects_duplicate_keys_nan_and_links_before_unlock(tmp_path, monkeypatch):
    inbound = tmp_path / "malicious.json"
    outbound = tmp_path / "must-not-sign.json"
    monkeypatch.setattr(cli, "_wallet_root", lambda args: pytest.fail("Do not unlock for invalid USB data"))
    for invalid in [
        '{"nonce":0,"nonce":1}',
        '{"nonce":NaN}',
        '{"nonce":"\ud800"}',
        "not json",
    ]:
        inbound.write_bytes(invalid.encode("utf-8", errors="replace"))
        assert cli.main(["sign-evm", "--tx", str(inbound), "--to", DEST,
                         "--wei", "1000", "--out", str(outbound)]) == 1
        assert not outbound.exists()
    link = tmp_path / "link.json"
    link.symlink_to(inbound)
    assert cli.main(["sign-evm", "--tx", str(link), "--to", DEST,
                     "--wei", "1000", "--out", str(outbound)]) == 1
    assert not outbound.exists()


def test_legacy_btc_rejects_non_psbt_regular_file_before_unlock(tmp_path, monkeypatch):
    inbound = tmp_path / "fake.psbt"
    inbound.write_text("cHNidP8BAA==", encoding="ascii")
    outbound = tmp_path / "must-not-sign.json"
    monkeypatch.setattr(cli, "_wallet_root", lambda args: pytest.fail("Do not unlock for bad PSBT"))
    assert cli.main(["sign-btc", "--psbt", str(inbound), "--to", btc_address(ROOT, 0, 1),
                     "--sats", "1000", "--max-fee-sats", "1000",
                     "--out", str(outbound)]) == 1
    assert not outbound.exists()
