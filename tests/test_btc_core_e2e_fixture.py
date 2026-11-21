"""Pinned Bitcoin Core 30.4 BIP84 PSBT v0 oracle; no Core process needed in CI.

Origin: tests/fixtures/bitcoin_core_bip84_regtest_e2e.json.
Regtest coinbase is synthetic, funded to the public m/84'/1'/0'/0/0 key.
Bitcoin Core creates the unsigned PSBT and finalizes/extracts the cold-signed
PSBT. embit is only used for metadata enrichment/decoding in the fixture
generator. Core's TXID and witness bytes are independent expected results.
"""
import base64
import hashlib
import json
from pathlib import Path

import pytest
from embit import psbt, script, transaction

from test_btc_independent_bip143 import independently_verify_exported_spend
from usb_cold_wallet.btc import review_btc_psbt, sign_btc_psbt
from usb_cold_wallet.keys import root_from_mnemonic

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "bitcoin_core_bip84_regtest_e2e.json").read_text()
)
ROOT = root_from_mnemonic(FIXTURE["public_bip39_mnemonic"])


def test_bitcoin_core_v0_unsigned_to_cold_signature_to_finalized_txid():
    unsigned = psbt.PSBT.parse(base64.b64decode(FIXTURE["core_unsigned_psbt_base64"]))
    assert unsigned.version is None
    assert len(unsigned.inputs) == 1 and len(unsigned.outputs) == 2
    assert unsigned.tx.version == 2 and unsigned.tx.locktime == 0
    assert unsigned.tx.vin[0].sequence == 0xFFFFFFFF
    assert unsigned.tx.vout[0].value == FIXTURE["recipient_sats"]
    assert unsigned.tx.vout[1].value == FIXTURE["change_sats"]

    raw = base64.b64decode(FIXTURE["enriched_psbt_base64"])
    assert hashlib.sha256(raw).hexdigest() == FIXTURE["psbt_sha256"]
    # Bitcoin Core's raw createpsbt lacks the full non-witness UTXO and
    # wallet derivation metadata; cold signing must reject that form.
    with pytest.raises(ValueError):
        review_btc_psbt(ROOT, FIXTURE["core_unsigned_psbt_base64"],
                        FIXTURE["recipient_testnet"], FIXTURE["recipient_sats"],
                        FIXTURE["fee_sats"], 0)
    accepted = review_btc_psbt(ROOT, FIXTURE["enriched_psbt_base64"],
                               FIXTURE["recipient_testnet"], FIXTURE["recipient_sats"],
                               FIXTURE["fee_sats"], 0)
    assert accepted["fee_sats"] == FIXTURE["fee_sats"]
    assert accepted["change_sats"] == FIXTURE["change_sats"]
    signed = sign_btc_psbt(ROOT, FIXTURE["enriched_psbt_base64"],
                           FIXTURE["recipient_testnet"], FIXTURE["recipient_sats"],
                           FIXTURE["fee_sats"], 0)
    final = transaction.Transaction.parse(bytes.fromhex(signed["finalized_tx_hex"]))
    assert final.txid().hex() == FIXTURE["core_txid"]
    assert [o.value for o in final.vout] == [
        FIXTURE["recipient_sats"], FIXTURE["change_sats"]]
    assert final.vout[0].script_pubkey.data == script.address_to_scriptpubkey(
        FIXTURE["recipient_testnet"]).data
    assert signed["fee_sats"] == FIXTURE["fee_sats"]

    # Immutable oracle: core RPC finalizepsbt extracted these bytes, and
    # Core decoderawtransaction returned core_txid/core_wtxid.
    core_final = transaction.Transaction.parse(bytes.fromhex(FIXTURE["core_finalized_tx_hex"]))
    assert core_final.txid().hex() == FIXTURE["core_txid"]
    raw_final = bytes.fromhex(FIXTURE["core_finalized_tx_hex"])
    assert hashlib.sha256(hashlib.sha256(raw_final).digest()).digest()[::-1].hex() == (
        FIXTURE["core_wtxid"])
    pinned_signed = psbt.PSBT.parse(base64.b64decode(FIXTURE["signed_psbt_base64"]))
    prev_value, _, _, _ = independently_verify_exported_spend(pinned_signed, core_final)
    assert prev_value - sum(o.value for o in core_final.vout) == FIXTURE["fee_sats"]
    assert core_final.vout[0].script_pubkey.data == final.vout[0].script_pubkey.data
    assert core_final.vout[1].script_pubkey.data == final.vout[1].script_pubkey.data


@pytest.mark.parametrize("mutation", ["recipient", "change", "fee", "rbf", "locktime"])
def test_core_fixture_policy_substitution_denied(mutation):
    p = psbt.PSBT.parse(base64.b64decode(FIXTURE["enriched_psbt_base64"]))
    if mutation == "recipient":
        p.tx.vout[0].value += 1
    elif mutation == "change":
        p.tx.vout[1].script_pubkey = script.Script(b"\\x00\\x14" + b"\\xaa" * 20)
    elif mutation == "fee":
        p.tx.vout[1].value -= 1_001
    elif mutation == "rbf":
        p.tx.vin[0].sequence = 0xFFFFFFFD
    else:
        p.tx.locktime = 1
    with pytest.raises(ValueError):
        review_btc_psbt(ROOT, p.to_base64(), FIXTURE["recipient_testnet"],
                        FIXTURE["recipient_sats"], FIXTURE["fee_sats"], 0)
