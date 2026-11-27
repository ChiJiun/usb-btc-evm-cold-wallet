"""Integration with BTC / EVM signer; public compromised test vector only."""
import base64
import copy

import pytest
from embit import bip32, psbt, script, transaction

from usb_cold_wallet.keys import btc_address, btc_key, evm_account, root_from_mnemonic
from usb_cold_wallet.qr_workflow import (
    prepare_evm_qr, prepare_btc_qr, sign_offline, verify_evm_response, verify_btc_response,
)
from usb_cold_wallet.qr_session import QRSession, make_response


@pytest.fixture(scope="module")
def root():
    return root_from_mnemonic("abandon " * 11 + "about")


def evm_tx():
    return {"type": 2, "chainId": 11155111, "nonce": 12,
            "to": "0x000000000000000000000000000000000000dEaD",
            "value": 1000000000000, "gas": 21000,
            "maxFeePerGas": 2000000000, "maxPriorityFeePerGas": 1000000000,
            "data": "0x"}


def test_sepolia_qr_sign_and_verify_roundtrip(root):
    tx = evm_tx()
    request = prepare_evm_qr(tx, evm_account(root).address, tx["to"], tx["value"])
    response = sign_offline(root, request, recipient=tx["to"], amount=tx["value"])
    assert verify_evm_response(request, response)["chain_id"] == 11155111


def test_sepolia_qr_deny_wrong_recipient_and_wrong_sender(root):
    tx = evm_tx()
    request = prepare_evm_qr(tx, evm_account(root).address, tx["to"], tx["value"])
    with pytest.raises(ValueError, match="independently|Independently"):
        sign_offline(root, request, recipient="0x0000000000000000000000000000000000000001", amount=tx["value"])
    request = copy.deepcopy(request)
    request["account"] = "0x0000000000000000000000000000000000000001"
    with pytest.raises(ValueError):
        sign_offline(root, request, recipient=tx["to"], amount=tx["value"])


def test_sepolia_qr_tampered_response_rejected(root):
    tx = evm_tx()
    request = prepare_evm_qr(tx, evm_account(root).address, tx["to"], tx["value"])
    response = sign_offline(root, request, recipient=tx["to"], amount=tx["value"])
    fake = copy.deepcopy(response)
    fake["payload"]["signed_raw_transaction"] = "0x02"
    from usb_cold_wallet.qr_session import make_response
    fake = make_response(request, fake["payload"])
    with pytest.raises(ValueError, match="verification"):
        verify_evm_response(request, fake)


def test_sepolia_qr_rejects_rehashed_forged_signed_metadata(root):
    tx = evm_tx()
    request = prepare_evm_qr(tx, evm_account(root).address, tx["to"], tx["value"])
    response = sign_offline(root, request, recipient=tx["to"], amount=tx["value"])
    mutations = (
        ("transaction_hash", "0x" + "00" * 32),
        ("max_fee_wei", response["payload"]["max_fee_wei"] + 1),
        ("max_total_wei", response["payload"]["max_total_wei"] + 1),
        ("decoded_transaction", {**response["payload"]["decoded_transaction"], "nonce": 13}),
        ("value_wei", tx["value"] + 1),
        ("chain_id", 1),
    )
    for field, forged_value in mutations:
        payload = copy.deepcopy(response["payload"])
        payload[field] = forged_value
        forged = make_response(request, payload)  # Rehash unkeyed QR envelope.
        with pytest.raises(ValueError, match="verification"):
            verify_evm_response(request, forged)


def test_btc_testnet_qr_psbt_signed_and_correlated(root):
    key = btc_key(root, 0, 0)
    target = btc_address(root, 0, 1)
    prev_tx = transaction.Transaction(
        vin=[transaction.TransactionInput(bytes.fromhex("11"*32), 0)],
        vout=[transaction.TransactionOutput(120000, script.p2wpkh(key.key))],
    )
    tx = transaction.Transaction(
        vin=[transaction.TransactionInput(prev_tx.txid(), 0)],
        vout=[
            transaction.TransactionOutput(60000, script.address_to_scriptpubkey(target)),
            transaction.TransactionOutput(58800, script.p2wpkh(btc_key(root, 1, 0).key)),
        ],
    )
    p = psbt.PSBT(tx)
    p.unknown = {}
    p.inputs[0].unknown = {}
    for out in p.outputs:
        out.unknown = {}
    p.inputs[0].witness_utxo = prev_tx.vout[0]
    p.inputs[0].non_witness_utxo = prev_tx
    p.inputs[0].bip32_derivations[key.key.get_public_key()] = psbt.DerivationPath(
        root.my_fingerprint, bip32.parse_path("m/84h/1h/0h/0/0")
    )
    request = prepare_btc_qr(p.to_base64(), root.my_fingerprint.hex(), target, 60000, 1500, 0)
    response = sign_offline(root, request, recipient=target, amount=60000,
                            max_fee_sats=1500, change_index=0)
    signed = psbt.PSBT.parse(base64.b64decode(response["payload"]["signed_psbt_base64"]))
    assert len(signed.inputs[0].partial_sigs) == 1
    assert verify_btc_response(request, response)["signature_count"] == 1

    original_final = transaction.Transaction.parse(
        bytes.fromhex(response["payload"]["finalized_tx_hex"])
    )
    changed_output = transaction.Transaction.parse(original_final.serialize())
    changed_output.vout[0].value -= 1
    changed_witness = transaction.Transaction.parse(original_final.serialize())
    changed_witness.vin[0].witness.items[0] = b"\x31" + changed_witness.vin[0].witness.items[0][1:]
    for forged_tx_hex in ("00", changed_output.serialize().hex(), changed_witness.serialize().hex()):
        payload = copy.deepcopy(response["payload"])
        payload["finalized_tx_hex"] = forged_tx_hex
        forged = make_response(request, payload)  # Signed PSBT still valid.
        with pytest.raises(ValueError, match="verification"):
            verify_btc_response(request, forged)

    with pytest.raises(ValueError):
        sign_offline(root, request, recipient=target, amount=60000,
                     max_fee_sats=1000, change_index=0)
    with pytest.raises(ValueError):
        sign_offline(root, request, recipient=target, amount=60000,
                     max_fee_sats=1500, change_index=1)
