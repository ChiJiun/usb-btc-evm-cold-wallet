"""Integration with BTC / EVM signer; public compromised test vector only."""
import base64
import copy

import pytest
from embit import bip32, psbt, script, transaction

from usb_cold_wallet.keys import btc_address, btc_key, evm_account, root_from_mnemonic
from usb_cold_wallet.qr_workflow import (
    prepare_evm_qr, prepare_btc_qr, sign_offline as _sign_offline,
    verify_evm_response, verify_btc_response,
)
from usb_cold_wallet.policy import default_profile, set_limit
from usb_cold_wallet.qr_session import QRSession, make_response


def sign_offline(root, request, **kwargs):
    """Public-test-vector convenience: real signer remains strict without policy."""
    kwargs.setdefault("profile", default_profile(root))
    kwargs.setdefault("extra_confirmation", "UNVERIFIED RECIPIENT")
    return _sign_offline(root, request, **kwargs)


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


def test_qr_requires_wallet_policy_and_separate_unknown_recipient_confirmation(root):
    tx = evm_tx()
    request = prepare_evm_qr(tx, evm_account(root).address, tx["to"], tx["value"])
    with pytest.raises(ValueError, match="mandatory"):
        _sign_offline(root, request, recipient=tx["to"], amount=tx["value"])
    with pytest.raises(ValueError, match="additional typed confirmation"):
        _sign_offline(root, request, recipient=tx["to"], amount=tx["value"],
                      profile=default_profile(root))
    blocked = set_limit(default_profile(root), root, "evm_max_value_wei", 1)
    with pytest.raises(ValueError, match="denied"):
        _sign_offline(root, request, recipient=tx["to"], amount=tx["value"],
                      profile=blocked, extra_confirmation="UNVERIFIED RECIPIENT")


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
    blocked = set_limit(default_profile(root), root, "btc_max_fee_sats", 1)
    with pytest.raises(ValueError, match="denied"):
        _sign_offline(root, request, recipient=target, amount=60000,
                      max_fee_sats=1500, change_index=0, profile=blocked,
                      extra_confirmation="UNVERIFIED RECIPIENT")
    with pytest.raises(ValueError):
        sign_offline(root, request, recipient=target, amount=60000,
                     max_fee_sats=1000, change_index=0)
    with pytest.raises(ValueError):
        sign_offline(root, request, recipient=target, amount=60000,
                     max_fee_sats=1500, change_index=1)

    # The signed PSBT remains correct while attacker changes the separate
    # transaction to be broadcast and recomputes the transport digest.
    invalid_raw = copy.deepcopy(response["payload"])
    invalid_raw["finalized_tx_hex"] = "00"
    with pytest.raises(ValueError, match="verification"):
        verify_btc_response(request, make_response(request, invalid_raw))
    invalid_raw = copy.deepcopy(response["payload"])
    canonical_raw = bytes.fromhex(invalid_raw["finalized_tx_hex"])
    invalid_raw["finalized_tx_hex"] = (canonical_raw[:-1] + bytes([canonical_raw[-1] ^ 1])).hex()
    with pytest.raises(ValueError, match="verification"):
        verify_btc_response(request, make_response(request, invalid_raw))



def test_sepolia_qr_rejects_metadata_tamper_with_matching_transport_digest(root):
    tx = evm_tx()
    request = prepare_evm_qr(tx, evm_account(root).address, tx["to"], tx["value"])
    genuine = sign_offline(root, request, recipient=tx["to"], amount=tx["value"])
    for key, value in (
        ("transaction_hash", "0x" + "a" * 64),
        ("max_fee_wei", genuine["payload"]["max_fee_wei"] + 1),
        ("max_total_wei", genuine["payload"]["max_total_wei"] + 1),
        ("decoded_transaction", {"type": 2}),
    ):
        payload = copy.deepcopy(genuine["payload"])
        payload[key] = value
        with pytest.raises(ValueError, match="verification"):
            verify_evm_response(request, make_response(request, payload))
