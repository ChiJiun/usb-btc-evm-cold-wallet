"""Testnet-only QR request preparation, offline signing and online verification.

The QR bytes are an UNTRUSTED transport, not an authorization. User-selected
recipient and amount are always supplied independently to the offline signer.
"""
import base64
import re
from embit import ec, psbt, script, transaction

from .btc import review_btc_psbt, sign_btc_psbt
from .evm import (review_evm_transaction, sign_evm, decode_signed_eip1559,
                  review_signed_evm_transaction)
from .keys import evm_account
from .policy import enforce_review_policy
from .qr_session import QRSession, _check, REQUEST_KEYS, make_request, make_response


def prepare_evm_qr(transaction, account, expected_recipient, expected_wei, *, request_id=None):
    review_evm_transaction(transaction, expected_recipient, expected_wei)
    return make_request("sepolia", account, {
        "kind": "evm", "transaction": transaction,
        "recipient": expected_recipient, "amount_wei": expected_wei,
    }, request_id=request_id)


def prepare_btc_qr(psbt_base64, account_fingerprint, expected_recipient,
                   expected_sats, max_fee_sats, change_index=None, *, request_id=None):
    if not isinstance(psbt_base64, str):
        raise ValueError("BTC PSBT payload must be base64 text")
    return make_request("bitcoin-testnet", account_fingerprint, {
        "kind": "btc", "psbt": psbt_base64, "recipient": expected_recipient,
        "amount_sats": expected_sats, "max_fee_sats": max_fee_sats,
        "change_index": change_index,
    }, request_id=request_id)


def sign_offline(root, request, *, recipient, amount, max_fee_sats=None, change_index=None,
                 profile=None, extra_confirmation=None):
    """Fail closed unless a wallet-bound policy authorizes the reviewed QR intent."""
    _check(request, REQUEST_KEYS, "unsigned")
    if profile is None:
        raise ValueError("Wallet-bound encrypted offline policy is mandatory for QR signing")
    data = request["payload"]
    if not isinstance(data, dict):
        raise ValueError("QR request payload must be an object")
    if request["network"] == "sepolia" and data.get("kind") == "evm":
        sender = evm_account(root).address
        if request["account"].lower() != sender.lower():
            raise ValueError("EVM QR account does not match unlocked wallet")
        if data.get("recipient", "").lower() != recipient.lower() or data.get("amount_wei") != amount:
            raise ValueError("Independently verified EVM recipient or amount differs")
        review = review_evm_transaction(data["transaction"], recipient, amount)
        decision = enforce_review_policy(profile, root, review, kind="evm")[1]
        if decision.status == "REQUIRE_EXTRA_CONFIRMATION" and extra_confirmation != "UNVERIFIED RECIPIENT":
            raise ValueError("Unknown QR recipient requires additional typed confirmation")
        signed = sign_evm(root, data["transaction"], recipient, amount)
        return make_response(request, signed)
    if request["network"] == "bitcoin-testnet" and data.get("kind") == "btc":
        if request["account"] != root.my_fingerprint.hex():
            raise ValueError("Bitcoin QR fingerprint does not match unlocked wallet")
        if (data.get("recipient") != recipient or data.get("amount_sats") != amount or
                data.get("max_fee_sats") != max_fee_sats or data.get("change_index") != change_index):
            raise ValueError("Independently verified BTC recipient/amount/fee/change mismatch")
        review = review_btc_psbt(root, data["psbt"], recipient, amount, max_fee_sats, change_index)
        decision = enforce_review_policy(profile, root, review, kind="btc")[1]
        if decision.status == "REQUIRE_EXTRA_CONFIRMATION" and extra_confirmation != "UNVERIFIED RECIPIENT":
            raise ValueError("Unknown QR recipient requires additional typed confirmation")
        signed = sign_btc_psbt(root, data["psbt"], recipient, amount, max_fee_sats, change_index)
        return make_response(request, signed)
    raise ValueError("Unsupported network or signing payload")


def verify_evm_response(request, response, *, session=None):
    """Validate raw signed Sepolia tx against the COMPLETE pending unsigned request."""
    session = session or QRSession(request)

    def verify(original, signed_response):
        try:
            data = original["payload"]
            signed = signed_response["payload"]
            if type(data) is not dict or type(signed) is not dict or set(signed) != {
                "chain_id", "from", "to", "value_wei", "max_fee_wei",
                "max_total_wei", "transaction_hash", "signed_raw_transaction",
                "decoded_transaction",
            }:
                return False
            raw = signed["signed_raw_transaction"]
            decoded = decode_signed_eip1559(raw)
            checked = review_signed_evm_transaction(raw, data["recipient"], data["amount_wei"])
            reviewed = review_evm_transaction(data["transaction"], data["recipient"],
                                              data["amount_wei"])["transaction"]
            expected = {
                "type": decoded["type"], "chainId": decoded["chain_id"],
                "nonce": decoded["nonce"], "to": decoded["to"],
                "value": decoded["value_wei"], "gas": decoded["gas"],
                "maxFeePerGas": decoded["max_fee_per_gas"],
                "maxPriorityFeePerGas": decoded["max_priority_fee_per_gas"],
                "data": decoded["data"], "accessList": decoded["access_list"],
            }
            if expected != reviewed:
                return False
            return (
                signed["chain_id"] == 11155111
                and checked["from"].lower() == original["account"].lower()
                and signed["from"] == checked["from"]
                and signed["to"] == reviewed["to"]
                and type(signed["value_wei"]) is int and signed["value_wei"] == reviewed["value"]
                and type(signed["max_fee_wei"]) is int
                and signed["max_fee_wei"] == checked["max_fee_wei"]
                and type(signed["max_total_wei"]) is int
                and signed["max_total_wei"] == checked["max_total_wei"]
                and signed["transaction_hash"] == checked["transaction_hash"]
                and signed["decoded_transaction"] == decoded
            )
        except Exception:
            # Fail closed on arbitrary QR response values and malformed signed RLP.
            return False

    return session.check_response(response, verify_signature=verify)


def verify_btc_response(request, response, *, session=None):
    """Check original transaction preservation and every native P2WPKH signature.

    Does not replace full consensus script validation or proof that UTXOs are unspent.
    """
    session = session or QRSession(request)

    def verify(original, signed_response):
        try:
            data = original["payload"]
            signed = signed_response["payload"]
            if data.get("kind") != "btc" or signed.get("network") != "bitcoin-testnet":
                return False
            initial = psbt.PSBT.parse(base64.b64decode(data["psbt"], validate=True))
            final = psbt.PSBT.parse(base64.b64decode(signed["signed_psbt_base64"], validate=True))
            if initial.tx.serialize() != final.tx.serialize() or len(final.inputs) != len(initial.inputs):
                return False
            if signed.get("recipient") != data["recipient"] or signed.get("amount_sats") != data["amount_sats"]:
                return False
            if signed.get("signature_count") != len(final.inputs):
                return False
            for i, (prev, inp) in enumerate(zip(initial.inputs, final.inputs, strict=True)):
                if prev.witness_utxo is None or inp.witness_utxo is None:
                    return False
                if prev.witness_utxo.serialize() != inp.witness_utxo.serialize():
                    return False
                if len(inp.partial_sigs) != 1:
                    return False
                pub, sig = next(iter(inp.partial_sigs.items()))
                if sig[-1:] != bytes([1]) or inp.witness_utxo.script_pubkey.data != script.p2wpkh(pub).data:
                    return False
                if not pub.verify(ec.Signature.parse(sig[:-1]), final.sighash(i, sighash=1)):
                    return False
                if pub not in inp.bip32_derivations or inp.bip32_derivations[pub].fingerprint.hex() != original["account"]:
                    return False
            # A verified PSBT does not authenticate a separate finalized raw tx.
            # Reconstruct all witnesses from verified signatures and compare bytes.
            raw_hex = signed.get("finalized_tx_hex")
            if (type(raw_hex) is not str or not 1 <= len(raw_hex) <= 140_000
                    or len(raw_hex) % 2 or re.fullmatch(r"[0-9a-f]+", raw_hex) is None):
                return False
            raw_bytes = bytes.fromhex(raw_hex)
            actual = transaction.Transaction.parse(raw_bytes)
            if actual.serialize() != raw_bytes:
                return False
            expected = transaction.Transaction.parse(final.tx.serialize())
            for i, inp in enumerate(final.inputs):
                pub, sig = next(iter(inp.partial_sigs.items()))
                expected.vin[i].witness = transaction.Witness([sig, pub.sec()])
            if actual.serialize() != expected.serialize() or actual.txid() != initial.tx.txid():
                return False
            input_total = sum(inp.witness_utxo.value for inp in initial.inputs)
            calculated_fee = input_total - sum(out.value for out in initial.tx.vout)
            if (signed.get("fee_sats") != calculated_fee or calculated_fee < 0 or
                    calculated_fee > data["max_fee_sats"]):
                return False
            return True
        except Exception:
            return False

    return session.check_response(response, verify_signature=verify)
