"""Testnet-only QR request preparation, offline signing and online verification.

The QR bytes are an UNTRUSTED transport, not an authorization. User-selected
recipient and amount are always supplied independently to the offline signer.
"""
import base64
from embit import ec, psbt, script
from eth_account import Account
from eth_account.typed_transactions import TypedTransaction
from hexbytes import HexBytes

from .btc import review_btc_psbt, sign_btc_psbt
from .evm import review_evm_transaction, sign_evm
from .keys import evm_account
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


def sign_offline(root, request, *, recipient, amount, max_fee_sats=None, change_index=None):
    """Caller MUST confirm recipient/amount/fee independently on trusted offline screen."""
    _check(request, REQUEST_KEYS, "unsigned")
    data = request["payload"]
    if not isinstance(data, dict):
        raise ValueError("QR request payload must be an object")
    if request["network"] == "sepolia" and data.get("kind") == "evm":
        sender = evm_account(root).address
        if request["account"].lower() != sender.lower():
            raise ValueError("EVM QR account does not match unlocked wallet")
        if data.get("recipient", "").lower() != recipient.lower() or data.get("amount_wei") != amount:
            raise ValueError("Independently verified EVM recipient or amount differs")
        review_evm_transaction(data["transaction"], recipient, amount)
        signed = sign_evm(root, data["transaction"], recipient, amount)
        return make_response(request, signed)
    if request["network"] == "bitcoin-testnet" and data.get("kind") == "btc":
        if request["account"] != root.my_fingerprint.hex():
            raise ValueError("Bitcoin QR fingerprint does not match unlocked wallet")
        if (data.get("recipient") != recipient or data.get("amount_sats") != amount or
                data.get("max_fee_sats") != max_fee_sats or data.get("change_index") != change_index):
            raise ValueError("Independently verified BTC recipient/amount/fee/change mismatch")
        review_btc_psbt(root, data["psbt"], recipient, amount, max_fee_sats, change_index)
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
            raw = signed["signed_raw_transaction"]
            if (signed.get("chain_id") != 11155111 or
                    signed.get("from", "").lower() != original["account"].lower()):
                return False
            sender = Account.recover_transaction(raw)
            if sender.lower() != original["account"].lower():
                return False
            decoded = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
            if decoded.get("chainId") != 11155111 or decoded.get("type") != 2:
                return False
            reviewed = review_evm_transaction(data["transaction"],
                                              data["recipient"], data["amount_wei"])["transaction"]
            for field in ("chainId", "nonce", "value", "gas", "maxFeePerGas", "maxPriorityFeePerGas"):
                if decoded.get(field) != reviewed[field]:
                    return False
            recipient = decoded.get("to")
            if isinstance(recipient, (bytes, bytearray)):
                recipient = "0x" + recipient.hex()
            if not isinstance(recipient, str) or recipient.lower() != reviewed["to"].lower():
                return False
            payload = decoded.get("data", b"")
            if payload not in (b"", "", "0x"):
                return False
            if decoded.get("accessList", ()) not in ([], ()):
                return False
            if signed.get("to", "").lower() != reviewed["to"].lower() or signed.get("value_wei") != reviewed["value"]:
                return False
            return True
        except Exception:
            # Untrusted typed-RLP bytes may fail at any parser layer.
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
            input_total = sum(inp.witness_utxo.value for inp in initial.inputs)
            calculated_fee = input_total - sum(out.value for out in initial.tx.vout)
            if (signed.get("fee_sats") != calculated_fee or calculated_fee < 0 or
                    calculated_fee > data["max_fee_sats"]):
                return False
            return True
        except Exception:
            return False

    return session.check_response(response, verify_signature=verify)
