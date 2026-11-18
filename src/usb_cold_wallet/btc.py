"""Fail-closed Bitcoin testnet PSBT v0 / native BIP84 P2WPKH signer.

A non_witness_utxo matching the outpoint is mandatory: witness_utxo alone is
untrusted and can lie about input value (fee deception). Research/testnet only.
"""
import base64
from io import BytesIO

from embit import ec, networks, psbt, script, transaction

from .keys import btc_key

_MAX_INPUTS = 20
_MAX_OUTPUTS = 2
_MAX_PSBT_BYTES = 200_000
_SEARCH_LIMIT = 100
_MAX_MONEY = 21_000_000 * 100_000_000
_HARDENED = 0x80000000


def _read_psbt(payload: str):
    if not isinstance(payload, str) or len(payload) > (_MAX_PSBT_BYTES * 4 // 3 + 16):
        raise ValueError("PSBT exceeds size limit or is not text")
    try:
        raw = base64.b64decode(payload.strip(), validate=True)
        if len(raw) > _MAX_PSBT_BYTES:
            raise ValueError("PSBT exceeds size limit")
        stream = BytesIO(raw)
        parsed = psbt.PSBT.read_from(stream, compress=0)
        if stream.read(1):
            raise ValueError("Trailing bytes after PSBT")
    except Exception as exc:
        raise ValueError("Malformed or unsupported PSBT") from exc
    if parsed.version is not None or not 1 <= len(parsed.inputs) <= _MAX_INPUTS:
        raise ValueError("Only PSBT v0 with 1..20 inputs supported")
    if not 1 <= len(parsed.outputs) <= _MAX_OUTPUTS:
        raise ValueError("Only one recipient and optional one change output supported")
    if parsed.unknown or parsed.xpubs:
        raise ValueError("Unexpected global PSBT metadata")
    return parsed


def _safe_amount(value):
    return type(value) is int and 0 < value <= _MAX_MONEY


def _validate_derivation(root, inp, idx):
    if len(inp.bip32_derivations) != 1:
        raise ValueError(f"Input {idx} must contain exactly one BIP32 derivation")
    pub, origin = next(iter(inp.bip32_derivations.items()))
    path = origin.derivation
    if (origin.fingerprint != root.my_fingerprint or len(path) != 5
            or path[:3] != [84 | _HARDENED, 1 | _HARDENED, 0 | _HARDENED]
            or path[3] not in (0, 1) or not 0 <= path[4] < _SEARCH_LIMIT):
        raise ValueError(f"Input {idx} has an unapproved BIP84 testnet derivation")
    key = btc_key(root, path[3], path[4]).key
    if pub.sec() != key.get_public_key().sec():
        raise ValueError(f"Input {idx} public key does not match derivation")
    if inp.witness_utxo.script_pubkey.data != script.p2wpkh(key).data:
        raise ValueError(f"Input {idx} does not belong to the claimed wallet key")
    return pub


def review_btc_psbt(root, psbt_b64: str, expected_recipient: str, expected_sats: int,
                    max_fee_sats: int, change_index: int | None = None) -> dict:
    if not _safe_amount(expected_sats):
        raise ValueError("expected_sats must be a positive Bitcoin amount")
    if type(max_fee_sats) is not int or not 0 <= max_fee_sats <= _MAX_MONEY:
        raise ValueError("Invalid maximum fee")
    if change_index is not None and (type(change_index) is not int or not 0 <= change_index <= 999):
        raise ValueError("Invalid change index")
    parsed = _read_psbt(psbt_b64)
    seen_outpoints = set()
    input_total = 0
    for idx, inp in enumerate(parsed.inputs):
        if (inp.sighash_type not in (None, 1) or inp.redeem_script is not None
                or inp.witness_script is not None or inp.partial_sigs
                or inp.final_scriptsig is not None or inp.final_scriptwitness is not None
                or inp.taproot_sigs or inp.taproot_scripts or inp.taproot_bip32_derivations
                or inp.taproot_internal_key is not None or inp.taproot_merkle_root is not None
                or inp.unknown):
            raise ValueError(f"Input {idx} has unsupported script, signature, or metadata")
        if inp.witness_utxo is None or inp.non_witness_utxo is None:
            raise ValueError(f"Input {idx} requires both witness_utxo and non_witness_utxo")
        outpoint = (inp.txid, inp.vout)
        if outpoint in seen_outpoints:
            raise ValueError("Duplicate PSBT input outpoint")
        seen_outpoints.add(outpoint)
        if inp.vout is None or inp.vout < 0 or inp.vout >= len(inp.non_witness_utxo.vout):
            raise ValueError(f"Input {idx} previous output index out of range")
        if inp.non_witness_utxo.txid() != inp.txid:
            raise ValueError(f"Input {idx} previous transaction ID mismatch")
        prevout = inp.non_witness_utxo.vout[inp.vout]
        if (prevout.value != inp.witness_utxo.value or
                prevout.script_pubkey.data != inp.witness_utxo.script_pubkey.data):
            raise ValueError(f"Input {idx} witness UTXO mismatch")
        if not _safe_amount(prevout.value):
            raise ValueError(f"Input {idx} invalid UTXO value")
        _validate_derivation(root, inp, idx)
        input_total += prevout.value
        if input_total > _MAX_MONEY:
            raise ValueError("Input total exceeds Bitcoin supply")
    try:
        target_script = script.address_to_scriptpubkey(expected_recipient).data
        canonical = script.Script(target_script).address(networks.NETWORKS["test"])
    except Exception as exc:
        raise ValueError("Invalid BTC recipient address") from exc
    if canonical != expected_recipient:
        raise ValueError("Recipient must be a canonical Bitcoin testnet address")
    change_script = (script.p2wpkh(btc_key(root, 1, change_index).key).data
                     if change_index is not None else None)
    if change_script == target_script:
        raise ValueError("Recipient must not equal designated change address")
    recipient_hits = 0
    change_hits = 0
    output_total = 0
    change_sats = 0
    for idx, output in enumerate(parsed.tx.vout):
        scope = parsed.outputs[idx]
        if (scope.unknown or scope.redeem_script is not None or scope.witness_script is not None
                or scope.taproot_bip32_derivations or scope.taproot_internal_key is not None
                or scope.bip32_derivations):
            raise ValueError("Unexpected PSBT output metadata")
        if not _safe_amount(output.value):
            raise ValueError("Invalid output value")
        output_total += output.value
        if output.script_pubkey.data == target_script and output.value == expected_sats:
            recipient_hits += 1
        elif change_script is not None and output.script_pubkey.data == change_script:
            change_hits += 1
            change_sats = output.value
        else:
            raise ValueError("Unexpected recipient, amount, or change address")
    if recipient_hits != 1 or change_hits > 1:
        raise ValueError("Exactly one expected recipient output required")
    fee = input_total - output_total
    if not 0 <= fee <= max_fee_sats:
        raise ValueError(f"Fee {fee} sats outside accepted range")
    return {
        "psbt": parsed, "network": "bitcoin-testnet",
        "recipient": expected_recipient, "amount_sats": expected_sats,
        "change_sats": change_sats, "fee_sats": fee,
        "input_count": len(parsed.inputs),
    }


def sign_btc_psbt(root, psbt_b64: str, expected_recipient: str, expected_sats: int,
                  max_fee_sats: int, change_index: int | None = None) -> dict:
    reviewed = review_btc_psbt(root, psbt_b64, expected_recipient, expected_sats,
                               max_fee_sats, change_index)
    parsed = reviewed["psbt"]
    try:
        count = parsed.sign_with(root)
        if count != len(parsed.inputs):
            raise ValueError("Not all inputs were signed")
        finalized = transaction.Transaction.parse(parsed.tx.serialize())
        for idx, inp in enumerate(parsed.inputs):
            if len(inp.partial_sigs) != 1:
                raise ValueError(f"Input {idx} missing a unique signature")
            pub, signature = next(iter(inp.partial_sigs.items()))
            if (len(signature) < 2 or signature[-1] != 1 or
                    pub not in inp.bip32_derivations or
                    not pub.verify(ec.Signature.parse(signature[:-1]), parsed.sighash(idx, sighash=1))):
                raise ValueError(f"Input {idx} signature failed independent verification")
            finalized.vin[idx].witness = transaction.Witness([signature, pub.sec()])
        raw_final = finalized.serialize()
        reparsed = transaction.Transaction.parse(raw_final)
        if (reparsed.txid() != parsed.tx.txid() or len(reparsed.vin) != len(parsed.inputs)
                or any(len(vin.witness.items) != 2 or vin.script_sig.data
                       for vin in reparsed.vin)):
            raise ValueError("Finalized transaction roundtrip failed")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("PSBT signing or signature validation failed") from exc
    return {
        "network": reviewed["network"], "recipient": reviewed["recipient"],
        "amount_sats": reviewed["amount_sats"], "fee_sats": reviewed["fee_sats"],
        "signature_count": count,
        "signed_psbt_base64": base64.b64encode(parsed.serialize()).decode(),
        "finalized_tx_hex": raw_final.hex(),
    }
