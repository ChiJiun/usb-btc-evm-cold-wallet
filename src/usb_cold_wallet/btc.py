"""Conservative Bitcoin testnet PSBT v0 P2WPKH signer with explicit recipient/fee policy."""
import base64
from embit import psbt, script, networks
from .keys import btc_key, btc_address

_MAX_INPUTS = 20
_MAX_OUTPUTS = 2
_SEARCH_LIMIT = 100  # account discovery should be made explicit in a later version


def _read_psbt(payload: str):
    try:
        parsed = psbt.PSBT.parse(base64.b64decode(payload.strip(), validate=True))
    except Exception as exc:
        raise ValueError("Invalid base64 PSBT") from exc
    if parsed.version is not None or len(parsed.inputs) < 1 or len(parsed.inputs) > _MAX_INPUTS:
        raise ValueError("Only PSBT v0 with 1..20 inputs supported")
    if not 1 <= len(parsed.tx.vout) <= _MAX_OUTPUTS:
        raise ValueError("Only one recipient and optional one change output supported")
    return parsed


def review_btc_psbt(root, psbt_b64: str, expected_recipient: str, expected_sats: int,
                    max_fee_sats: int, change_index: int | None = None) -> dict:
    parsed = _read_psbt(psbt_b64)
    if type(expected_sats) is not int or expected_sats <= 0:
        raise ValueError("expected_sats must be positive")
    if type(max_fee_sats) is not int or max_fee_sats < 0:
        raise ValueError("max_fee_sats must be non-negative")
    if change_index is not None and (type(change_index) is not int or not 0 <= change_index <= 999):
        raise ValueError("Invalid change index")
    allowed_input_scripts = {
        script.p2wpkh(btc_key(root, branch, i).key).data
        for branch in (0, 1) for i in range(_SEARCH_LIMIT)
    }
    for idx, inp in enumerate(parsed.inputs):
        if inp.sighash_type not in (None, 1):
            raise ValueError("Only SIGHASH_ALL supported")
        if inp.witness_utxo is None:
            raise ValueError("Every input must provide witness_utxo")
        if inp.witness_utxo.script_pubkey.data not in allowed_input_scripts:
            raise ValueError(f"Input {idx} is not a recognized wallet P2WPKH input")
    try:
        target_script = script.address_to_scriptpubkey(expected_recipient).data
    except Exception as exc:
        raise ValueError("Invalid BTC recipient address") from exc
    if script.Script(target_script).address(networks.NETWORKS["test"]) != expected_recipient:
        raise ValueError("Recipient must be a Bitcoin testnet address")
    change_script = (
        script.p2wpkh(btc_key(root, 1, change_index).key).data if change_index is not None else None
    )
    recipient_hits = 0
    change_hits = 0
    for output in parsed.tx.vout:
        if output.value <= 0:
            raise ValueError("Nonpositive output value")
        if output.script_pubkey.data == target_script and output.value == expected_sats:
            recipient_hits += 1
        elif change_script is not None and output.script_pubkey.data == change_script:
            change_hits += 1
        else:
            raise ValueError("Unexpected recipient, amount, or change address")
    if recipient_hits != 1 or change_hits > 1:
        raise ValueError("Exactly one expected recipient output required")
    try:
        fee = parsed.fee()
    except Exception as exc:
        raise ValueError("PSBT does not contain enough UTXO information") from exc
    if not 0 <= fee <= max_fee_sats:
        raise ValueError(f"Fee {fee} sats outside accepted range")
    return {
        "psbt": parsed,
        "network": "bitcoin-testnet",
        "recipient": expected_recipient,
        "amount_sats": expected_sats,
        "change_sats": next((o.value for o in parsed.tx.vout if change_script is not None and o.script_pubkey.data == change_script), 0),
        "fee_sats": fee,
        "input_count": len(parsed.inputs),
    }


def sign_btc_psbt(root, psbt_b64: str, expected_recipient: str, expected_sats: int,
                  max_fee_sats: int, change_index: int | None = None) -> dict:
    reviewed = review_btc_psbt(root, psbt_b64, expected_recipient, expected_sats, max_fee_sats, change_index)
    parsed = reviewed["psbt"]
    count = parsed.sign_with(root)
    if count != len(parsed.inputs) or any(not inp.partial_sigs for inp in parsed.inputs):
        raise ValueError("PSBT lacks valid wallet BIP32 derivation paths; not fully signed")
    return {
        "network": reviewed["network"],
        "recipient": reviewed["recipient"],
        "amount_sats": reviewed["amount_sats"],
        "fee_sats": reviewed["fee_sats"],
        "signature_count": count,
        "signed_psbt_base64": base64.b64encode(parsed.serialize()).decode(),
    }
