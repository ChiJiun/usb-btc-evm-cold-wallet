"""Versioned single-USB cross-boot transaction protocol.

The FAT32 exchange area and the online host are untrusted transports.  V2 binds
an immutable request identity and transaction facts across reboot, but does not
authenticate the online host.  Signing policy and human review remain in the
existing BTC/EVM paths.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Any

from eth_utils import to_checksum_address

from . import exchange
from .btc import _read_psbt
from .evm import decode_signed_eip1559, review_evm_transaction, review_signed_evm_transaction

VERSION = 2
REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
BTC_ACCOUNT_RE = re.compile(r"^[0-9a-f]{8}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
REQUEST_KINDS = {"btc-request", "evm-request"}
RESPONSE_KINDS = {"btc-signed", "evm-signed"}
REQUEST_TO_RESPONSE = {"btc-request": "btc-signed", "evm-request": "evm-signed"}
MAX_UTXOS = 20

_REQUEST_FIELDS = {
    "format", "version", "kind", "network", "requestId", "account",
    "transactionDigest", "intent", "expiry", "payload", "sha256",
}
_RESPONSE_FIELDS = {
    "format", "version", "kind", "network", "requestId", "account",
    "transactionDigest", "requestEnvelopeDigest", "signedResultDigest",
    "expiryAssurance", "payload", "sha256",
}


def _canonical(value: Any) -> bytes:
    return exchange._canonical(value)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _envelope_sha(data: dict) -> str:
    return _sha({key: value for key, value in data.items() if key != "sha256"})


def _request_id(value: Any) -> str:
    if type(value) is not str or REQUEST_ID_RE.fullmatch(value) is None:
        raise ValueError("requestId must be 128-bit lowercase hex")
    return value


def _account(kind: str, value: Any) -> str:
    if type(value) is not str:
        raise ValueError("Invalid request account")
    if kind == "evm-request":
        try:
            if to_checksum_address(value) != value:
                raise ValueError("EVM request account must be checksummed")
        except Exception as exc:
            raise ValueError("Invalid EVM request account") from exc
        return value
    if BTC_ACCOUNT_RE.fullmatch(value) is None:
        raise ValueError("Bitcoin request account must be master fingerprint hex")
    return value


def _expiry(value: Any, *, trusted_time: int | None, allow_no_trusted_clock: bool) -> str:
    if type(value) is not dict or set(value) != {"mode", "notAfter"}:
        raise ValueError("Invalid expiry policy")
    mode = value["mode"]
    not_after = value["notAfter"]
    if mode == "trusted-time":
        if type(not_after) is not int or not 0 <= not_after <= (1 << 53) - 1:
            raise ValueError("Invalid expiry timestamp")
        if type(trusted_time) is not int or trusted_time < 0:
            raise ValueError("Trusted time required for expiry validation")
        if trusted_time > not_after:
            raise ValueError("Cross-boot request expired")
        return "trusted-time"
    if mode == "no-trusted-clock":
        if not_after is not None:
            raise ValueError("No-clock mode cannot claim a wall-clock expiry")
        if not allow_no_trusted_clock:
            raise ValueError("No trusted clock: restricted mode was not explicitly enabled")
        return "unverified"
    raise ValueError("Unsupported expiry mode")


def _transaction_digest(kind: str, payload: Any) -> str:
    if kind == "btc-request":
        raw = exchange._psbt_base64(payload, "BTC request")
        return hashlib.sha256(raw).hexdigest()
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _btc_intent(payload: str, account: str, recipient: str, amount: int) -> dict:
    exchange._btc_address(recipient)
    exchange._int(amount, "Bitcoin amount", 1, exchange._MAX_MONEY)
    parsed = _read_psbt(payload)
    if not 1 <= len(parsed.inputs) <= MAX_UTXOS:
        raise ValueError("Bitcoin input count out of bounds")
    input_total = 0
    utxos = []
    for index, scope in enumerate(parsed.inputs):
        if scope.witness_utxo is None or scope.non_witness_utxo is None:
            raise ValueError("Bitcoin request requires witness and non-witness UTXO")
        vin = parsed.tx.vin[index]
        if scope.non_witness_utxo.txid() != vin.txid:
            raise ValueError("Bitcoin previous transaction mismatch")
        if not 0 <= vin.vout < len(scope.non_witness_utxo.vout):
            raise ValueError("Bitcoin prevout index out of range")
        prev = scope.non_witness_utxo.vout[vin.vout]
        if (prev.value != scope.witness_utxo.value or
                prev.script_pubkey.data != scope.witness_utxo.script_pubkey.data):
            raise ValueError("Bitcoin UTXO metadata mismatch")
        if len(scope.bip32_derivations) != 1:
            raise ValueError("Bitcoin request needs one BIP32 origin per input")
        origin = next(iter(scope.bip32_derivations.values()))
        if origin.fingerprint.hex() != account:
            raise ValueError("Bitcoin input account fingerprint mismatch")
        input_total += prev.value
        utxos.append({"txid": vin.txid.hex(), "vout": vin.vout, "value": prev.value})
    output_total = sum(out.value for out in parsed.tx.vout)
    fee = input_total - output_total
    if fee < 0:
        raise ValueError("Bitcoin request has negative fee")
    hits = 0
    for out in parsed.tx.vout:
        try:
            address = out.script_pubkey.address(exchange._BTC_NETWORK)
        except Exception:
            continue
        if address == recipient and out.value == amount:
            hits += 1
    if hits != 1:
        raise ValueError("Bitcoin recipient/amount must occur exactly once")
    return {
        "recipient": recipient,
        "amount": amount,
        "fee": fee,
        "nonce": None,
        "utxos": utxos,
    }


def _evm_intent(payload: dict, account: str, recipient: str, amount: int) -> dict:
    reviewed = review_evm_transaction(payload, recipient, amount)["transaction"]
    if reviewed["chainId"] != 11155111:
        raise ValueError("Sepolia request required")
    fee = reviewed["gas"] * reviewed["maxFeePerGas"]
    return {
        "recipient": reviewed["to"],
        "amount": reviewed["value"],
        "fee": fee,
        "nonce": reviewed["nonce"],
        "utxos": [],
    }


def package_v2_request(
    kind: str,
    payload: Any,
    *,
    request_id: str,
    account: str,
    recipient: str,
    amount: int,
    expiry: dict,
) -> dict:
    """Create a v2 request while deriving immutable transaction facts.

    The caller supplies the independently intended recipient/amount. Existing
    review code proves those values against the raw transaction/PSBT.
    """
    if kind not in REQUEST_KINDS:
        raise ValueError("V2 request kind must be BTC or EVM unsigned transaction")
    exchange._validate_payload(kind, payload)
    request_id = _request_id(request_id)
    account = _account(kind, account)
    # Packaging may carry either expiry mode; enforcement happens on import.
    if type(expiry) is not dict or set(expiry) != {"mode", "notAfter"}:
        raise ValueError("Invalid expiry policy")
    if expiry["mode"] == "trusted-time":
        if type(expiry["notAfter"]) is not int or not 0 <= expiry["notAfter"] <= (1 << 53) - 1:
            raise ValueError("Invalid expiry timestamp")
    elif expiry != {"mode": "no-trusted-clock", "notAfter": None}:
        raise ValueError("Invalid no-clock expiry policy")

    intent = (_evm_intent(payload, account, recipient, amount)
              if kind == "evm-request"
              else _btc_intent(payload, account, recipient, amount))
    content = {
        "format": exchange.FORMAT,
        "version": VERSION,
        "kind": kind,
        "network": exchange.KINDS[kind],
        "requestId": request_id,
        "account": account,
        "transactionDigest": _transaction_digest(kind, payload),
        "intent": intent,
        "expiry": expiry,
        "payload": payload,
    }
    encoded = _canonical(content)
    if len(encoded) > exchange.MAX_BYTES:
        raise ValueError("Exchange exceeds maximum size")
    return {**content, "sha256": hashlib.sha256(encoded).hexdigest()}


def verify_v2_request(
    data: dict,
    expected_kind: str | None = None,
    *,
    trusted_time: int | None = None,
    allow_no_trusted_clock: bool = False,
) -> dict:
    if type(data) is not dict or set(data) != _REQUEST_FIELDS:
        raise ValueError("Invalid v2 request envelope fields")
    kind = data["kind"]
    if (data["format"] != exchange.FORMAT or data["version"] != VERSION or
            kind not in REQUEST_KINDS or data["network"] != exchange.KINDS[kind] or
            (expected_kind is not None and expected_kind != kind)):
        raise ValueError("V2 request format, type, or network mismatch")
    _request_id(data["requestId"])
    account = _account(kind, data["account"])
    exchange._validate_payload(kind, data["payload"])
    if (type(data["transactionDigest"]) is not str or
            HEX64_RE.fullmatch(data["transactionDigest"]) is None or
            not hmac.compare_digest(data["transactionDigest"], _transaction_digest(kind, data["payload"]))):
        raise ValueError("V2 request transaction digest mismatch")
    intent = (_evm_intent(
        data["payload"], account, data["intent"].get("recipient"), data["intent"].get("amount")
    ) if kind == "evm-request" else _btc_intent(
        data["payload"], account, data["intent"].get("recipient"), data["intent"].get("amount")
    )) if type(data["intent"]) is dict else None
    if intent is None or data["intent"] != intent:
        raise ValueError("V2 request intent does not match raw transaction")
    assurance = _expiry(
        data["expiry"], trusted_time=trusted_time,
        allow_no_trusted_clock=allow_no_trusted_clock,
    )
    expected_sha = _envelope_sha(data)
    if (type(data["sha256"]) is not str or HEX64_RE.fullmatch(data["sha256"]) is None or
            not hmac.compare_digest(data["sha256"], expected_sha)):
        raise ValueError("V2 request envelope integrity check failed")
    return {**data, "expiryAssurance": assurance}


def _verify_evm_signed_binding(request: dict, payload: dict) -> None:
    exchange._validate_payload("evm-signed", payload)
    raw = payload["signed_raw_transaction"]
    decoded = decode_signed_eip1559(raw)
    checked = review_signed_evm_transaction(
        raw, request["intent"]["recipient"], request["intent"]["amount"]
    )
    unsigned = review_evm_transaction(
        request["payload"], request["intent"]["recipient"], request["intent"]["amount"]
    )["transaction"]
    signed_as_unsigned = {
        "type": decoded["type"],
        "chainId": decoded["chain_id"],
        "nonce": decoded["nonce"],
        "to": decoded["to"],
        "value": decoded["value_wei"],
        "gas": decoded["gas"],
        "maxFeePerGas": decoded["max_fee_per_gas"],
        "maxPriorityFeePerGas": decoded["max_priority_fee_per_gas"],
        "data": decoded["data"],
        "accessList": decoded["access_list"],
    }
    if signed_as_unsigned != unsigned:
        raise ValueError("Signed EVM result changed unsigned transaction")
    if checked["from"].lower() != request["account"].lower():
        raise ValueError("Signed EVM account mismatch")


def _verify_btc_signed_binding(request: dict, payload: dict) -> None:
    exchange._validate_payload("btc-signed", payload)
    initial = _read_psbt(request["payload"])
    final = _read_psbt(payload["signed_psbt_base64"])
    if initial.tx.serialize() != final.tx.serialize() or len(initial.inputs) != len(final.inputs):
        raise ValueError("Signed Bitcoin result changed unsigned transaction")
    for before, after in zip(initial.inputs, final.inputs, strict=True):
        if (before.witness_utxo is None or after.witness_utxo is None or
                before.witness_utxo.serialize() != after.witness_utxo.serialize()):
            raise ValueError("Signed Bitcoin UTXO changed")
        if len(after.partial_sigs) != 1:
            raise ValueError("Signed Bitcoin input signature missing")
        pub = next(iter(after.partial_sigs))
        if (pub not in after.bip32_derivations or
                after.bip32_derivations[pub].fingerprint.hex() != request["account"]):
            raise ValueError("Signed Bitcoin account fingerprint mismatch")


def package_v2_response(
    request: dict,
    signed_payload: dict,
    *,
    trusted_time: int | None = None,
    allow_no_trusted_clock: bool = False,
) -> dict:
    checked = verify_v2_request(
        request, trusted_time=trusted_time, allow_no_trusted_clock=allow_no_trusted_clock
    )
    response_kind = REQUEST_TO_RESPONSE[request["kind"]]
    if response_kind == "evm-signed":
        _verify_evm_signed_binding(request, signed_payload)
    else:
        _verify_btc_signed_binding(request, signed_payload)
    content = {
        "format": exchange.FORMAT,
        "version": VERSION,
        "kind": response_kind,
        "network": request["network"],
        "requestId": request["requestId"],
        "account": request["account"],
        "transactionDigest": request["transactionDigest"],
        "requestEnvelopeDigest": _sha(request),
        "signedResultDigest": _sha(signed_payload),
        "expiryAssurance": checked["expiryAssurance"],
        "payload": signed_payload,
    }
    encoded = _canonical(content)
    if len(encoded) > exchange.MAX_BYTES:
        raise ValueError("Exchange exceeds maximum size")
    return {**content, "sha256": hashlib.sha256(encoded).hexdigest()}


def verify_v2_response(
    request: dict,
    response: dict,
    *,
    trusted_time: int | None = None,
    allow_no_trusted_clock: bool = False,
) -> dict:
    checked_request = verify_v2_request(
        request, trusted_time=trusted_time, allow_no_trusted_clock=allow_no_trusted_clock
    )
    if type(response) is not dict or set(response) != _RESPONSE_FIELDS:
        raise ValueError("Invalid v2 signed response fields")
    expected_kind = REQUEST_TO_RESPONSE[request["kind"]]
    if (response["format"] != exchange.FORMAT or response["version"] != VERSION or
            response["kind"] != expected_kind or response["network"] != request["network"] or
            response["requestId"] != request["requestId"] or
            response["account"] != request["account"] or
            response["transactionDigest"] != request["transactionDigest"] or
            response["expiryAssurance"] != checked_request["expiryAssurance"]):
        raise ValueError("Signed response does not match pending request")
    if not hmac.compare_digest(response["requestEnvelopeDigest"], _sha(request)):
        raise ValueError("Signed response request digest mismatch")
    if not hmac.compare_digest(response["signedResultDigest"], _sha(response["payload"])):
        raise ValueError("Signed response result digest mismatch")
    if not hmac.compare_digest(response["sha256"], _envelope_sha(response)):
        raise ValueError("Signed response envelope integrity check failed")
    if expected_kind == "evm-signed":
        _verify_evm_signed_binding(request, response["payload"])
    else:
        _verify_btc_signed_binding(request, response["payload"])
    return response["payload"]
