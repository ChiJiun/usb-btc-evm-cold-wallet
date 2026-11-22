"""Signer-independent canonical v2 cross-boot request codec.

This module is deliberately public-only so the Windows Companion and cold signer
consume exactly one request schema/digest/intent implementation without pulling
keys, vault, signer, policy, or network code across the trust boundary.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
from typing import Any

from embit import networks, psbt
from eth_utils import to_checksum_address

VERSION = 2
FORMAT = "usb-cold-wallet-exchange"
MAX_BYTES = 200_000
MAX_UTXOS = 20
REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
BTC_ACCOUNT_RE = re.compile(r"^[0-9a-f]{8}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
REQUEST_KINDS = {"btc-request", "evm-request"}
REQUEST_TO_RESPONSE = {"btc-request": "btc-signed", "evm-request": "evm-signed"}
NETWORK = {"btc-request": "bitcoin-testnet", "evm-request": "sepolia"}
REQUEST_FIELDS = {
    "format", "version", "kind", "network", "requestId", "account",
    "transactionDigest", "intent", "expiry", "payload", "sha256",
}
RESPONSE_FIELDS = {
    "format", "version", "kind", "network", "requestId", "account",
    "transactionDigest", "requestEnvelopeDigest", "signedResultDigest",
    "expiryAssurance", "payload", "sha256",
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def sha_value(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def envelope_sha(data: dict) -> str:
    return sha_value({key: value for key, value in data.items() if key != "sha256"})


def new_request_id() -> str:
    return secrets.token_hex(16)


def parse_psbt(value: str):
    if not isinstance(value, str) or not value or len(value) > 180_000:
        raise ValueError("BTC PSBT size invalid")
    try:
        raw = base64.b64decode(value, validate=True)
        parsed = psbt.PSBT.parse(raw)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("BTC PSBT invalid") from exc
    except Exception as exc:
        raise ValueError("BTC PSBT cannot be parsed") from exc
    if not raw.startswith(b"psbt\xff") or parsed.version is not None or parsed.serialize() != raw:
        raise ValueError("BTC PSBT must be canonical v0")
    return parsed, raw


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
    mode, not_after = value["mode"], value["notAfter"]
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


def _evm_intent(payload: dict, recipient: str, amount: int) -> dict:
    if type(payload) is not dict:
        raise ValueError("EVM request payload invalid")
    required = {"type", "chainId", "nonce", "to", "value", "gas",
                "maxFeePerGas", "maxPriorityFeePerGas"}
    if required - payload.keys() or set(payload) - required - {"data", "accessList"}:
        raise ValueError("Unsupported EVM request fields")
    if payload["type"] != 2 or payload["chainId"] != 11155111:
        raise ValueError("Sepolia EIP-1559 request required")
    for field in ("nonce", "value", "gas", "maxFeePerGas", "maxPriorityFeePerGas"):
        if type(payload[field]) is not int or payload[field] < 0:
            raise ValueError(f"Invalid EVM {field}")
    if payload["value"] < 1 or payload["gas"] != 21_000:
        raise ValueError("Unsupported EVM value/gas policy")
    if payload["maxFeePerGas"] < 1 or payload["maxFeePerGas"] > 1_000_000_000_000:
        raise ValueError("Invalid EVM maxFeePerGas")
    if payload["maxPriorityFeePerGas"] > payload["maxFeePerGas"]:
        raise ValueError("Invalid EVM priority fee")
    if payload.get("data", "0x") not in ("", "0x") or payload.get("accessList", []) != []:
        raise ValueError("Contract data/access list is not supported")
    try:
        actual = to_checksum_address(payload["to"])
        expected = to_checksum_address(recipient)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid EVM recipient") from exc
    if payload["to"] != actual:
        raise ValueError("Ethereum address must be checksummed")
    if actual != expected or type(amount) is not int or payload["value"] != amount:
        raise ValueError("EVM recipient/amount mismatch")
    return {
        "recipient": actual, "amount": amount,
        "fee": payload["gas"] * payload["maxFeePerGas"],
        "nonce": payload["nonce"], "utxos": [],
    }


def _btc_intent(payload: str, account: str, recipient: str, amount: int) -> dict:
    parsed, _raw = parse_psbt(payload)
    if BTC_ACCOUNT_RE.fullmatch(account or "") is None:
        raise ValueError("BTC account fingerprint invalid")
    if type(amount) is not int or not 1 <= amount <= 21_000_000 * 100_000_000:
        raise ValueError("Bitcoin amount invalid")
    if not 1 <= len(parsed.inputs) <= MAX_UTXOS:
        raise ValueError("Bitcoin input count out of bounds")
    input_total, utxos = 0, []
    for index, scope in enumerate(parsed.inputs):
        if scope.witness_utxo is None or scope.non_witness_utxo is None:
            raise ValueError("Bitcoin request requires witness and non-witness UTXO")
        vin = parsed.tx.vin[index]
        if scope.non_witness_utxo.txid() != vin.txid or not 0 <= vin.vout < len(scope.non_witness_utxo.vout):
            raise ValueError("Bitcoin previous transaction mismatch")
        prev = scope.non_witness_utxo.vout[vin.vout]
        if (prev.value != scope.witness_utxo.value
                or prev.script_pubkey.data != scope.witness_utxo.script_pubkey.data):
            raise ValueError("Bitcoin UTXO metadata mismatch")
        if len(scope.bip32_derivations) != 1:
            raise ValueError("Bitcoin request needs one BIP32 origin per input")
        origin = next(iter(scope.bip32_derivations.values()))
        if origin.fingerprint.hex() != account:
            raise ValueError("Bitcoin input account fingerprint mismatch")
        input_total += prev.value
        utxos.append({"txid": vin.txid.hex(), "vout": vin.vout, "value": prev.value})
    fee = input_total - sum(out.value for out in parsed.tx.vout)
    if fee < 0:
        raise ValueError("Bitcoin request has negative fee")
    hits = 0
    for out in parsed.tx.vout:
        try:
            address = out.script_pubkey.address(networks.NETWORKS["test"])
        except Exception:
            continue
        if address == recipient and out.value == amount:
            hits += 1
    if hits != 1:
        raise ValueError("Bitcoin recipient/amount must occur exactly once")
    return {"recipient": recipient, "amount": amount, "fee": fee, "nonce": None, "utxos": utxos}


def transaction_digest(kind: str, payload: Any) -> str:
    if kind == "btc-request":
        _parsed, raw = parse_psbt(payload)
        return hashlib.sha256(raw).hexdigest()
    return hashlib.sha256(canonical(payload)).hexdigest()


def package_v2_request(kind: str, payload: Any, *, request_id: str, account: str,
                       recipient: str, amount: int, expiry: dict) -> dict:
    if kind not in REQUEST_KINDS:
        raise ValueError("V2 request kind must be BTC or EVM unsigned transaction")
    request_id = _request_id(request_id)
    account = _account(kind, account)
    if type(expiry) is not dict or set(expiry) != {"mode", "notAfter"}:
        raise ValueError("Invalid expiry policy")
    if expiry["mode"] == "trusted-time":
        if type(expiry["notAfter"]) is not int or not 0 <= expiry["notAfter"] <= (1 << 53) - 1:
            raise ValueError("Invalid expiry timestamp")
    elif expiry != {"mode": "no-trusted-clock", "notAfter": None}:
        raise ValueError("Invalid no-clock expiry policy")
    intent = (_evm_intent(payload, recipient, amount) if kind == "evm-request"
              else _btc_intent(payload, account, recipient, amount))
    content = {
        "format": FORMAT, "version": VERSION, "kind": kind, "network": NETWORK[kind],
        "requestId": request_id, "account": account,
        "transactionDigest": transaction_digest(kind, payload),
        "intent": intent, "expiry": expiry, "payload": payload,
    }
    encoded = canonical(content)
    if len(encoded) > MAX_BYTES:
        raise ValueError("Exchange exceeds maximum size")
    return {**content, "sha256": hashlib.sha256(encoded).hexdigest()}


def verify_v2_request(data: dict, expected_kind: str | None = None, *,
                      expected_account: str | None = None,
                      trusted_time: int | None = None,
                      allow_no_trusted_clock: bool = False) -> dict:
    if type(data) is not dict or set(data) != REQUEST_FIELDS:
        raise ValueError("Invalid v2 request envelope fields")
    kind = data["kind"]
    if (data["format"] != FORMAT or data["version"] != VERSION or kind not in REQUEST_KINDS
            or data["network"] != NETWORK[kind]
            or (expected_kind is not None and expected_kind != kind)):
        raise ValueError("V2 request format, type, or network mismatch")
    _request_id(data["requestId"])
    account = _account(kind, data["account"])
    if expected_account is not None and account != _account(kind, expected_account):
        raise ValueError("V2 request account does not match expected wallet")
    if type(data["transactionDigest"]) is not str or HEX64_RE.fullmatch(data["transactionDigest"]) is None:
        raise ValueError("V2 request transaction digest mismatch")
    if not hmac.compare_digest(data["transactionDigest"], transaction_digest(kind, data["payload"])):
        raise ValueError("V2 request transaction digest mismatch")
    intent = data["intent"]
    if type(intent) is not dict:
        raise ValueError("V2 request intent does not match raw transaction")
    derived = (_evm_intent(data["payload"], intent.get("recipient"), intent.get("amount"))
               if kind == "evm-request"
               else _btc_intent(data["payload"], account, intent.get("recipient"), intent.get("amount")))
    if intent != derived:
        raise ValueError("V2 request intent does not match raw transaction")
    assurance = _expiry(data["expiry"], trusted_time=trusted_time,
                        allow_no_trusted_clock=allow_no_trusted_clock)
    if (type(data["sha256"]) is not str or HEX64_RE.fullmatch(data["sha256"]) is None
            or not hmac.compare_digest(data["sha256"], envelope_sha(data))):
        raise ValueError("V2 request envelope integrity check failed")
    return {**data, "expiryAssurance": assurance}


def verify_v2_response_envelope(request: dict, response: dict, *,
                                expected_account: str | None = None,
                                trusted_time: int | None = None,
                                allow_no_trusted_clock: bool = False) -> dict:
    checked = verify_v2_request(
        request, expected_account=expected_account, trusted_time=trusted_time,
        allow_no_trusted_clock=allow_no_trusted_clock,
    )
    if type(response) is not dict or set(response) != RESPONSE_FIELDS:
        raise ValueError("Invalid v2 signed response fields")
    expected_kind = REQUEST_TO_RESPONSE[request["kind"]]
    if (response["format"] != FORMAT or response["version"] != VERSION
            or response["kind"] != expected_kind or response["network"] != request["network"]
            or response["requestId"] != request["requestId"]
            or response["account"] != request["account"]
            or response["transactionDigest"] != request["transactionDigest"]
            or response["expiryAssurance"] != checked["expiryAssurance"]):
        raise ValueError("Signed response does not match pending request")
    for field in ("requestEnvelopeDigest", "signedResultDigest", "sha256"):
        if type(response[field]) is not str or HEX64_RE.fullmatch(response[field]) is None:
            raise ValueError(f"Invalid signed response {field}")
    if not hmac.compare_digest(response["requestEnvelopeDigest"], sha_value(request)):
        raise ValueError("Signed response request digest mismatch")
    if not hmac.compare_digest(response["signedResultDigest"], sha_value(response["payload"])):
        raise ValueError("Signed response result digest mismatch")
    if not hmac.compare_digest(response["sha256"], envelope_sha(response)):
        raise ValueError("Signed response envelope integrity check failed")
    return response["payload"]
