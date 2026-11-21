"""QR transport correlation only. NEVER treats a QR as signing authorization.

This module does not decode UR or perform cryptography. UR framing lives in
qr-transport/ using Blockchain Commons' maintained upstream implementation.
"""
import hashlib
import json
import re
import time
import uuid

MAX_BYTES = 150_000
MAX_AGE_SEC = 120
KINDS = {"btc": "bitcoin-testnet", "evm": "sepolia"}
REQUEST_KEYS = {"version", "direction", "network", "account", "request_id", "payload_digest", "payload"}
RESPONSE_KEYS = REQUEST_KEYS | {"request_digest"}
ACCOUNT_RE = re.compile(r"^[A-Za-z0-9:_-]{8,150}$")
FORBIDDEN = ("mnemonic", "passphrase", "private", "seed", "secret", "xprv", "password", "vault")
ID_RE = re.compile(r"^[0-9a-f]{32}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _validate_json(value, depth=0):
    if depth > 16:
        raise ValueError("QR data is too deeply nested")
    if isinstance(value, dict):
        if len(value) > 256:
            raise ValueError("QR map too large")
        for key, item in value.items():
            if type(key) is not str or not key.isascii() or len(key) > 128:
                raise ValueError("Invalid QR key")
            if any(word in key.lower() for word in FORBIDDEN):
                raise ValueError("QR cannot contain secret fields")
            _validate_json(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 1024:
            raise ValueError("QR list too large")
        for item in value:
            _validate_json(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > MAX_BYTES or not value.isascii():
            raise ValueError("QR strings must be bounded ASCII")
    elif type(value) not in (int, bool, type(None)):
        raise ValueError("QR JSON supports only integers, strings, booleans and null")


def _canonical(data):
    _validate_json(data)
    return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(data):
    return hashlib.sha256(_canonical(data)).hexdigest()


def _verify_bytes(value):
    if len(_canonical(value)) > MAX_BYTES:
        raise ValueError("QR message exceeds maximum size")


def _check(data, keys, direction):
    if type(data) is not dict or set(data) != keys or data["version"] != 1 or type(data["version"]) is not int:
        raise ValueError("Invalid QR protocol version or fields")
    if data["direction"] != direction or data["network"] not in KINDS.values():
        raise ValueError("Wrong QR direction or unsupported network")
    if type(data["account"]) is not str or ACCOUNT_RE.fullmatch(data["account"]) is None:
        raise ValueError("Invalid account identifier")
    if type(data["request_id"]) is not str or ID_RE.fullmatch(data["request_id"]) is None:
        raise ValueError("Invalid request ID")
    if type(data["payload_digest"]) is not str or HASH_RE.fullmatch(data["payload_digest"]) is None:
        raise ValueError("Invalid payload digest")
    if _digest(data["payload"]) != data["payload_digest"]:
        raise ValueError("QR payload digest mismatch")
    if direction == "signed" and (type(data["request_digest"]) is not str or
                                  HASH_RE.fullmatch(data["request_digest"]) is None):
        raise ValueError("Invalid original request digest")
    _verify_bytes(data)


def make_request(network: str, account: str, payload, *, request_id=None):
    if network not in KINDS.values():
        raise ValueError("QR transport supports testnet / Sepolia only")
    data = {"version": 1, "direction": "unsigned", "network": network,
            "account": account, "request_id": request_id or uuid.uuid4().hex,
            "payload_digest": _digest(payload), "payload": payload}
    _check(data, REQUEST_KEYS, "unsigned")
    return data


def make_response(request, signed_payload):
    _check(request, REQUEST_KEYS, "unsigned")
    result = {"version": 1, "direction": "signed",
              "network": request["network"], "account": request["account"],
              "request_id": request["request_id"], "request_digest": _digest(request),
              "payload_digest": _digest(signed_payload), "payload": signed_payload}
    _check(result, RESPONSE_KEYS, "signed")
    return result


class QRSession:
    """Volatile in-memory session, one request / one successful response."""

    def __init__(self, request, *, now=None, ttl=MAX_AGE_SEC):
        _check(request, REQUEST_KEYS, "unsigned")
        if type(ttl) is not int or not 0 < ttl <= MAX_AGE_SEC:
            raise ValueError("Invalid session lifetime")
        # Freeze the canonical request to prevent caller-side mutations from
        # changing what a pending signing session is bound to.
        self._request_bytes = _canonical(request)
        self.started = time.monotonic() if now is None else now
        self.ttl = ttl
        self.state = "pending"

    def cancel(self):
        self.state = "cancelled"

    def check_response(self, response, *, now=None, verify_signature=None):
        if self.state != "pending":
            raise ValueError("Cancelled, expired or already-consumed QR session")
        current = time.monotonic() if now is None else now
        if current < self.started or current - self.started > self.ttl:
            self.state = "expired"
            raise ValueError("QR session expired")
        _check(response, RESPONSE_KEYS, "signed")
        original = json.loads(self._request_bytes)
        if (response["request_id"] != original["request_id"] or
                response["network"] != original["network"] or
                response["account"] != original["account"] or
                response["request_digest"] != _digest(original)):
            raise ValueError("Signed response does not match pending request")
        # A signature verifier MUST parse the raw signed tx/PSBT, check sender,
        # recipient, chain, fee and exact original unsigned payload.
        if verify_signature is None or not callable(verify_signature):
            raise ValueError("Independent chain-specific signed transaction verifier required")
        if verify_signature(original, response) is not True:
            raise ValueError("Signed transaction failed verification against request")
        self.state = "consumed"
        return response["payload"]
