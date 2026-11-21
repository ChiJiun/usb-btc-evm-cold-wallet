"""Public-only USB exchange envelope used by the Windows Companion.

The offline signer independently validates each payload using exchange.py.
No vault, signing, recovery, or offline transaction modules may be imported here.
"""
from __future__ import annotations

import hashlib
import hmac
import json

FORMAT = "usb-cold-wallet-exchange"
VERSION = 1
MAX_BYTES = 200_000
NETWORKS = {
    "watch-only": "testnet-sepolia",
    "evm-request": "sepolia",
    "evm-signed": "sepolia",
    "btc-request": "bitcoin-testnet",
    "btc-signed": "bitcoin-testnet",
}
FORBIDDEN = ("mnemonic", "passphrase", "private", "seed", "secret", "xprv", "password", "vault")


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _public(value, depth=0):
    if depth > 16:
        raise ValueError("Exchange payload nesting limit exceeded")
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or any(token in key.lower().replace("-", "_") for token in FORBIDDEN):
                raise ValueError("Secret or invalid exchange key")
            _public(item, depth + 1)
    elif type(value) is list:
        for item in value:
            _public(item, depth + 1)
    elif value is not None and type(value) not in (str, int, bool):
        raise ValueError("Invalid public exchange value")


def _validate_payload(kind, payload):
    """Validate public wire schema; final signed-byte verification is caller-owned."""
    if kind == "evm-request":
        required = {"type", "chainId", "nonce", "to", "value", "gas",
                    "maxFeePerGas", "maxPriorityFeePerGas"}
        if (type(payload) is not dict or
                not required <= payload.keys() or
                payload.keys() - required - {"data", "accessList"}):
            raise ValueError("Unexpected EVM request fields")
        ints = ("type", "chainId", "nonce", "value", "gas", "maxFeePerGas", "maxPriorityFeePerGas")
        if any(type(payload[k]) is not int for k in ints):
            raise ValueError("Invalid EVM request quantity")
        if (payload["type"] != 2 or payload["chainId"] != 11155111 or
                not 0 <= payload["nonce"] <= 2**53 - 1 or
                not 1 <= payload["value"] < 2**256 or
                payload["gas"] != 21000 or
                not 1 <= payload["maxFeePerGas"] <= 1_000_000_000_000 or
                not 0 <= payload["maxPriorityFeePerGas"] <= payload["maxFeePerGas"] or
                payload.get("data", "0x") not in ("0x", "") or
                payload.get("accessList", []) != []):
            raise ValueError("Invalid Sepolia EVM request")
        import re
        from eth_utils import to_checksum_address
        address = payload["to"]
        if (type(address) is not str or
                not re.fullmatch(r"0x[0-9a-fA-F]{40}", address) or
                address != to_checksum_address(address)):
            raise ValueError("EVM recipient must be checksummed")
    elif kind == "btc-request":
        if type(payload) is not str or not 0 < len(payload) <= 180_000:
            raise ValueError("Invalid BTC PSBT request")
        import base64
        import binascii
        try:
            raw = base64.b64decode(payload, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("Invalid BTC PSBT base64") from exc
        if not raw.startswith(b"psbt\xff") or len(raw) > 130_000:
            raise ValueError("Invalid BTC PSBT framing")
    elif kind in ("evm-signed", "btc-signed", "watch-only"):
        if type(payload) is not dict:
            raise ValueError("Invalid signed/public exchange fields")


def package(kind, payload):
    if type(kind) is not str or kind not in NETWORKS:
        raise ValueError("Unknown exchange kind")
    _public(payload)
    _validate_payload(kind, payload)
    content = {"format": FORMAT, "version": VERSION, "kind": kind,
               "network": NETWORKS[kind], "payload": payload}
    encoded = _canonical(content)
    if len(encoded) > MAX_BYTES:
        raise ValueError("Exchange exceeds maximum size")
    return {**content, "sha256": hashlib.sha256(encoded).hexdigest()}


def verify(data, kind):
    if type(data) is not dict or set(data) != {
        "format", "version", "kind", "network", "payload", "sha256"
    }:
        raise ValueError("Invalid exchange envelope fields")
    if (type(kind) is not str or kind not in NETWORKS or
            data["format"] != FORMAT or type(data["version"]) is not int or
            data["version"] != VERSION or type(data["kind"]) is not str or
            data["kind"] != kind or data["network"] != NETWORKS[kind]):
        raise ValueError("Exchange format, kind, or network mismatch")
    _public(data["payload"])
    _validate_payload(kind, data["payload"])
    content = {field: data[field] for field in ("format", "version", "kind", "network", "payload")}
    encoded = _canonical(content)
    if len(encoded) > MAX_BYTES:
        raise ValueError("Exchange exceeds maximum size")
    expected = hashlib.sha256(encoded).hexdigest()
    if type(data["sha256"]) is not str or not hmac.compare_digest(expected, data["sha256"]):
        raise ValueError("Exchange SHA-256 integrity check failed")
    return data["payload"]
