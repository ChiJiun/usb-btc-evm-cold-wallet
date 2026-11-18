"""Untrusted USB file exchange: strict schema, size bounds, SHA-256 corruption check.

The digest is NOT an authentication signature. Every transaction still needs an
independent recipient/amount policy check on the offline screen/terminal.
"""
import hashlib
import hmac
import json
import os
import stat
from pathlib import Path

from .vault import save_vault

FORMAT = "usb-cold-wallet-exchange"
VERSION = 1
MAX_BYTES = 200_000
KINDS = {
    "btc-request": "bitcoin-testnet",
    "btc-signed": "bitcoin-testnet",
    "evm-request": "sepolia",
    "evm-signed": "sepolia",
    "watch-only": "testnet-sepolia",
}
FORBIDDEN_KEYS = {"mnemonic", "seed", "private_key", "privatekey", "secret", "xprv", "vault", "passphrase", "password"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _no_secrets(value, depth=0):
    if depth > 16:
        raise ValueError("Exchange payload nesting limit exceeded")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Exchange object keys must be strings")
            normalized = key.lower().replace("-", "_")
            if (normalized in FORBIDDEN_KEYS or any(token in normalized for token in
                    ("mnemonic", "passphrase", "private", "seed", "secret", "xprv", "password"))):
                raise ValueError("Secret field is forbidden in exchange data")
            _no_secrets(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _no_secrets(item, depth + 1)
    elif value is not None and type(value) not in (str, int, bool, float):
        raise ValueError("Unsupported exchange payload value")


def _validate_payload(kind, payload):
    if kind == "btc-request":
        if not isinstance(payload, str) or not payload.strip() or len(payload) > 180_000:
            raise ValueError("BTC request must be a bounded base64 PSBT")
    elif not isinstance(payload, dict):
        raise ValueError("Expected JSON object for this exchange kind")
    if kind == "evm-request" and (payload.get("chainId") != 11155111 or type(payload.get("chainId")) is not int):
        raise ValueError("Exchange EVM request must target Sepolia")
    if kind == "watch-only" and (set(payload) != {"bitcoin", "evm"}
            or not isinstance(payload["bitcoin"], dict)
            or not isinstance(payload["evm"], dict)
            or payload["bitcoin"].get("network") != "testnet"
            or payload["evm"].get("chain_id") != 11155111):
        raise ValueError("Watch-only network mismatch")
    if kind == "btc-signed" and payload.get("network") != "bitcoin-testnet":
        raise ValueError("Signed BTC network mismatch")
    if kind == "evm-signed" and (type(payload.get("chain_id")) is not int or payload["chain_id"] != 11155111):
        raise ValueError("Signed EVM network mismatch")
    _no_secrets(payload)


def package(kind: str, payload):
    if kind not in KINDS:
        raise ValueError("Unrecognized exchange kind")
    _validate_payload(kind, payload)
    content = {"format": FORMAT, "version": VERSION, "kind": kind,
               "network": KINDS[kind], "payload": payload}
    encoded = _canonical(content)
    if len(encoded) > MAX_BYTES:
        raise ValueError("Exchange exceeds maximum size")
    return {**content, "sha256": hashlib.sha256(encoded).hexdigest()}


def verify(data, expected_kind=None):
    if not isinstance(data, dict) or set(data) != {
        "format", "version", "kind", "network", "payload", "sha256"
    }:
        raise ValueError("Invalid exchange envelope fields")
    kind = data["kind"]
    if (data["format"] != FORMAT or type(data["version"]) is not int or
            data["version"] != VERSION or kind not in KINDS or
            data["network"] != KINDS[kind] or
            (expected_kind is not None and kind != expected_kind)):
        raise ValueError("Exchange format, type, or network mismatch")
    _validate_payload(kind, data["payload"])
    content = {field: data[field] for field in ("format", "version", "kind", "network", "payload")}
    encoded = _canonical(content)
    if len(encoded) > MAX_BYTES:
        raise ValueError("Exchange exceeds maximum size")
    digest = hashlib.sha256(encoded).hexdigest()
    if type(data["sha256"]) is not str or not hmac.compare_digest(digest, data["sha256"]):
        raise ValueError("Exchange SHA-256 integrity check failed")
    return data["payload"]


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key in exchange envelope")
        result[key] = value
    return result


def read_bounded(path: Path, limit=MAX_BYTES + 8192):
    """Read a single regular file once, never follow a symbolic link or block on devices."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(Path(path), flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Transfer must be a regular file, not a device or pipe")
        raw = os.read(fd, limit + 1)
        if len(raw) > limit:
            raise ValueError("Exchange file too large")
        return raw
    finally:
        os.close(fd)


def read_envelope(path: Path, expected_kind=None):
    raw = read_bounded(path)
    try:
        data = json.loads(raw.decode("utf-8"),
                          object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON number")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid exchange JSON") from exc
    verify(data, expected_kind)
    return data


def read(path: Path, expected_kind=None):
    return read_envelope(path, expected_kind)["payload"]


def write(path: Path, kind: str, payload):
    save_vault(path, package(kind, payload))
