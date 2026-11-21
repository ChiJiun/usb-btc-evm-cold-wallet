"""Ensure imported public envelopes enforce the same wire schema as exports."""
import base64
import hashlib
import json

import pytest

from usb_cold_wallet.companion_envelope import package, verify


def resign(envelope):
    """Simulate an attacker recomputing a non-authenticating integrity digest."""
    content = {key: envelope[key] for key in ("format", "version", "kind", "network", "payload")}
    raw = json.dumps(content, sort_keys=True, ensure_ascii=True,
                     separators=(",", ":"), allow_nan=False).encode("ascii")
    return {**content, "sha256": hashlib.sha256(raw).hexdigest()}


def test_valid_btc_request_roundtrip():
    # The wire-level guard checks magic/size; strict offline PSBT validation
    # remains the offline signer's responsibility.
    payload = base64.b64encode(b"psbt" + bytes([255, 0])).decode()
    assert verify(package("btc-request", payload), "btc-request") == payload


@pytest.mark.parametrize("invalid", [
    "not-base64",
    base64.b64encode(b"psbt\\xff").decode(),
    base64.b64encode(b"other" + bytes([255])).decode(),
])
def test_import_rejects_invalid_btc_request_even_with_valid_checksum(invalid):
    good = package("btc-request", base64.b64encode(b"psbt" + bytes([255, 0])).decode())
    with pytest.raises(ValueError, match="BTC PSBT"):
        verify(resign({**good, "payload": invalid}), "btc-request")


def test_import_rejects_invalid_evm_request_even_with_valid_checksum():
    request = {
        "type": 2, "chainId": 11155111, "nonce": 7,
        "to": "0x000000000000000000000000000000000000dEaD",
        "value": 10**18, "gas": 21000, "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000, "data": "0x",
    }
    original = package("evm-request", request)
    assert verify(original, "evm-request") == request
    with pytest.raises(ValueError, match="Sepolia"):
        verify(resign({**original, "payload": {**request, "chainId": 1}}), "evm-request")
    with pytest.raises(ValueError, match="fields"):
        verify(resign({**original, "payload": {**request, "unexpected": 1}}), "evm-request")


def test_signed_payload_shape_still_requires_object():
    signed = package("btc-signed", {"network": "bitcoin-testnet"})
    assert verify(signed, "btc-signed") == {"network": "bitcoin-testnet"}
    with pytest.raises(ValueError, match="fields"):
        verify(resign({**signed, "payload": "not-an-object"}), "btc-signed")
