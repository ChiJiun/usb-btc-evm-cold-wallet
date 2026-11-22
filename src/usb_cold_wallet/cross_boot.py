"""Versioned single-USB cross-boot transaction protocol.

The FAT32 exchange area and the online host are untrusted transports.  V2 binds
an immutable request identity and transaction facts across reboot, but does not
authenticate the online host.  Signing policy and human review remain in the
existing BTC/EVM paths.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from pathlib import Path
from typing import Any

from eth_utils import to_checksum_address

from . import exchange
from .btc import _read_psbt
from .evm import decode_signed_eip1559, review_evm_transaction, review_signed_evm_transaction
from .cross_boot_public import (
    VERSION, REQUEST_KINDS, REQUEST_TO_RESPONSE, HEX64_RE,
    REQUEST_FIELDS as _REQUEST_FIELDS, RESPONSE_FIELDS as _RESPONSE_FIELDS,
    canonical as _canonical, sha_value as _sha, envelope_sha as _envelope_sha,
    new_request_id, package_v2_request, verify_v2_request,
)

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
        # exchange._validate_payload already verifies ECDSA, P2WPKH ownership,
        # fee and finalized witness. Strip only the allowed new signatures:
        # no other PSBT origin, UTXO, script or unknown metadata may change.
        after.partial_sigs = {}
    if final.serialize() != initial.serialize():
        raise ValueError("Signed Bitcoin PSBT changed unsigned metadata")


def package_v2_response(
    request: dict,
    signed_payload: dict,
    *,
    expected_account: str | None = None,
    trusted_time: int | None = None,
    allow_no_trusted_clock: bool = False,
) -> dict:
    checked = verify_v2_request(
        request,
        expected_account=expected_account,
        trusted_time=trusted_time,
        allow_no_trusted_clock=allow_no_trusted_clock,
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
    expected_account: str | None = None,
    trusted_time: int | None = None,
    allow_no_trusted_clock: bool = False,
) -> dict:
    checked_request = verify_v2_request(
        request,
        expected_account=expected_account,
        trusted_time=trusted_time,
        allow_no_trusted_clock=allow_no_trusted_clock,
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
    for field in ("requestEnvelopeDigest", "signedResultDigest", "sha256"):
        if type(response[field]) is not str or HEX64_RE.fullmatch(response[field]) is None:
            raise ValueError(f"Invalid signed response {field}")
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


def _decode_v2_file(path: Path) -> dict:
    """Bounded/no-follow/duplicate-key-safe JSON load for untrusted exchange media."""
    raw = exchange.read_bounded(Path(path))
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=exchange._unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("Non-finite JSON number in v2 exchange")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid v2 exchange JSON") from exc


def read_v2_request(
    path: Path,
    expected_kind: str | None = None,
    *,
    expected_account: str | None = None,
    trusted_time: int | None = None,
    allow_no_trusted_clock: bool = False,
) -> dict:
    data = _decode_v2_file(path)
    return verify_v2_request(
        data,
        expected_kind,
        expected_account=expected_account,
        trusted_time=trusted_time,
        allow_no_trusted_clock=allow_no_trusted_clock,
    )


def read_v2_response(
    path: Path,
    request: dict,
    *,
    expected_account: str | None = None,
    trusted_time: int | None = None,
    allow_no_trusted_clock: bool = False,
) -> dict:
    data = _decode_v2_file(path)
    verify_v2_response(
        request,
        data,
        expected_account=expected_account,
        trusted_time=trusted_time,
        allow_no_trusted_clock=allow_no_trusted_clock,
    )
    return data


def write_v2(path: Path, envelope: dict) -> None:
    """Create-only atomic publication using the existing exchange/vault primitive."""
    if type(envelope) is not dict or envelope.get("version") != VERSION:
        raise ValueError("Only v2 envelopes may be written by write_v2")
    fields = set(envelope)
    if fields not in (_REQUEST_FIELDS, _RESPONSE_FIELDS):
        raise ValueError("Invalid v2 envelope fields")
    if type(envelope.get("sha256")) is not str or not hmac.compare_digest(
        envelope["sha256"], _envelope_sha(envelope)
    ):
        raise ValueError("Invalid v2 envelope integrity digest")
    raw = _canonical(envelope)
    if len(raw) > exchange.MAX_BYTES:
        raise ValueError("Exchange exceeds maximum size")
    from .vault import save_vault
    save_vault(Path(path), envelope)
