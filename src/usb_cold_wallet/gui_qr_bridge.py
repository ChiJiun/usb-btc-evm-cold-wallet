"""Strict adapter between #27 QR v1 requests and #11 offline GUI ReviewPlan.

The QR request is untrusted transport data. It never authorizes a signature;
the wallet-bound plan, independent policy and attended GUI checks still apply.
"""
from __future__ import annotations

import json

from .exchange import MAX_BYTES, _unique_object, package, verify
from .keys import evm_account
from .qr_session import REQUEST_KEYS, _check as check_qr_request
from .qr_session import make_response as make_qr_response
from .review import ReviewPlan

MAX_QR_TEXT_BYTES = MAX_BYTES + 8192


def parse_qr_input(text: str, expected_kind: str) -> tuple[dict, dict | None]:
    """Return a strict #11 envelope and the original #27 request if present.

    Parsing and all structure/size checks happen while the GUI is LOCKED.
    """
    if expected_kind not in ("evm-request", "btc-request"):
        raise ValueError("QR signing requires an explicit selected transaction kind")
    if type(text) is not str or len(text.encode("utf-8")) > MAX_QR_TEXT_BYTES:
        raise ValueError("QR text is not valid bounded UTF-8")
    try:
        obj = json.loads(
            text, object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError("Non-finite QR JSON constant: " + value)),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid QR JSON") from exc
    if type(obj) is not dict:
        raise ValueError("QR payload must be an object")
    if set(obj) != REQUEST_KEYS:
        verify(obj, expected_kind)
        return obj, None

    check_qr_request(obj, REQUEST_KEYS, "unsigned")
    expected_network = "sepolia" if expected_kind == "evm-request" else "bitcoin-testnet"
    if obj["network"] != expected_network:
        raise ValueError("QR transaction network does not match selected chain")
    data = obj["payload"]
    if type(data) is not dict:
        raise ValueError("QR request payload must be an object")
    if expected_kind == "evm-request":
        if set(data) != {"kind", "transaction", "recipient", "amount_wei"} or data["kind"] != "evm":
            raise ValueError("Unknown EVM QR request payload fields")
        payload = data["transaction"]
    else:
        if set(data) != {"kind", "psbt", "recipient", "amount_sats", "max_fee_sats", "change_index"} or data["kind"] != "btc":
            raise ValueError("Unknown BTC QR request payload fields")
        payload = data["psbt"]
    envelope = package(expected_kind, payload)
    verify(envelope, expected_kind)
    return envelope, obj


def bind_qr_to_review(qr_request: dict, plan: ReviewPlan, root) -> None:
    """Bind all QR intent metadata to the actual unlocked wallet and review."""
    kind = plan.envelope_kind
    if kind == "evm-request":
        if (qr_request["network"] != "sepolia" or
                qr_request["account"].lower() != evm_account(root).address.lower()):
            raise ValueError("QR account does not match unlocked EVM wallet")
        payload = qr_request["payload"]
        if (type(payload["recipient"]) is not str or
                payload["recipient"].lower() != plan.recipient.lower() or
                type(payload["amount_wei"]) is not int or
                payload["amount_wei"] != plan.amount_atomic):
            raise ValueError("EVM QR amount or recipient differs from trusted review")
    elif kind == "btc-request":
        if (qr_request["network"] != "bitcoin-testnet" or
                qr_request["account"] != root.my_fingerprint.hex()):
            raise ValueError("QR fingerprint does not match unlocked BTC wallet")
        payload = qr_request["payload"]
        fee_cap = payload["max_fee_sats"]
        change_index = payload["change_index"]
        if (change_index is not None and
                (type(change_index) is not int or not 0 <= change_index < 2**31)):
            raise ValueError("BTC QR change index must be a valid non-hardened integer or null")
        if (type(payload["recipient"]) is not str or payload["recipient"] != plan.recipient
                or type(payload["amount_sats"]) is not int or
                payload["amount_sats"] != plan.amount_atomic
                or type(fee_cap) is not int or fee_cap < plan.fee_atomic
                or fee_cap < 0
                or change_index != plan.change_index):
            raise ValueError("BTC QR intent, fee cap or change index differs from trusted review")
    else:
        raise ValueError("Unsupported QR review transaction kind")


def signed_qr_text(qr_request: dict, signed_envelope: dict, signed_kind: str) -> str:
    """Preserve the original QR request ID/digest when presenting a signed QR."""
    signed_payload = verify(signed_envelope, signed_kind)
    result = make_qr_response(qr_request, signed_payload)
    return json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
