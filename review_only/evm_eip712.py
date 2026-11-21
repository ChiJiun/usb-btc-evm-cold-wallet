"""Restricted EIP-712 typed-data *review*, not a signer or generic EIP-712 router.

Only two exact, project-defined intent schemas are recognized. EIP-2612
Permit/Permit2, arbitrary dApp schemas and blind digest signing are rejected.
No current on-chain deployment of these custom intents is asserted.
"""
from __future__ import annotations

from collections.abc import Collection

from eth_utils import keccak

from .evm_erc20 import (
    SEPOLIA_CHAIN_ID, UINT256_MAX, checked_address, checked_contracts,
    checked_uint,
)

DOMAIN_NAME = "USB Cold Wallet Intent"
DOMAIN_VERSION = "1"
DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
_INTENT_FIELDS = {
    "WalletTransferIntent": [
        {"name": "owner", "type": "address"},
        {"name": "token", "type": "address"},
        {"name": "recipient", "type": "address"},
        {"name": "amount", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ],
    "WalletApprovalIntent": [
        {"name": "owner", "type": "address"},
        {"name": "token", "type": "address"},
        {"name": "spender", "type": "address"},
        {"name": "allowance", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ],
}
MAX_VALIDITY_SECONDS = 7 * 24 * 60 * 60


def _encode_field(value: object, kind: str) -> bytes:
    if kind == "address":
        normalized = checked_address(value, "typed address")
        return bytes.fromhex(normalized[2:]).rjust(32, b"\x00")
    if kind == "uint256":
        return checked_uint(value, "typed integer").to_bytes(32, "big")
    if kind == "string":
        if type(value) is not str or not 1 <= len(value) <= 64 or not value.isascii():
            raise ValueError("Unsupported EIP-712 string")
        return keccak(text=value)
    raise ValueError("Unsupported EIP-712 ABI field type")


def _hash_struct(name: str, fields: list[dict], values: dict) -> bytes:
    # EIP-712 encodeType for flat, exact, non-nested schema only.
    signature = name + "(" + ",".join(f["type"] + " " + f["name"] for f in fields) + ")"
    return keccak(keccak(text=signature) + b"".join(
        _encode_field(values[f["name"]], f["type"]) for f in fields
    ))


def review_eip712_intent(
    typed_data: object, *, expected_contract: str, expected_owner: str,
    expected_counterparty: str, expected_amount: int, expected_nonce: int,
    expected_deadline: int, trusted_contracts: Collection[str],
    now_timestamp: int, max_validity_seconds: int = MAX_VALIDITY_SECONDS,
) -> dict:
    """Review a strictly specified offline intent and return its EIP-712 digest.

    expected_* and now_timestamp must originate from trusted offline policy.
    The returned digest is NOT permission to sign it. A consumer must
    independently enforce nonce consumption before it enables any signature.
    """
    if type(typed_data) is not dict or set(typed_data) != {"types", "primaryType", "domain", "message"}:
        raise ValueError("Invalid EIP-712 envelope")
    primary = typed_data["primaryType"]
    if type(primary) is not str or primary not in _INTENT_FIELDS:
        raise ValueError("EIP-712 schema is not allowlisted (Permit/Permit2 forbidden)")
    fields = _INTENT_FIELDS[primary]
    types = typed_data["types"]
    if type(types) is not dict or set(types) != {"EIP712Domain", primary}:
        raise ValueError("Unknown or missing EIP-712 types")
    if types["EIP712Domain"] != DOMAIN_FIELDS or types[primary] != fields:
        raise ValueError("EIP-712 schema fields/order/types differ from approved version")
    domain, message = typed_data["domain"], typed_data["message"]
    if type(domain) is not dict or set(domain) != {"name", "version", "chainId", "verifyingContract"}:
        raise ValueError("Invalid EIP-712 domain fields")
    if type(message) is not dict or set(message) != {field["name"] for field in fields}:
        raise ValueError("Invalid EIP-712 message fields")
    if domain["name"] != DOMAIN_NAME or domain["version"] != DOMAIN_VERSION:
        raise ValueError("Untrusted EIP-712 domain name/version")
    if type(domain["chainId"]) is not int or domain["chainId"] != SEPOLIA_CHAIN_ID:
        raise ValueError("Only Sepolia EIP-712 chainId supported")

    contract = checked_address(domain["verifyingContract"], "verifyingContract")
    independently_approved = checked_address(expected_contract, "expected verifyingContract")
    if contract != independently_approved:
        raise ValueError("EIP-712 verifyingContract mismatch")
    checked_contracts(trusted_contracts, contract)
    owner = checked_address(message["owner"], "owner")
    approved_owner = checked_address(expected_owner, "expected owner")
    if owner != approved_owner:
        raise ValueError("EIP-712 signing account mismatch")
    token = checked_address(message["token"], "message token")
    if token != contract:
        raise ValueError("EIP-712 token must equal independently verified contract")
    party_field = "recipient" if primary == "WalletTransferIntent" else "spender"
    amount_field = "amount" if primary == "WalletTransferIntent" else "allowance"
    counterparty = checked_address(message[party_field], party_field)
    if counterparty != checked_address(expected_counterparty, "expected counterparty"):
        raise ValueError("EIP-712 counterparty mismatch")
    minimum_amount = 1 if amount_field == "amount" else 0  # approve(0) revokes.
    amount = checked_uint(message[amount_field], amount_field, minimum=minimum_amount)
    if amount != checked_uint(expected_amount, "expected amount", minimum=minimum_amount):
        raise ValueError("EIP-712 amount/allowance mismatch")
    if amount_field == "allowance" and amount == UINT256_MAX:
        raise ValueError("Infinite typed-data allowance forbidden")
    nonce = checked_uint(message["nonce"], "nonce")
    if nonce != checked_uint(expected_nonce, "trusted expected nonce"):
        raise ValueError("EIP-712 nonce mismatch / replay attempt")
    deadline = checked_uint(message["deadline"], "deadline")
    if deadline != checked_uint(expected_deadline, "trusted deadline"):
        raise ValueError("EIP-712 deadline mismatch")
    now = checked_uint(now_timestamp, "trusted offline timestamp")
    ttl = checked_uint(max_validity_seconds, "offline maximum validity", minimum=1)
    if ttl > MAX_VALIDITY_SECONDS or not now < deadline <= now + ttl:
        raise ValueError("EIP-712 message expired or validity window too long")

    domain_hash = _hash_struct("EIP712Domain", DOMAIN_FIELDS, domain)
    message_hash = _hash_struct(primary, fields, message)
    digest = keccak(b"\x19\x01" + domain_hash + message_hash)
    return {
        "network": "sepolia",
        "chain_id": SEPOLIA_CHAIN_ID,
        "primary_type": primary,
        "domain": {
            "name": DOMAIN_NAME,
            "version": DOMAIN_VERSION,
            "chainId": SEPOLIA_CHAIN_ID,
            "verifyingContract": contract,
        },
        "owner": owner,
        "token": token,
        "recipient": counterparty if party_field == "recipient" else None,
        "spender": counterparty if party_field == "spender" else None,
        "amount": amount if amount_field == "amount" else None,
        "allowance": amount if amount_field == "allowance" else None,
        "nonce": nonce,
        "deadline": deadline,
        "domain_separator": "0x" + domain_hash.hex(),
        "message_hash": "0x" + message_hash.hex(),
        "signing_digest": "0x" + digest.hex(),
        "signature_allowed": False,
    }
