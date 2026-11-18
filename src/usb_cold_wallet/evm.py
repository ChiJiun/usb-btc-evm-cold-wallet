"""Strict Sepolia native transfer signing: no blind smart-contract signing."""
import json
from eth_account import Account
from eth_utils import is_checksum_address, to_checksum_address
from .keys import evm_account

ALLOWED_CHAIN_ID = 11155111
REQUIRED_FIELDS = {"type", "chainId", "nonce", "to", "value", "gas", "maxFeePerGas", "maxPriorityFeePerGas"}
ALLOWED_FIELDS = REQUIRED_FIELDS | {"data", "accessList"}


def review_evm_transaction(payload: dict, expected_recipient: str, expected_wei: int) -> dict:
    if not isinstance(payload, dict) or set(payload) - ALLOWED_FIELDS or REQUIRED_FIELDS - set(payload):
        raise ValueError("Unsupported EVM transaction fields")
    tx = dict(payload)
    if type(tx["type"]) is not int or tx["type"] != 2:
        raise ValueError("Only EIP-1559 (type 2) supported")
    if type(tx["chainId"]) is not int or tx["chainId"] != ALLOWED_CHAIN_ID:
        raise ValueError("Only Sepolia chainId 11155111 supported")
    for field in ("nonce", "value", "gas", "maxFeePerGas", "maxPriorityFeePerGas"):
        if type(tx[field]) is not int or tx[field] < 0:
            raise ValueError(f"{field} must be a non-negative integer")
    if not 21000 <= tx["gas"] <= 21000:
        raise ValueError("Prototype only allows simple 21,000-gas ETH transfers")
    if tx["maxFeePerGas"] < tx["maxPriorityFeePerGas"]:
        raise ValueError("maxFeePerGas is below maxPriorityFeePerGas")
    if not isinstance(tx["to"], str) or not isinstance(expected_recipient, str):
        raise ValueError("Invalid recipient")
    try:
        to = to_checksum_address(tx["to"])
        expected = to_checksum_address(expected_recipient)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid Ethereum address") from exc
    if to != expected or type(expected_wei) is not int or tx["value"] != expected_wei:
        raise ValueError("Recipient or value does not match the independently supplied policy")
    if tx.get("data", "0x") not in ("0x", ""):
        raise ValueError("Contract calls, token approvals and arbitrary data are disabled")
    if tx.get("accessList", []) != []:
        raise ValueError("Access list signing is disabled")
    tx["to"] = to
    tx["data"] = "0x"
    tx.pop("accessList", None)
    max_fee = tx["gas"] * tx["maxFeePerGas"]
    return {
        "transaction": tx,
        "recipient": to,
        "value_wei": tx["value"],
        "max_fee_wei": max_fee,
        "max_total_wei": max_fee + tx["value"],
        "chain_id": ALLOWED_CHAIN_ID,
    }


def sign_evm(root, payload: dict, expected_recipient: str, expected_wei: int) -> dict:
    reviewed = review_evm_transaction(payload, expected_recipient, expected_wei)
    account = evm_account(root)
    signed = Account.sign_transaction(reviewed["transaction"], account.key)
    return {
        "chain_id": ALLOWED_CHAIN_ID,
        "from": account.address,
        "to": reviewed["recipient"],
        "value_wei": reviewed["value_wei"],
        "transaction_hash": signed.hash.hex(),
        "signed_raw_transaction": "0x" + signed.raw_transaction.hex(),
    }
