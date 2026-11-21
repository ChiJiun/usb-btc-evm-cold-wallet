"""Fail-closed Sepolia ERC-20 transfer/approve *review*; no signing entry point.

The caller must supply independently verified contract/counterparty/amount and
maximum fee. No RPC, token metadata, decimals, or online summary is trusted.
The existing native-only evm.py signer intentionally remains unchanged.
"""
from __future__ import annotations

import re
from collections.abc import Collection

from eth_account import Account
from eth_utils import to_checksum_address

from usb_cold_wallet.evm import decode_signed_eip1559

SEPOLIA_CHAIN_ID = 11155111
UINT256_MAX = (1 << 256) - 1
MAX_ERC20_CALLDATA_BYTES = 68
MAX_ERC20_GAS = 300_000

_SELECTORS = {
    bytes.fromhex("a9059cbb"): ("transfer", "recipient", "amount"),
    bytes.fromhex("095ea7b3"): ("approve", "spender", "allowance"),
}
_REQUIRED_TX_FIELDS = frozenset({
    "type", "chainId", "nonce", "to", "value", "gas",
    "maxFeePerGas", "maxPriorityFeePerGas", "data",
})
_ALLOWED_TX_FIELDS = _REQUIRED_TX_FIELDS | {"accessList"}
_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})+\Z")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_ZERO = "0x" + "00" * 20


def checked_uint(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= UINT256_MAX:
        raise ValueError(f"Invalid {label}: expected bounded uint256")
    return value


def checked_address(value: object, label: str) -> str:
    if type(value) is not str or not _ADDRESS.fullmatch(value):
        raise ValueError(f"Invalid {label}: expected exactly 20-byte Ethereum address")
    canonical = to_checksum_address(value)
    if canonical.lower() == _ZERO:
        raise ValueError(f"Invalid {label}: zero address is forbidden")
    return canonical


def checked_contracts(contracts: Collection[str], contract: str) -> None:
    """Trusted allowlist is mandatory and cannot be a string / online metadata."""
    if isinstance(contracts, (str, bytes, dict)) or not isinstance(contracts, (set, frozenset, tuple, list)):
        raise ValueError("Trusted offline contract allowlist required")
    if not 1 <= len(contracts) <= 64:
        raise ValueError("Trusted offline contract allowlist must contain 1..64 addresses")
    authorized = {checked_address(addr, "allowlisted contract") for addr in contracts}
    if len(authorized) != len(contracts) or contract not in authorized:
        raise ValueError("Contract not independently allowlisted")


def parse_erc20_calldata(data: object) -> dict:
    """Decode precisely selector + two canonical 32-byte ABI words, with no tails."""
    if type(data) is not str or len(data) != 2 + MAX_ERC20_CALLDATA_BYTES * 2 or not _HEX.fullmatch(data):
        raise ValueError("ERC-20 calldata must be exactly 68 bytes of prefixed hex")
    raw = bytes.fromhex(data[2:])
    method = _SELECTORS.get(raw[:4])
    if method is None:
        raise ValueError("Unsupported ERC-20 selector; blind calldata forbidden")
    if raw[4:16] != b"\x00" * 12:
        raise ValueError("Non-canonical ABI address word (dirty high bytes)")
    label, counterparty_label, amount_label = method
    counterparty = checked_address("0x" + raw[16:36].hex(), counterparty_label)
    value = int.from_bytes(raw[36:68], "big")
    checked_uint(value, amount_label, minimum=1 if label == "transfer" else 0)
    if label == "approve" and value == UINT256_MAX:
        raise ValueError("Unlimited ERC-20 approval forbidden")
    return {
        "method": label,
        counterparty_label: counterparty,
        amount_label: value,
        "selector": "0x" + raw[:4].hex(),
        "calldata": "0x" + raw.hex(),
    }


def review_erc20_transaction(
    payload: object, *, expected_contract: str,
    expected_counterparty: str, expected_amount: int,
    trusted_contracts: Collection[str], max_fee_wei: int,
    max_gas: int = MAX_ERC20_GAS,
) -> dict:
    """Independently bind the unsigned transaction and raw calldata to review intent.

    Returned data is for display/policy review ONLY: cannot be given to
    sign_evm(), which rejects all contract calldata.
    """
    if type(payload) is not dict or set(payload) != _REQUIRED_TX_FIELDS and set(payload) != _ALLOWED_TX_FIELDS:
        raise ValueError("Unknown or missing EIP-1559 token transaction fields")
    if type(payload["type"]) is not int or payload["type"] != 2:
        raise ValueError("Only EIP-1559 type 2 supported")
    if type(payload["chainId"]) is not int or payload["chainId"] != SEPOLIA_CHAIN_ID:
        raise ValueError("Only Sepolia chainId 11155111 supported")
    if payload.get("accessList", []) != []:
        raise ValueError("Access lists are forbidden for token review")
    contract = checked_address(payload["to"], "token contract")
    trusted = checked_address(expected_contract, "expected token contract")
    if contract != trusted:
        raise ValueError("Transaction contract differs from independently verified contract")
    checked_contracts(trusted_contracts, contract)

    expected_party = checked_address(expected_counterparty, "expected recipient/spender")
    decoded = parse_erc20_calldata(payload["data"])
    expected_qty = checked_uint(expected_amount, "expected token amount",
                                minimum=1 if decoded["method"] == "transfer" else 0)
    nonce = checked_uint(payload["nonce"], "nonce")
    gas = checked_uint(payload["gas"], "gas", minimum=21_000)
    gas_ceiling = checked_uint(max_gas, "independently verified gas limit", minimum=21_000)
    if gas > min(gas_ceiling, MAX_ERC20_GAS):
        raise ValueError("ERC-20 gas limit exceeds offline policy")
    max_fee_per_gas = checked_uint(payload["maxFeePerGas"], "maxFeePerGas", minimum=1)
    priority = checked_uint(payload["maxPriorityFeePerGas"], "maxPriorityFeePerGas")
    if priority > max_fee_per_gas:
        raise ValueError("Priority fee exceeds max fee per gas")
    if checked_uint(payload["value"], "native ETH value") != 0:
        raise ValueError("Sending ETH alongside ERC-20 call is forbidden")
    fee_cap = checked_uint(max_fee_wei, "independently approved maximum fee")
    actual_fee_cap = gas * max_fee_per_gas
    if actual_fee_cap > fee_cap or actual_fee_cap > UINT256_MAX:
        raise ValueError("Transaction maximum fee exceeds trusted offline limit")

    party_field = "recipient" if decoded["method"] == "transfer" else "spender"
    qty_field = "amount" if decoded["method"] == "transfer" else "allowance"
    if decoded[party_field] != expected_party or decoded[qty_field] != expected_qty:
        raise ValueError("ERC-20 counterparty/amount differs from independently approved intent")
    return {
        "network": "sepolia",
        "chain_id": SEPOLIA_CHAIN_ID,
        "contract": contract,
        "method": decoded["method"],
        "recipient": decoded.get("recipient"),
        "spender": decoded.get("spender"),
        "amount": decoded.get("amount"),
        "allowance": decoded.get("allowance"),
        "nonce": nonce,
        "gas": gas,
        "max_fee_per_gas": max_fee_per_gas,
        "max_priority_fee_per_gas": priority,
        "max_fee_wei": actual_fee_cap,
        "max_total_wei": actual_fee_cap,  # Native ETH value must be zero.
        "data": decoded["calldata"],
        "signature_allowed": False,
    }

def review_signed_erc20_transaction(
    raw_transaction: str | bytes, *, expected_sender: str,
    expected_contract: str, expected_counterparty: str, expected_amount: int,
    trusted_contracts: Collection[str], max_fee_wei: int,
    max_gas: int = MAX_ERC20_GAS,
) -> dict:
    """Independently verify post-signature serialized bytes, sender and intent.

    This is a read-only verifier for independently obtained signed transfers.
    It does NOT sign or permit enabling any contract call on the cold signer.
    """
    if type(raw_transaction) is str:
        if len(raw_transaction) > 4098:
            raise ValueError("Oversized signed ERC-20 transaction")
    elif isinstance(raw_transaction, bytes):
        if len(raw_transaction) > 2048:
            raise ValueError("Oversized signed ERC-20 transaction")
        raw_transaction = bytes(raw_transaction)
    else:
        raise ValueError("Unsupported signed ERC-20 transaction representation")
    decoded = decode_signed_eip1559(raw_transaction)
    payload = {
        "type": decoded["type"], "chainId": decoded["chain_id"],
        "nonce": decoded["nonce"], "to": decoded["to"],
        "value": decoded["value_wei"], "gas": decoded["gas"],
        "maxFeePerGas": decoded["max_fee_per_gas"],
        "maxPriorityFeePerGas": decoded["max_priority_fee_per_gas"],
        "data": decoded["data"], "accessList": decoded["access_list"],
    }
    reviewed = review_erc20_transaction(
        payload, expected_contract=expected_contract,
        expected_counterparty=expected_counterparty, expected_amount=expected_amount,
        trusted_contracts=trusted_contracts, max_fee_wei=max_fee_wei,
        max_gas=max_gas,
    )
    approved_sender = checked_address(expected_sender, "independently approved sender")
    try:
        signer = checked_address(Account.recover_transaction(raw_transaction), "recovered signer")
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("Signed ERC-20 EIP-1559 sender recovery failed") from exc
    if signer != approved_sender:
        raise ValueError("Signed ERC-20 transaction sender mismatch")
    return {
        **reviewed,
        "sender": signer,
        "transaction_hash": decoded["transaction_hash"],
        "signed_bytes_verified": True,
        "signature_allowed": False,
    }
