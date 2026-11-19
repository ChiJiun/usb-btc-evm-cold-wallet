"""Strict Sepolia native transfer signing: no blind smart-contract signing."""
import rlp
from eth_account import Account
from eth_utils import keccak, to_checksum_address

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
    tx["accessList"] = []
    max_fee = tx["gas"] * tx["maxFeePerGas"]
    return {
        "transaction": tx,
        "recipient": to,
        "value_wei": tx["value"],
        "max_fee_wei": max_fee,
        "max_total_wei": max_fee + tx["value"],
        "chain_id": ALLOWED_CHAIN_ID,
    }


def _decode_uint(value: bytes, field: str) -> int:
    if not isinstance(value, bytes):
        raise ValueError(f"{field} must be an RLP byte string")
    if value.startswith(b"\x00"):
        raise ValueError(f"{field} is not canonically encoded")
    return int.from_bytes(value, "big")


def _decode_access_list(value: list) -> list[dict]:
    if not isinstance(value, list):
        raise ValueError("accessList must be an RLP list")
    decoded = []
    for entry in value:
        if not isinstance(entry, list) or len(entry) != 2:
            raise ValueError("Malformed EIP-2930 access list entry")
        address, storage_keys = entry
        if not isinstance(address, bytes) or len(address) != 20 or not isinstance(storage_keys, list):
            raise ValueError("Malformed EIP-2930 access list entry")
        keys = []
        for storage_key in storage_keys:
            if not isinstance(storage_key, bytes) or len(storage_key) != 32:
                raise ValueError("Malformed EIP-2930 storage key")
            keys.append("0x" + storage_key.hex())
        decoded.append({"address": to_checksum_address("0x" + address.hex()), "storage_keys": keys})
    return decoded


def _raw_transaction_bytes(raw_transaction: str | bytes | bytearray) -> bytes:
    if isinstance(raw_transaction, str):
        if not raw_transaction.startswith("0x"):
            raise ValueError("Signed transaction must be 0x-prefixed hex")
        try:
            raw = bytes.fromhex(raw_transaction[2:])
        except ValueError as exc:
            raise ValueError("Signed transaction is not valid hex") from exc
    elif isinstance(raw_transaction, (bytes, bytearray)):
        raw = bytes(raw_transaction)
    else:
        raise ValueError("Signed transaction must be bytes or 0x-prefixed hex")
    if not raw or raw[0] != 2:
        raise ValueError("Only signed EIP-1559 (type 2) transactions are supported")
    return raw


def decode_signed_eip1559(raw_transaction: str | bytes | bytearray) -> dict:
    """Decode a signed type-2 transaction without trusting the original JSON request."""
    raw = _raw_transaction_bytes(raw_transaction)
    try:
        fields = rlp.decode(raw[1:], strict=True)
    except (rlp.exceptions.DecodingError, rlp.exceptions.DeserializationError) as exc:
        raise ValueError("Malformed EIP-1559 RLP payload") from exc
    if not isinstance(fields, list) or len(fields) != 12:
        raise ValueError("Signed EIP-1559 transaction must contain exactly 12 fields")

    chain_id = _decode_uint(fields[0], "chainId")
    nonce = _decode_uint(fields[1], "nonce")
    max_priority_fee = _decode_uint(fields[2], "maxPriorityFeePerGas")
    max_fee = _decode_uint(fields[3], "maxFeePerGas")
    gas = _decode_uint(fields[4], "gas")
    destination = fields[5]
    value = _decode_uint(fields[6], "value")
    data = fields[7]
    access_list = _decode_access_list(fields[8])
    y_parity = _decode_uint(fields[9], "signatureYParity")
    signature_r = _decode_uint(fields[10], "signatureR")
    signature_s = _decode_uint(fields[11], "signatureS")

    if not isinstance(destination, bytes) or len(destination) != 20:
        raise ValueError("Only transactions with a 20-byte recipient are supported")
    if not isinstance(data, bytes):
        raise ValueError("Transaction data must be an RLP byte string")
    if y_parity not in (0, 1) or signature_r == 0 or signature_s == 0:
        raise ValueError("Invalid or missing EIP-1559 signature")

    return {
        "type": 2,
        "chain_id": chain_id,
        "nonce": nonce,
        "max_priority_fee_per_gas": max_priority_fee,
        "max_fee_per_gas": max_fee,
        "gas": gas,
        "to": to_checksum_address("0x" + destination.hex()),
        "value_wei": value,
        "data": "0x" + data.hex(),
        "access_list": access_list,
        "signature": {
            "y_parity": y_parity,
            "r": hex(signature_r),
            "s": hex(signature_s),
        },
        "transaction_hash": "0x" + keccak(raw).hex(),
    }


def review_signed_evm_transaction(
    raw_transaction: str | bytes | bytearray,
    expected_recipient: str,
    expected_wei: int,
) -> dict:
    """Decode a signed transaction, re-run wallet policy, and recover its sender."""
    raw = _raw_transaction_bytes(raw_transaction)
    decoded = decode_signed_eip1559(raw)
    reviewed = review_evm_transaction(
        {
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
        },
        expected_recipient,
        expected_wei,
    )
    try:
        sender = to_checksum_address(Account.recover_transaction(raw))
    except (ValueError, TypeError) as exc:
        raise ValueError("EIP-1559 signature recovery failed") from exc
    return {
        "from": sender,
        "transaction_hash": decoded["transaction_hash"],
        "decoded_transaction": decoded,
        "max_fee_wei": reviewed["max_fee_wei"],
        "max_total_wei": reviewed["max_total_wei"],
    }


def sign_evm(root, payload: dict, expected_recipient: str, expected_wei: int) -> dict:
    reviewed = review_evm_transaction(payload, expected_recipient, expected_wei)
    account = evm_account(root)
    signed = Account.sign_transaction(reviewed["transaction"], account.key)
    raw_transaction = "0x" + signed.raw_transaction.hex()
    signed_review = review_signed_evm_transaction(raw_transaction, expected_recipient, expected_wei)

    decoded = signed_review["decoded_transaction"]
    expected = reviewed["transaction"]
    decoded_unsigned = {
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
    if decoded_unsigned != expected or signed_review["from"] != account.address:
        raise ValueError("Signed transaction does not match the reviewed EVM transaction")

    return {
        "chain_id": ALLOWED_CHAIN_ID,
        "from": account.address,
        "to": reviewed["recipient"],
        "value_wei": reviewed["value_wei"],
        "max_fee_wei": reviewed["max_fee_wei"],
        "max_total_wei": reviewed["max_total_wei"],
        "transaction_hash": signed_review["transaction_hash"],
        "signed_raw_transaction": raw_transaction,
        "decoded_transaction": decoded,
    }
