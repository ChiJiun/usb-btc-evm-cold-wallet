"""Independent eth-abi/ERC-20 vectors and adversarial Sepolia-only review tests."""
from __future__ import annotations

import pytest
from eth_abi import encode
from eth_account import Account
from eth_utils import to_checksum_address

from usb_cold_wallet.evm import review_evm_transaction, sign_evm
from review_only.evm_erc20 import (
    MAX_ERC20_GAS, UINT256_MAX, parse_erc20_calldata, review_erc20_transaction,
    review_signed_erc20_transaction,
)
from usb_cold_wallet.keys import root_from_mnemonic

CONTRACT = "0x1111111111111111111111111111111111111111"
RECIPIENT = "0x2222222222222222222222222222222222222222"
SPENDER = "0x3333333333333333333333333333333333333333"
OTHER = "0x4444444444444444444444444444444444444444"
FEE_LIMIT = 300_000 * 2_000_000_000


def independent_calldata(method="transfer", party=RECIPIENT, amount=123) -> str:
    # Independent eth-abi library, not the module under test.
    selector = "a9059cbb" if method == "transfer" else "095ea7b3"
    return "0x" + selector + encode(["address", "uint256"], [party, amount]).hex()


def tx(method="transfer", party=RECIPIENT, amount=123):
    return {
        "type": 2, "chainId": 11155111, "nonce": 7, "to": CONTRACT,
        "value": 0, "gas": 80_000, "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000,
        "data": independent_calldata(method, party, amount),
    }


def review(payload, method="transfer", party=RECIPIENT, amount=123, **kwargs):
    return review_erc20_transaction(
        payload, expected_contract=CONTRACT, expected_counterparty=party,
        expected_amount=amount, expected_method=method, expected_nonce=7,
        trusted_contracts={CONTRACT},
        max_fee_wei=FEE_LIMIT, **kwargs,
    )


@pytest.mark.parametrize("method,party,amount", [
    ("transfer", RECIPIENT, 123),
    ("approve", SPENDER, 55),
    ("transfer", RECIPIENT, 1),
    ("transfer", RECIPIENT, UINT256_MAX),
    ("approve", SPENDER, 0),  # explicit allowance revocation is permitted
])
def test_eth_abi_reference_vectors_and_exact_review(method, party, amount):
    raw = independent_calldata(method, party, amount)
    parsed = parse_erc20_calldata(raw)
    assert parsed["method"] == method
    assert parsed["recipient" if method == "transfer" else "spender"] == to_checksum_address(party)
    assert parsed["amount" if method == "transfer" else "allowance"] == amount
    reviewed = review(tx(method, party, amount), method, party, amount)
    assert reviewed["contract"] == to_checksum_address(CONTRACT)
    assert reviewed["max_fee_wei"] == 160_000_000_000_000
    assert reviewed["signature_allowed"] is False


def test_existing_native_only_signer_still_rejects_token_calls():
    payload = tx()
    with pytest.raises(ValueError):
        review_evm_transaction(payload, CONTRACT, 0)
    root = root_from_mnemonic("abandon " * 11 + "about")  # compromised test mnemonic
    with pytest.raises(ValueError):
        sign_evm(root, payload, CONTRACT, 0)


@pytest.mark.parametrize("mutated", [
    "0x" + "deadbeef" + independent_calldata()[10:],
    independent_calldata()[:-2],
    independent_calldata() + "00",
    independent_calldata()[2:],
    "0x" + "a9059cbb" + "01" + "00" * 11 + independent_calldata()[34:],
    "0x" + "a9059cbb" + "00" * 12 + "00" * 20 + "00" * 31 + "01",
    independent_calldata().upper(),
    "0x" + "a9059cbb" + "00" * 64,
    "0x" + "a9059cbb" + "00" * 12 + "22" * 20 + "00" * 31 + "00",
])
def test_malformed_or_untrusted_calldata_denied(mutated):
    with pytest.raises(ValueError):
        parse_erc20_calldata(mutated)


def test_canonical_erc20_approve_unlimited_denied_but_zero_revocation_allowed():
    assert parse_erc20_calldata(independent_calldata("approve", SPENDER, 0))["allowance"] == 0
    with pytest.raises(ValueError):
        parse_erc20_calldata(independent_calldata("approve", SPENDER, UINT256_MAX))
    with pytest.raises(ValueError):
        parse_erc20_calldata(independent_calldata("transfer", RECIPIENT, 0))


@pytest.mark.parametrize("field,value", [
    ("chainId", 1), ("chainId", 137), ("chainId", True),
    ("to", OTHER), ("value", 1), ("value", True),
    ("nonce", True), ("nonce", -1), ("nonce", UINT256_MAX + 1),
    ("gas", 20_999), ("gas", MAX_ERC20_GAS + 1), ("gas", True),
    ("maxFeePerGas", 0), ("maxFeePerGas", UINT256_MAX + 1),
    ("maxPriorityFeePerGas", 3_000_000_000),
    ("type", 0), ("type", True), ("accessList", [{"address": CONTRACT}]),
])
def test_cross_chain_fee_limit_and_invalid_transaction_fields(field, value):
    payload = tx()
    payload[field] = value
    with pytest.raises(ValueError):
        review(payload)


def test_spender_replacement_and_exact_allowance_binding():
    original = tx("approve", SPENDER, 500)
    with pytest.raises(ValueError, match="counterparty"):
        review(original, "approve", OTHER, 500)
    with pytest.raises(ValueError, match="amount"):
        review(original, "approve", SPENDER, 499)
    original["data"] = independent_calldata("approve", OTHER, 500)
    with pytest.raises(ValueError):
        review(original, "approve", SPENDER, 500)


def test_contract_allowlist_and_trusted_limit_are_required():
    p = tx()
    for allow in ([], [OTHER], [CONTRACT, CONTRACT], "online", None):
        with pytest.raises(ValueError):
            review_erc20_transaction(
                p, expected_contract=CONTRACT, expected_counterparty=RECIPIENT,
                expected_amount=123, expected_method="transfer", expected_nonce=7,
                trusted_contracts=allow, max_fee_wei=FEE_LIMIT
            )
    with pytest.raises(ValueError):
        review_erc20_transaction(
            p, expected_contract=CONTRACT, expected_counterparty=RECIPIENT,
            expected_amount=123, expected_method="transfer", expected_nonce=7,
            trusted_contracts={CONTRACT}, max_fee_wei=1,
        )
    with pytest.raises(ValueError):
        review_erc20_transaction(
            p, expected_contract=CONTRACT, expected_counterparty=RECIPIENT,
            expected_amount=123, expected_method="transfer", expected_nonce=7,
            trusted_contracts={CONTRACT}, max_fee_wei=FEE_LIMIT,
            max_gas=30_000,
        )


def test_unknown_metadata_and_uint256_overflow_denied():
    p = tx()
    p["tokenSymbol"] = "SCAM"
    with pytest.raises(ValueError):
        review(p)
    for val in (UINT256_MAX,):
        with pytest.raises(ValueError):
            parse_erc20_calldata(independent_calldata("approve", SPENDER, val))
    p = tx()
    p["data"] = independent_calldata("transfer", RECIPIENT, UINT256_MAX)
    with pytest.raises(ValueError):
        review(p)  # Trusted expected amount remains 123.


@pytest.mark.parametrize("method,party,amount", [
    ("transfer", RECIPIENT, 123), ("approve", SPENDER, 20),
])
def test_independent_eth_account_signed_bytes_recovered_and_reviewed(method, party, amount):
    # Independently serialized/signed EIP-1559 by eth-account, not the wallet signer.
    signer = Account.from_key("0x" + "12" * 32)  # Public compromised test key.
    unsigned = tx(method, party, amount)
    signed = Account.sign_transaction(unsigned, signer.key)
    recovered = review_signed_erc20_transaction(
        signed.raw_transaction, expected_sender=signer.address,
        expected_contract=CONTRACT, expected_counterparty=party,
        expected_amount=amount, expected_method=method, expected_nonce=7,
        trusted_contracts=[CONTRACT], max_fee_wei=FEE_LIMIT,
    )
    assert recovered["signed_bytes_verified"] is True
    assert recovered["sender"] == signer.address
    assert recovered["method"] == method
    assert recovered["transaction_hash"] == "0x" + signed.hash.hex()
    assert recovered["signature_allowed"] is False

    with pytest.raises(ValueError, match="sender"):
        review_signed_erc20_transaction(
            signed.raw_transaction, expected_sender=OTHER,
            expected_contract=CONTRACT, expected_counterparty=party,
            expected_amount=amount, expected_method=method, expected_nonce=7,
            trusted_contracts=[CONTRACT], max_fee_wei=FEE_LIMIT,
        )
    with pytest.raises(ValueError):
        review_signed_erc20_transaction(
            signed.raw_transaction, expected_sender=signer.address,
            expected_contract=CONTRACT, expected_counterparty=OTHER,
            expected_amount=amount, trusted_contracts=[CONTRACT], max_fee_wei=FEE_LIMIT,
        )


def test_signed_raw_transaction_truncation_bad_type_and_size_denied():
    signer = Account.from_key("0x" + "12" * 32)
    signed = Account.sign_transaction(tx(), signer.key).raw_transaction
    expected = dict(
        expected_sender=signer.address, expected_contract=CONTRACT,
        expected_counterparty=RECIPIENT, expected_amount=123,
        expected_method="transfer", expected_nonce=7,
        trusted_contracts={CONTRACT}, max_fee_wei=FEE_LIMIT,
    )
    for malformed in (signed[:-1], b"\x01" + signed[1:], signed + b"\x00",
                      b"\x02" + b"\xff" * 2049, "0x02" + "00" * 2050):
        with pytest.raises(ValueError):
            review_signed_erc20_transaction(malformed, **expected)


@pytest.mark.parametrize("method,substituted", [
    ("transfer", "approve"), ("approve", "transfer"),
])
def test_cannot_substitute_method_with_same_party_and_quantity(method, substituted):
    party = RECIPIENT
    untrusted = tx(substituted, party, 123)
    with pytest.raises(ValueError, match="method"):
        review(untrusted, method, party, 123)
    # Post-signature verification must have the identical independent method binding.
    signer = Account.from_key("0x" + "12" * 32)
    signed = Account.sign_transaction(untrusted, signer.key)
    with pytest.raises(ValueError, match="method"):
        review_signed_erc20_transaction(
            signed.raw_transaction, expected_sender=signer.address,
            expected_contract=CONTRACT, expected_counterparty=party,
            expected_amount=123, expected_method=method, expected_nonce=7,
            trusted_contracts={CONTRACT}, max_fee_wei=FEE_LIMIT,
        )


@pytest.mark.parametrize("wrong_nonce", [0, 6, 8, True, -1, UINT256_MAX + 1])
def test_trusted_expected_nonce_required_for_unsigned_and_signed(wrong_nonce):
    with pytest.raises(ValueError, match="nonce"):
        review(tx(), expected_nonce=wrong_nonce)
    signer = Account.from_key("0x" + "12" * 32)
    signed = Account.sign_transaction(tx(), signer.key)
    with pytest.raises(ValueError, match="nonce"):
        review_signed_erc20_transaction(
            signed.raw_transaction, expected_sender=signer.address,
            expected_contract=CONTRACT, expected_counterparty=RECIPIENT,
            expected_amount=123, expected_method="transfer",
            expected_nonce=wrong_nonce, trusted_contracts={CONTRACT},
            max_fee_wei=FEE_LIMIT,
        )


@pytest.mark.parametrize("bad_method", ["", "permit", "Transfer", None, True])
def test_invalid_trusted_erc20_method_fails_closed(bad_method):
    with pytest.raises(ValueError, match="method"):
        review(tx(), expected_method=bad_method)
