"""EIP-712 independent eth-account reference hashing and adversarial schema tests."""
from __future__ import annotations

from copy import deepcopy

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak, to_checksum_address

from review_only.evm_eip712 import (
    DOMAIN_FIELDS, DOMAIN_NAME, DOMAIN_VERSION, MAX_VALIDITY_SECONDS,
    review_eip712_intent,
)
from review_only.evm_erc20 import UINT256_MAX

CONTRACT = "0x1111111111111111111111111111111111111111"
OWNER = "0x2222222222222222222222222222222222222222"
PARTY = "0x3333333333333333333333333333333333333333"
OTHER = "0x4444444444444444444444444444444444444444"
NOW = 1_800_000_000
DEADLINE = NOW + 3600
# Frozen eth-account 0.14.0 reference hashes, independently encoded.
REFERENCE_HASHES = {
    "WalletTransferIntent": "0xef5bad643007b005d5c1d55c73a6dcd9fd4a11acaf081cd87963a48c6eb40b0b",
    "WalletApprovalIntent": "0x0b56e332c98a1abb376a659d24b91f73e0a25bd38c4cc2b7213847322755c6fc",
}
FIELDS = {
    "WalletTransferIntent": [
        {"name": name, "type": typ} for name, typ in (
            ("owner", "address"), ("token", "address"), ("recipient", "address"),
            ("amount", "uint256"), ("nonce", "uint256"), ("deadline", "uint256"),
        )
    ],
    "WalletApprovalIntent": [
        {"name": name, "type": typ} for name, typ in (
            ("owner", "address"), ("token", "address"), ("spender", "address"),
            ("allowance", "uint256"), ("nonce", "uint256"), ("deadline", "uint256"),
        )
    ],
}


def typed(primary="WalletTransferIntent", value=123, nonce=9):
    field = "recipient" if primary == "WalletTransferIntent" else "spender"
    amount = "amount" if field == "recipient" else "allowance"
    return {
        "types": {"EIP712Domain": deepcopy(DOMAIN_FIELDS), primary: deepcopy(FIELDS[primary])},
        "primaryType": primary,
        "domain": {
            "name": DOMAIN_NAME, "version": DOMAIN_VERSION,
            "chainId": 11155111, "verifyingContract": CONTRACT,
        },
        "message": {
            "owner": OWNER, "token": CONTRACT, field: PARTY,
            amount: value, "nonce": nonce, "deadline": DEADLINE,
        },
    }


def review(data, **overrides):
    options = {
        "expected_contract": CONTRACT, "expected_owner": OWNER,
        "expected_counterparty": PARTY, "expected_amount": 123,
        "expected_nonce": 9, "expected_deadline": DEADLINE,
        "trusted_contracts": [CONTRACT], "now_timestamp": NOW,
    }
    options.update(overrides)
    return review_eip712_intent(data, **options)


@pytest.mark.parametrize("primary", ["WalletTransferIntent", "WalletApprovalIntent"])
def test_independent_eth_account_eip712_struct_hash_and_signature_intent(primary):
    data = typed(primary)
    inspected = review(data)
    external = encode_typed_data(full_message=data)  # Independently implemented eth-account encoder
    expected_digest = keccak(b"\x19" + external.version + external.header + external.body)
    assert inspected["domain_separator"] == "0x" + external.header.hex()
    assert inspected["message_hash"] == "0x" + external.body.hex()
    assert inspected["signing_digest"] == "0x" + expected_digest.hex()
    assert inspected["signing_digest"] == REFERENCE_HASHES[primary]
    assert inspected["signature_allowed"] is False
    # Independent public, permanently compromised development account.
    key = "0x" + "12" * 32
    signed = Account.sign_message(external, private_key=key)
    assert Account.recover_message(external, signature=signed.signature) == Account.from_key(key).address
    assert inspected["owner"] == to_checksum_address(OWNER)


@pytest.mark.parametrize("mutation", [
    lambda d: d.update({"primaryType": "Permit"}),
    lambda d: d["domain"].update({"chainId": 1}),
    lambda d: d["domain"].update({"chainId": True}),
    lambda d: d["domain"].update({"verifyingContract": OTHER}),
    lambda d: d["domain"].update({"name": "Untrusted dApp"}),
    lambda d: d["domain"].update({"version": "2"}),
    lambda d: d["domain"].update({"salt": "0x" + "00" * 32}),
    lambda d: d["types"].update({"Permit": FIELDS["WalletTransferIntent"]}),
    lambda d: d["types"]["WalletTransferIntent"].reverse(),
    lambda d: d["types"]["WalletTransferIntent"][3].update({"type": "uint8"}),
    lambda d: d["message"].update({"owner": OTHER}),
    lambda d: d["message"].update({"token": OTHER}),
    lambda d: d["message"].update({"recipient": OTHER}),
    lambda d: d["message"].update({"amount": 124}),
    lambda d: d["message"].update({"nonce": 10}),
    lambda d: d["message"].update({"deadline": DEADLINE + 1}),
    lambda d: d["message"].update({"amount": True}),
    lambda d: d["message"].update({"amount": -1}),
    lambda d: d["message"].update({"amount": UINT256_MAX + 1}),
    lambda d: d["message"].update({"bonus": "injected"}),
    lambda d: d["message"].update({"deadline": "1800003600"}),
    lambda d: d.update({"signature": "0xdeadbeef"}),
])
def test_eip712_unknown_schema_cross_chain_address_poisoning_and_replay_denied(mutation):
    data = typed()
    mutation(data)
    with pytest.raises(ValueError):
        review(data)


def test_replay_uses_independently_maintained_nonce_and_deadline():
    data = typed()
    review(data)  # First inspection, no signing
    with pytest.raises(ValueError, match="nonce"):
        review(data, expected_nonce=10)  # Trusted state advanced: stale message rejected.
    with pytest.raises(ValueError, match="expired"):
        review(data, now_timestamp=DEADLINE)
    with pytest.raises(ValueError, match="validity"):
        review(data, now_timestamp=NOW - MAX_VALIDITY_SECONDS)
    with pytest.raises(ValueError, match="nonce"):
        review(data, expected_nonce=True)


def test_explicit_approval_cap_and_schema_allowlist():
    data = typed("WalletApprovalIntent")
    assert review(typed("WalletApprovalIntent", 0), expected_amount=0)["allowance"] == 0
    with pytest.raises(ValueError, match="Infinite"):
        review(typed("WalletApprovalIntent", UINT256_MAX), expected_amount=UINT256_MAX)
    with pytest.raises(ValueError, match="counterparty"):
        review(data, expected_counterparty=OTHER)
    with pytest.raises(ValueError, match="allowlisted"):
        review(data, trusted_contracts=[OTHER])
    with pytest.raises(ValueError):
        review(data, expected_contract=OTHER)
    with pytest.raises(ValueError):
        review(data, max_validity_seconds=MAX_VALIDITY_SECONDS + 1)


def test_reject_genuine_permit2612_schema_and_permit2():
    base = typed()
    for name in ("Permit", "PermitSingle", "PermitBatch", "Permit2"):
        data = deepcopy(base)
        data["primaryType"] = name
        data["types"][name] = data["types"].pop("WalletTransferIntent")
        with pytest.raises(ValueError, match="schema"):
            review(data)
