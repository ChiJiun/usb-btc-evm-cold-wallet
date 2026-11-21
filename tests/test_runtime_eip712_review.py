"""Runtime EIP-712 review model never permits blind or typed-data signing."""
from copy import deepcopy

import pytest
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from usb_cold_wallet.evm_eip712 import DOMAIN_FIELDS
from usb_cold_wallet.review import build_eip712_review_pages

CONTRACT = "0x1111111111111111111111111111111111111111"
OWNER = "0x2222222222222222222222222222222222222222"
PARTY = "0x3333333333333333333333333333333333333333"
NOW = 1800000000
DEADLINE = NOW + 3600
FIELDS = [
    {"name": "owner", "type": "address"},
    {"name": "token", "type": "address"},
    {"name": "recipient", "type": "address"},
    {"name": "amount", "type": "uint256"},
    {"name": "nonce", "type": "uint256"},
    {"name": "deadline", "type": "uint256"},
]


def typed():
    return {
        "types": {"EIP712Domain": deepcopy(DOMAIN_FIELDS), "WalletTransferIntent": deepcopy(FIELDS)},
        "primaryType": "WalletTransferIntent",
        "domain": {"name": "USB Cold Wallet Intent", "version": "1",
                   "chainId": 11155111, "verifyingContract": CONTRACT},
        "message": {"owner": OWNER, "token": CONTRACT, "recipient": PARTY,
                    "amount": 123, "nonce": 9, "deadline": DEADLINE},
    }


def approved():
    return {"expected_contract": CONTRACT, "expected_owner": OWNER,
            "expected_primary_type": "WalletTransferIntent",
            "expected_counterparty": PARTY, "expected_amount": 123,
            "expected_nonce": 9, "expected_deadline": DEADLINE,
            "trusted_contracts": [CONTRACT], "now_timestamp": NOW}


def test_independent_typed_hash_and_review_fields():
    message = typed()
    pages = build_eip712_review_pages(message, trusted_approval=approved())
    displayed = {f.key: f.value for p in pages for f in p.fields}
    external = encode_typed_data(full_message=message)
    digest = keccak(b"\x19" + external.version + external.header + external.body)
    assert displayed["signing_digest"] == "0x" + digest.hex()
    assert displayed["owner"] == OWNER
    assert displayed["verifying_contract"] == CONTRACT
    assert displayed["signing_enabled"] == "false"


@pytest.mark.parametrize("mutate", [
    lambda m: m["domain"].update({"chainId": 1}),
    lambda m: m["domain"].update({"verifyingContract": PARTY}),
    lambda m: m["message"].update({"recipient": OWNER}),
    lambda m: m["message"].update({"nonce": 8}),
    lambda m: m["message"].update({"deadline": NOW - 1}),
    lambda m: m.update({"primaryType": "Permit"}),
    lambda m: m["types"]["WalletTransferIntent"].append({"name": "extra", "type": "uint256"}),
])
def test_typed_data_schema_and_replay_fail_closed(mutate):
    message = typed()
    mutate(message)
    with pytest.raises(ValueError):
        build_eip712_review_pages(message, trusted_approval=approved())
