"""Runtime EIP-712 review model never permits blind or typed-data signing."""
from copy import deepcopy

import pytest
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from usb_cold_wallet.evm_eip712 import DOMAIN_FIELDS
from usb_cold_wallet.review import build_eip712_review_pages, build_eip712_policy_pages
from usb_cold_wallet.keys import root_from_mnemonic, evm_account
from usb_cold_wallet.policy import default_profile, decide_eip712

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


def test_typed_policy_uses_wallet_bound_rules_and_exact_deadline():
    wallet = root_from_mnemonic("abandon " * 11 + "about")
    msg = typed()
    msg["message"]["owner"] = evm_account(wallet).address
    policy = default_profile(wallet)
    policy["typed_rules"] = [{
        "contract": CONTRACT, "schema": "WalletTransferIntent",
        "counterparty": PARTY, "max_amount": 123, "expected_nonce": 9,
        "deadline": DEADLINE,
    }]
    pages, decision = build_eip712_policy_pages(msg, wallet, policy, now_timestamp=NOW)
    assert decision.status == "REQUIRE_EXTRA_CONFIRMATION"
    display = {f.key: f.value for p in pages for f in p.fields}
    assert display["signing_enabled"] == "false"
    assert display["schema"] == "WalletTransferIntent"
    assert display["nonce"] == "9"
    assert display["deadline"] == str(DEADLINE)

    msg["message"]["nonce"] = 8
    assert decide_eip712(policy, wallet, msg, now_timestamp=NOW)[1].status == "DENY"
    msg["message"]["nonce"] = 9
    msg["message"]["amount"] = 124
    assert decide_eip712(policy, wallet, msg, now_timestamp=NOW)[1].status == "DENY"
    msg["message"]["amount"] = 123
    msg["message"]["deadline"] = DEADLINE + 1
    assert decide_eip712(policy, wallet, msg, now_timestamp=NOW)[1].status == "DENY"
    msg["message"]["deadline"] = DEADLINE
    assert decide_eip712(policy, wallet, msg, now_timestamp=DEADLINE)[1].status == "DENY"
    policy["typed_rules"] = []
    assert decide_eip712(policy, wallet, msg, now_timestamp=NOW)[1].status == "DENY"
