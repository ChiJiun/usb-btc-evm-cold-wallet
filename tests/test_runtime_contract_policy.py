"""Runtime ERC-20 policy integration regression tests using independent eth-abi."""
from copy import deepcopy

import pytest
from eth_abi import encode

from usb_cold_wallet.keys import root_from_mnemonic, evm_account
from usb_cold_wallet.policy import default_profile, decide_erc20, validate_profile
from usb_cold_wallet.review import build_erc20_review_pages
from usb_cold_wallet.evm import sign_evm

CONTRACT = "0x1111111111111111111111111111111111111111"
PARTY = "0x2222222222222222222222222222222222222222"
BAD = "0x3333333333333333333333333333333333333333"


@pytest.fixture
def wallet():
    return root_from_mnemonic("abandon " * 11 + "about")


@pytest.fixture
def profile(wallet):
    result = default_profile(wallet)
    result["contract_rules"] = [
        {"contract": CONTRACT, "method": "transfer", "counterparty": PARTY,
         "max_amount": 250, "expected_nonce": 7},
        {"contract": CONTRACT, "method": "approve", "counterparty": PARTY,
         "max_amount": 100, "expected_nonce": 7},
    ]
    return result


def transaction(method="transfer", amount=100, party=PARTY):
    selector = "a9059cbb" if method == "transfer" else "095ea7b3"
    return {"type": 2, "chainId": 11155111, "nonce": 7, "to": CONTRACT,
            "value": 0, "gas": 80000, "maxFeePerGas": 1_000_000_000,
            "maxPriorityFeePerGas": 500_000_000,
            "data": "0x" + selector + encode(["address", "uint256"], [party, amount]).hex()}


@pytest.mark.parametrize("method,amount", [("transfer", 100), ("approve", 80), ("approve", 0)])
def test_encrypted_profile_allowlisted_runtime_review(wallet, profile, method, amount):
    assert validate_profile(profile, wallet)
    tx = transaction(method, amount)
    review, decision = decide_erc20(profile, wallet, tx)
    assert review["method"] == method
    assert decision.status == "REQUIRE_EXTRA_CONFIRMATION"
    pages, gui_decision = build_erc20_review_pages(tx, wallet, profile)
    assert gui_decision == decision
    fields = {field.key: field.value for page in pages for field in page.fields}
    assert fields["contract"] == CONTRACT
    assert fields["signing_enabled"] == "false"
    assert fields["nonce"] == "7"
    assert fields["amount_atomic" if method == "transfer" else "allowance_atomic"] == str(amount)
    if amount == 0:
        assert fields["revoke"] == "true"
    # A decision that permits human review must never unlock the native signer.
    with pytest.raises(ValueError):
        sign_evm(wallet, tx, CONTRACT, 0)


@pytest.mark.parametrize("change", [
    lambda p, t: t.update({"chainId": 1}),
    lambda p, t: t.update({"nonce": 8}),
    lambda p, t: t.update({"to": BAD}),
    lambda p, t: t.update({"gas": 400000}),
    lambda p, t: t.update({"maxFeePerGas": 2_000_000_000_000}),
    lambda p, t: t.update({"tokenSymbol": "USDC"}),
    lambda p, t: t.update({"data": "0xdeadbeef" + t["data"][10:]}),
    lambda p, t: t.update({"data": t["data"] + "00"}),
    lambda p, t: t.update({"value": 1}),
    lambda p, t: (p["contract_rules"].pop(), t.update({"data": "0x095ea7b3" + t["data"][10:]})),
    lambda p, t: t.update({"data": "0xa9059cbb" + encode(["address", "uint256"], [BAD, 100]).hex()}),
    lambda p, t: t.update({"data": "0xa9059cbb" + encode(["address", "uint256"], [PARTY, 251]).hex()}),
])
def test_fail_closed_adversarial_runtime_policy(wallet, profile, change):
    t = transaction()
    change(profile, t)
    review, decision = decide_erc20(profile, wallet, t)
    assert review is None
    assert decision.status == "DENY"


def test_denies_missing_rule_tamper_and_cross_wallet(wallet, profile):
    t = transaction()
    blank = default_profile(wallet)
    assert decide_erc20(blank, wallet, t)[1].status == "DENY"
    wrong = deepcopy(profile)
    wrong["wallet_binding"] = "wrong"
    assert decide_erc20(wrong, wallet, t)[1].status == "DENY"
    wrong = deepcopy(profile)
    wrong["contract_rules"][0]["counterparty"] = BAD
    assert decide_erc20(wrong, wallet, t)[1].status == "DENY"
    wrong = deepcopy(profile)
    wrong["contract_rules"][0]["expected_nonce"] = 8
    assert decide_erc20(wrong, wallet, t)[1].status == "DENY"
    wrong = deepcopy(profile)
    wrong["contract_rules"][0]["max_amount"] = True
    with pytest.raises(ValueError):
        validate_profile(wrong, wallet)
