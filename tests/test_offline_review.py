"""Issue #19 offline review model tests use only public, compromised vectors."""
import base64
import json

import pytest
from embit import bip32, psbt, script, transaction
from eth_account import Account

from usb_cold_wallet.exchange import package, read as read_exchange, write
from usb_cold_wallet.keys import btc_address, btc_key, evm_account, root_from_mnemonic
from usb_cold_wallet.review import (
    ReviewSession,
    build_review_plan,
    load_review_file,
    load_review_qr,
)

TEST_MNEMONIC = "abandon " * 11 + "about"
EVM_RECIPIENT = "0x000000000000000000000000000000000000dEaD"


@pytest.fixture(scope="module")
def root():
    return root_from_mnemonic(TEST_MNEMONIC)


def _evm_tx(**changes):
    tx = {
        "type": 2,
        "chainId": 11155111,
        "nonce": 7,
        "to": EVM_RECIPIENT,
        "value": 1_000_000_000_000,
        "gas": 21_000,
        "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000,
        "data": "0x",
        "accessList": [],
    }
    tx.update(changes)
    return tx


def _btc_psbt(root, *, recipient_value=60_000, fee=1_200):
    receive_key = btc_key(root, 0, 0)
    input_utxo = transaction.TransactionOutput(120_000, script.p2wpkh(receive_key.key))
    destination = btc_address(root, 0, 1)
    previous = transaction.Transaction(
        vin=[transaction.TransactionInput(bytes.fromhex("22" * 32), 0)],
        vout=[input_utxo],
    )
    tx = transaction.Transaction(
        vin=[transaction.TransactionInput(previous.txid(), 0)],
        vout=[
            transaction.TransactionOutput(
                recipient_value,
                script.address_to_scriptpubkey(destination),
            ),
            transaction.TransactionOutput(
                120_000 - recipient_value - fee,
                script.p2wpkh(btc_key(root, 1, 0).key),
            ),
        ],
    )
    obj = psbt.PSBT(tx)
    obj.unknown = {}
    obj.inputs[0].unknown = {}
    for scope in obj.outputs:
        scope.unknown = {}
    obj.inputs[0].non_witness_utxo = previous
    obj.inputs[0].witness_utxo = input_utxo
    obj.inputs[0].bip32_derivations[receive_key.key.get_public_key()] = psbt.DerivationPath(
        root.my_fingerprint,
        bip32.parse_path("m/84h/1h/0h/0/0"),
    )
    return base64.b64encode(obj.serialize()).decode(), destination


def _fully_confirm(session: ReviewSession):
    for index in range(len(session.plan.pages)):
        session.acknowledge(index, session.plan.review_digest)
    session.set_confirmation(session.plan.challenge, session.plan.review_digest)


def test_usb_and_qr_share_same_evm_review_pipeline(tmp_path, root):
    envelope = package("evm-request", _evm_tx())
    usb = tmp_path / "request.json"
    usb.write_text(json.dumps(envelope), encoding="utf-8")

    usb_plan = load_review_file(usb, root, "evm-request")
    qr_plan = load_review_qr(json.dumps(envelope), root, "evm-request")

    assert usb_plan.review_digest == qr_plan.review_digest
    assert usb_plan.request_digest == qr_plan.request_digest
    assert usb_plan.account == evm_account(root).address
    assert usb_plan.recipient == EVM_RECIPIENT
    assert [page.key for page in usb_plan.pages] == [
        "network_account",
        "integrity",
        "recipient",
        "amount_fee",
        "policy",
    ]


def test_evm_review_fields_are_offline_derived_and_traceable(root):
    plan = build_review_plan(package("evm-request", _evm_tx()), root)
    flattened = {
        field.key: field
        for page in plan.pages
        for field in page.fields
    }
    assert flattened["chain_id"].value == "11155111"
    assert flattened["nonce"].value == "7"
    assert flattened["recipient"].value == EVM_RECIPIENT
    assert flattened["max_network_fee_wei"].value == "42000000000000"
    assert flattened["max_total_spend_wei"].value == "43000000000000"
    assert flattened["recipient"].source == "payload.to"
    assert flattened["account"].source == "vault m/44h/60h/0h/0/0"
    assert flattened["request_digest"].value == plan.request_digest
    assert flattened["review_digest"].value == plan.review_digest


@pytest.mark.parametrize(
    "changed",
    [
        {"chainId": 1},
        {"gas": 50_000},
        {"data": "0xdeadbeef"},
        {"accessList": [{"address": EVM_RECIPIENT, "storageKeys": []}]},
    ],
)
def test_evm_policy_fail_closed_before_confirmation(root, changed):
    with pytest.raises(ValueError):
        build_review_plan(package("evm-request", _evm_tx(**changed)), root)


def test_btc_review_lists_inputs_outputs_change_and_fee(root):
    encoded, destination = _btc_psbt(root)
    plan = build_review_plan(package("btc-request", encoded), root)
    flattened = {
        field.key: field
        for page in plan.pages
        for field in page.fields
    }

    assert plan.recipient == destination
    assert plan.amount_atomic == 60_000
    assert plan.fee_atomic == 1_200
    assert flattened["network"].value == "Bitcoin testnet"
    assert flattened["input_0_value_sats"].value == "120000"
    assert flattened["output_0_role"].value == "recipient"
    assert flattened["output_0_address"].value == destination
    assert flattened["output_1_role"].value == "change"
    assert flattened["output_1_change_index"].value == "0"
    assert flattened["fee_sats"].value == "1200"
    assert flattened["input_0_outpoint"].source == "PSBT.tx.vin[0]"


def test_confirmation_requires_every_page_and_exact_typed_challenge(root):
    plan = build_review_plan(package("evm-request", _evm_tx()), root)
    session = ReviewSession(plan)

    assert not session.can_sign
    for index in range(len(plan.pages) - 1):
        session.acknowledge(index, plan.review_digest)
    session.set_confirmation(plan.challenge, plan.review_digest)
    assert not session.can_sign

    session.acknowledge(len(plan.pages) - 1, plan.review_digest)
    assert session.can_sign
    session.set_confirmation(plan.challenge + " ", plan.review_digest)
    assert not session.can_sign


def test_digest_mismatch_resets_all_confirmation(root):
    first = build_review_plan(package("evm-request", _evm_tx(nonce=1)), root)
    second = build_review_plan(package("evm-request", _evm_tx(nonce=2)), root)
    session = ReviewSession(first)
    _fully_confirm(session)
    assert session.can_sign

    with pytest.raises(ValueError, match="digest changed"):
        session.acknowledge(0, second.review_digest)
    assert not session.acknowledged_pages
    assert not session.can_sign

    session.replace_plan(second)
    assert session.plan.review_digest == second.review_digest
    assert not session.acknowledged_pages
    assert not session.can_sign


def test_cancel_and_duplicate_sign_are_fail_closed(root):
    plan = build_review_plan(package("evm-request", _evm_tx()), root)
    canceled = ReviewSession(plan)
    _fully_confirm(canceled)
    canceled.cancel()
    with pytest.raises(ValueError, match="explicitly confirmed"):
        canceled.sign(root)

    session = ReviewSession(plan)
    _fully_confirm(session)
    signed = session.sign(root)
    assert signed["kind"] == "evm-signed"
    with pytest.raises(ValueError, match="explicitly confirmed"):
        session.sign(root)


def test_evm_signed_output_matches_reviewed_request_and_backend(root):
    plan = build_review_plan(package("evm-request", _evm_tx()), root)
    session = ReviewSession(plan)
    _fully_confirm(session)
    signed = session.sign(root)
    payload = signed["payload"]

    assert payload["request_sha256"] == plan.request_digest
    assert payload["review_sha256"] == plan.review_digest
    assert payload["chain_id"] == 11155111
    assert payload["to"] == EVM_RECIPIENT
    assert payload["value_wei"] == 1_000_000_000_000
    assert Account.recover_transaction(payload["signed_raw_transaction"]) == evm_account(root).address


def test_btc_signed_output_matches_review_and_exports_create_only(tmp_path, root):
    encoded, destination = _btc_psbt(root)
    plan = build_review_plan(package("btc-request", encoded), root)
    session = ReviewSession(plan)
    _fully_confirm(session)
    signed = session.sign(root)

    payload = signed["payload"]
    assert payload["network"] == "bitcoin-testnet"
    assert payload["recipient"] == destination
    assert payload["amount_sats"] == 60_000
    assert payload["fee_sats"] == 1_200
    assert payload["signature_count"] == 1
    assert payload["request_sha256"] == plan.request_digest
    assert payload["review_sha256"] == plan.review_digest

    out = tmp_path / "signed.json"
    session.export_signed(out)
    assert read_exchange(out, "btc-signed")["signed_psbt_base64"] == payload["signed_psbt_base64"]
    with pytest.raises(FileExistsError):
        session.export_signed(out)


def test_review_digest_fields_are_strict_and_never_arbitrary_metadata(root):
    plan = build_review_plan(package("evm-request", _evm_tx()), root)
    session = ReviewSession(plan)
    _fully_confirm(session)
    signed = session.sign(root)
    payload = signed["payload"]
    assert package("evm-signed", payload)["payload"] == payload

    from copy import deepcopy
    attacks = [
        {key: value for key, value in payload.items() if key != "review_sha256"},
        {**payload, "request_sha256": "not-a-digest"},
        {**payload, "review_sha256": "a" * 65},
        {**payload, "extra": {"recovery_words": "abandon " * 11 + "about"}},
    ]
    for bad in attacks:
        with pytest.raises(ValueError):
            package("evm-signed", bad)


def test_signing_with_different_wallet_is_rejected(root):
    plan = build_review_plan(package("evm-request", _evm_tx()), root)
    session = ReviewSession(plan)
    _fully_confirm(session)
    other = root_from_mnemonic(
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
    )
    with pytest.raises(ValueError, match="wallet account changed"):
        session.sign(other)


def test_malicious_long_or_invalid_qr_text_never_creates_review(root):
    with pytest.raises(ValueError, match="too large"):
        load_review_qr("x" * 210_000, root)
    with pytest.raises(ValueError):
        load_review_qr('{"format":"usb-cold-wallet-exchange","kind":"evm-request","kind":"btc-request"}', root)
    with pytest.raises(ValueError):
        load_review_qr("\ud800", root)
