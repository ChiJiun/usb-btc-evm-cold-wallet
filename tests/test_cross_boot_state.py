"""Issue #37 single-USB cross-boot protocol/state tests.

All keys and transactions use the public BIP39 "abandon ... about" vector.
"""
from __future__ import annotations

import base64
import copy

import pytest
from embit import bip32, psbt, script, transaction

from usb_cold_wallet.btc import sign_btc_psbt
from usb_cold_wallet.cross_boot import (
    _envelope_sha,
    package_v2_request,
    package_v2_response,
    verify_v2_request,
    verify_v2_response,
    read_v2_request,
    read_v2_response,
    write_v2,
)
from usb_cold_wallet.evm import sign_evm
from usb_cold_wallet.keys import btc_address, btc_key, evm_account, root_from_mnemonic
from usb_cold_wallet.transaction_state import (
    PendingRequestStore,
    ReplayLedger,
    RollbackDetected,
    StateCorruptionError,
)

MNEMONIC = "abandon " * 11 + "about"
ROOT = root_from_mnemonic(MNEMONIC)
EVM_ACCOUNT = evm_account(ROOT).address
EVM_RECIPIENT = "0x000000000000000000000000000000000000dEaD"
BTC_RECIPIENT = btc_address(ROOT, 0, 1)


def evm_tx(nonce=7, value=123456789):
    return {
        "type": 2,
        "chainId": 11155111,
        "nonce": nonce,
        "to": EVM_RECIPIENT,
        "value": value,
        "gas": 21000,
        "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000,
        "data": "0x",
        "accessList": [],
    }


def evm_request(request_id="11" * 16, *, nonce=7, expiry=None):
    tx = evm_tx(nonce)
    return package_v2_request(
        "evm-request",
        tx,
        request_id=request_id,
        account=EVM_ACCOUNT,
        recipient=EVM_RECIPIENT,
        amount=tx["value"],
        expiry=expiry or {"mode": "trusted-time", "notAfter": 200},
    )


def btc_psbt():
    receive = btc_address(ROOT, 0, 0)
    change = btc_address(ROOT, 1, 0)
    previous = transaction.Transaction(
        version=2,
        vin=[transaction.TransactionInput(bytes.fromhex("ab" * 32), 0, sequence=0xFFFFFFFF)],
        vout=[transaction.TransactionOutput(150_000, script.address_to_scriptpubkey(receive))],
        locktime=0,
    )
    unsigned = transaction.Transaction(
        version=2,
        vin=[transaction.TransactionInput(previous.txid(), 0, sequence=0xFFFFFFFF)],
        vout=[
            transaction.TransactionOutput(60_000, script.address_to_scriptpubkey(BTC_RECIPIENT)),
            transaction.TransactionOutput(88_500, script.address_to_scriptpubkey(change)),
        ],
        locktime=0,
    )
    obj = psbt.PSBT(unsigned)
    obj.inputs[0].witness_utxo = previous.vout[0]
    obj.inputs[0].non_witness_utxo = previous
    key = btc_key(ROOT, 0, 0)
    obj.inputs[0].bip32_derivations[key.key.get_public_key()] = psbt.DerivationPath(
        ROOT.my_fingerprint, bip32.parse_path("m/84h/1h/0h/0/0")
    )
    return obj.to_base64()


def btc_request(request_id="22" * 16):
    return package_v2_request(
        "btc-request",
        btc_psbt(),
        request_id=request_id,
        account=ROOT.my_fingerprint.hex(),
        recipient=BTC_RECIPIENT,
        amount=60_000,
        expiry={"mode": "trusted-time", "notAfter": 200},
    )


def rehash(envelope):
    envelope["sha256"] = _envelope_sha(envelope)
    return envelope


def test_evm_v2_full_request_response_binding():
    request = evm_request()
    checked = verify_v2_request(request, trusted_time=100)
    assert checked["expiryAssurance"] == "trusted-time"
    assert checked["intent"] == {
        "recipient": EVM_RECIPIENT,
        "amount": 123456789,
        "fee": 42_000_000_000_000,
        "nonce": 7,
        "utxos": [],
    }
    signed = sign_evm(ROOT, request["payload"], EVM_RECIPIENT, request["intent"]["amount"])
    response = package_v2_response(request, signed, trusted_time=100)
    assert verify_v2_response(request, response, trusted_time=100) == signed


def test_btc_v2_full_request_response_binds_utxo_account_fee_and_unsigned_tx():
    request = btc_request()
    checked = verify_v2_request(request, trusted_time=100)
    assert checked["intent"]["fee"] == 1500
    assert checked["intent"]["utxos"][0]["vout"] == 0
    assert checked["intent"]["utxos"][0]["value"] == 150_000
    signed = sign_btc_psbt(ROOT, request["payload"], BTC_RECIPIENT, 60_000, 1500, 0)
    response = package_v2_response(request, signed, trusted_time=100)
    assert verify_v2_response(request, response, trusted_time=100) == signed


@pytest.mark.parametrize("mutator", [
    lambda r: r.update(network="bitcoin-testnet"),
    lambda r: r.update(account="0x0000000000000000000000000000000000000000"),
    lambda r: r.update(transactionDigest="00" * 32),
    lambda r: r["intent"].update(nonce=8),
    lambda r: r["intent"].update(amount=1),
])
def test_v2_request_rejects_recomputed_wrong_chain_account_digest_or_intent(mutator):
    request = copy.deepcopy(evm_request())
    mutator(request)
    rehash(request)
    with pytest.raises(ValueError):
        verify_v2_request(request, trusted_time=100)


def test_expiry_requires_trusted_time_or_explicit_restricted_no_clock_mode():
    request = evm_request()
    with pytest.raises(ValueError, match="Trusted time"):
        verify_v2_request(request)
    with pytest.raises(ValueError, match="expired"):
        verify_v2_request(request, trusted_time=201)

    no_clock = evm_request(expiry={"mode": "no-trusted-clock", "notAfter": None})
    with pytest.raises(ValueError, match="restricted mode"):
        verify_v2_request(no_clock)
    checked = verify_v2_request(no_clock, allow_no_trusted_clock=True)
    assert checked["expiryAssurance"] == "unverified"


def test_signed_response_replacement_and_replay_on_other_request_rejected():
    first = evm_request("31" * 16, nonce=7)
    second = evm_request("32" * 16, nonce=8)
    signed_second = sign_evm(ROOT, second["payload"], EVM_RECIPIENT, second["intent"]["amount"])
    response_second = package_v2_response(second, signed_second, trusted_time=100)
    with pytest.raises(ValueError):
        verify_v2_response(first, response_second, trusted_time=100)


def test_online_state_survives_restarts_and_prevents_double_broadcast(tmp_path):
    root = tmp_path / "online-state"
    request = evm_request()
    signed = sign_evm(ROOT, request["payload"], EVM_RECIPIENT, request["intent"]["amount"])
    response = package_v2_response(request, signed, trusted_time=100)

    store = PendingRequestStore(root)
    assert store.create(request).state == "DRAFT"
    store = PendingRequestStore(root)
    assert store.exported(request).state == "EXPORTED"
    store = PendingRequestStore(root)
    assert store.import_verified(request, response, trusted_time=100).state == "IMPORTED_VERIFIED"
    store = PendingRequestStore(root)
    assert store.broadcasted(request, signed["transaction_hash"]).state == "BROADCASTED"
    store = PendingRequestStore(root)
    assert store.get(request["requestId"]).state == "BROADCASTED"
    with pytest.raises(ValueError, match="transition"):
        store.broadcasted(request, signed["transaction_hash"])


def test_cold_replay_ledger_survives_restart_and_blocks_id_and_transaction_replay(tmp_path):
    root = tmp_path / "cold-ledger"
    request = evm_request("41" * 16)
    ledger = ReplayLedger(root)
    checked = verify_v2_request(request, trusted_time=100)
    assert ledger.review_once(request, trusted_time=100).state == "COLD_REVIEWED"
    ledger = ReplayLedger(root)
    with pytest.raises(ValueError, match="Duplicate requestId"):
        ledger.review_once(request, trusted_time=100)

    same_tx_new_id = copy.deepcopy(request)
    same_tx_new_id["requestId"] = "42" * 16
    rehash(same_tx_new_id)
    with pytest.raises(ValueError, match="Transaction digest already reviewed"):
        ledger.review_once(same_tx_new_id, trusted_time=100)


def test_cold_signed_state_and_response_digest_survive_restart(tmp_path):
    root = tmp_path / "cold-ledger"
    request = btc_request()
    checked = verify_v2_request(request, trusted_time=100)
    ledger = ReplayLedger(root)
    ledger.review_once(request, trusted_time=100)
    signed = sign_btc_psbt(ROOT, request["payload"], BTC_RECIPIENT, 60_000, 1500, 0)
    response = package_v2_response(request, signed, trusted_time=100)
    ledger.mark_signed(request, response, trusted_time=100)
    assert ReplayLedger(root).get(request["requestId"]).state == "SIGNED"


def test_trailing_partial_write_is_recoverable_but_reported(tmp_path):
    root = tmp_path / "online-state"
    request = evm_request()
    store = PendingRequestStore(root)
    store.create(request)
    (root / ".simulated-crash.partial").write_bytes(b'{"truncated":')
    reopened = PendingRequestStore(root)
    assert reopened.get(request["requestId"]).state == "DRAFT"
    assert reopened.recovery_warnings


def test_corrupt_published_state_fails_closed(tmp_path):
    root = tmp_path / "online-state"
    request = evm_request()
    store = PendingRequestStore(root)
    store.create(request)
    published = next(root.glob("*.json"))
    published.write_bytes(b'{"corrupt":true}\n')
    with pytest.raises(StateCorruptionError):
        PendingRequestStore(root)


def test_external_tip_anchor_detects_whole_store_rollback(tmp_path):
    root = tmp_path / "online-state"
    request = evm_request()
    store = PendingRequestStore(root)
    store.create(request)
    store.exported(request)
    expected_tip = store.tip_anchor()
    assert store.rollback_resistant is False

    records = sorted(root.glob("*.json"))
    records[-1].unlink()
    with pytest.raises(RollbackDetected):
        PendingRequestStore(root, expected_tip=expected_tip)


def test_unanchored_store_does_not_claim_rollback_protection(tmp_path):
    request = evm_request()
    online = PendingRequestStore(tmp_path / "state")
    online.create(request)
    assert online.rollback_resistant is False


def test_v2_file_io_reuses_bounded_atomic_exchange_primitives(tmp_path):
    request = evm_request()
    request_path = tmp_path / "request.json"
    write_v2(request_path, request)
    loaded = read_v2_request(request_path, trusted_time=100)
    assert loaded["requestId"] == request["requestId"]

    signed = sign_evm(ROOT, request["payload"], EVM_RECIPIENT, request["intent"]["amount"])
    response = package_v2_response(request, signed, trusted_time=100)
    response_path = tmp_path / "response.json"
    write_v2(response_path, response)
    assert read_v2_response(response_path, request, trusted_time=100)["requestId"] == request["requestId"]

    with pytest.raises(FileExistsError):
        write_v2(request_path, request)
