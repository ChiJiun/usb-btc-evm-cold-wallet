"""Cross-process/simulated-reboot tests for single-USB Companion state.

All keys come from the public BIP39 test vector; never use this mnemonic for funds.
"""
import json
from pathlib import Path

import pytest
from eth_account import Account
from eth_utils import keccak

from usb_cold_wallet.companion_btc import BitcoinCompanion
from usb_cold_wallet.companion_core import (
    CHAIN_ID, CompanionSession, canonical, pack_envelope,
)
from usb_cold_wallet.companion_crossboot import CrossBootManager
from usb_cold_wallet.evm import decode_signed_eip1559
from usb_cold_wallet.keys import evm_account, root_from_mnemonic, watch_only

MNEMONIC = "abandon " * 11 + "about"
ROOT = root_from_mnemonic(MNEMONIC)
WATCH = watch_only(ROOT, count=2)
ADDRESS = WATCH["evm"]["address"]
RECIPIENT = "0x000000000000000000000000000000000000dEaD"


class FakeRpc:
    display_endpoint = "https://mock-sepolia.invalid"

    def __init__(self):
        self.balance = 5 * 10**18
        self.nonce = 3
        self.sent = []

    def assert_sepolia(self):
        return None

    def account_state(self, address):
        assert address == ADDRESS
        return self.balance, self.nonce

    def fee_quote(self):
        return 2_000_000_000, 1_000_000_000

    def call(self, method, params):
        if method == "eth_getTransactionCount":
            return hex(self.nonce)
        if method == "eth_sendRawTransaction":
            self.sent.append(params[0])
            return "0x" + keccak(hexstr=params[0]).hex()
        if method == "eth_getTransactionReceipt":
            return None
        if method == "eth_getTransactionByHash":
            return {"hash": params[0]}
        raise AssertionError(method)


class NoNetworkEsplora:
    display_endpoint = "https://unused.invalid"


def fresh_sessions(rpc=None):
    rpc = rpc or FakeRpc()
    evm = CompanionSession(rpc)
    evm.import_wallet(canonical(WATCH))
    btc = BitcoinCompanion(NoNetworkEsplora())
    btc.import_wallet(WATCH)
    return evm, btc, rpc


def signed_response(tx, *, recipient=None):
    signed_tx = dict(tx)
    if recipient is not None:
        signed_tx["to"] = recipient
    account = evm_account(ROOT)
    signed = Account.sign_transaction(signed_tx, account.key)
    raw = "0x" + signed.raw_transaction.hex()
    decoded = decode_signed_eip1559(raw)
    payload = {
        "chain_id": CHAIN_ID,
        "from": account.address,
        "to": signed_tx["to"],
        "value_wei": signed_tx["value"],
        "max_fee_wei": signed_tx["gas"] * signed_tx["maxFeePerGas"],
        "max_total_wei": signed_tx["value"] + signed_tx["gas"] * signed_tx["maxFeePerGas"],
        "decoded_transaction": decoded,
        "transaction_hash": decoded["transaction_hash"],
        "signed_raw_transaction": raw,
    }
    return pack_envelope("evm-signed", payload)


def test_pending_request_survives_process_restart_and_signed_response_reverifies(tmp_path):
    manager = CrossBootManager.auto(tmp_path)
    online, btc, rpc = fresh_sessions()
    prepared = online.prepare(RECIPIENT, "0.01")
    request_id = prepared["pending"]["request_id"]

    status = manager.export_current(online, btc)
    request_file = manager.exchange / f"request-{request_id}.json"
    assert status["can_export"] and request_file.is_file()
    assert json.loads(request_file.read_text()) == prepared["envelope"]

    response = signed_response(online.pending["tx"])
    manager.exchange.joinpath(f"response-{request_id}.json").write_text(
        json.dumps(response), encoding="ascii"
    )

    restored, restored_btc, _ = fresh_sessions(rpc)
    restored.pending = None
    restored_btc.pending = None
    assert manager.restore(restored, restored_btc)
    result = manager.resume_response(restored, restored_btc)
    assert result["stage"] == "verified"
    assert restored.pending["request_id"] == request_id
    assert restored.pending["tx"] == online.pending["tx"]
    assert rpc.sent == []  # verification/recovery never broadcasts


def test_malicious_signed_result_is_rejected_after_restart(tmp_path):
    manager = CrossBootManager(tmp_path)
    online, btc, _ = fresh_sessions()
    prepared = online.prepare(RECIPIENT, "0.01")
    manager.export_current(online, btc)
    request_id = prepared["pending"]["request_id"]

    bad = signed_response(
        online.pending["tx"],
        recipient="0x1111111111111111111111111111111111111111",
    )
    manager.exchange.joinpath(f"response-{request_id}.json").write_text(
        json.dumps(bad), encoding="ascii"
    )

    restored, restored_btc, _ = fresh_sessions()
    restored.pending = None
    restored_btc.pending = None
    manager.restore(restored, restored_btc)
    with pytest.raises(ValueError, match="differs|mismatch"):
        manager.resume_response(restored, restored_btc)
    assert restored.pending["stage"] == "prepared"


def test_ambiguous_response_and_stale_request_fail_closed(tmp_path):
    manager = CrossBootManager(tmp_path)
    online, btc, _ = fresh_sessions()
    prepared = online.prepare(RECIPIENT, "0.01")
    request_id = prepared["pending"]["request_id"]
    manager.exchange.mkdir(parents=True)
    manager.exchange.joinpath("request-" + "b" * 32 + ".json").write_text("{}", encoding="ascii")
    with pytest.raises(ValueError, match="Another pending request"):
        manager.export_current(online, btc)

    manager.exchange.joinpath("request-" + "b" * 32 + ".json").unlink()
    manager.export_current(online, btc)
    response = signed_response(online.pending["tx"])
    manager.exchange.joinpath(f"response-{request_id}.json").write_text(json.dumps(response), encoding="ascii")
    manager.exchange.joinpath(f"response-{request_id}-duplicate.json").write_text(json.dumps(response), encoding="ascii")
    with pytest.raises(ValueError, match="ambiguous"):
        manager.resume_response(online, btc)


def test_state_checksum_tamper_is_rejected(tmp_path):
    manager = CrossBootManager(tmp_path)
    online, btc, _ = fresh_sessions()
    online.prepare(RECIPIENT, "0.01")
    manager.save(online, btc)
    state = json.loads(manager.state_path.read_text())
    state["evm"]["digest"] = "0" * 64
    manager.state_path.write_text(json.dumps(state), encoding="ascii")
    restored, restored_btc, _ = fresh_sessions()
    restored.pending = None
    restored_btc.pending = None
    with pytest.raises(ValueError, match="checksum"):
        manager.restore(restored, restored_btc)


def test_broadcasted_state_cannot_broadcast_twice_after_restart(tmp_path):
    manager = CrossBootManager(tmp_path)
    online, btc, rpc = fresh_sessions()
    prepared = online.prepare(RECIPIENT, "0.01")
    online.accept_signed(canonical(signed_response(online.pending["tx"])))
    assert online.broadcast()["stage"] == "broadcasted"
    assert len(rpc.sent) == 1
    manager.save(online, btc)

    restored, restored_btc, _ = fresh_sessions(rpc)
    restored.pending = None
    restored_btc.pending = None
    manager.restore(restored, restored_btc)
    assert restored.pending["request_id"] == prepared["pending"]["request_id"]
    assert restored.pending["stage"] == "broadcasted"
    with pytest.raises(ValueError, match="cannot repeat"):
        restored.broadcast()
    assert len(rpc.sent) == 1
