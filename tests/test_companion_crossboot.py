"""Cross-process/simulated-reboot tests for single-USB Companion state.

All keys come from the public BIP39 test vector; never use this mnemonic for funds.
"""
import http.client
import json
import threading
from pathlib import Path

import pytest
from eth_account import Account
from eth_utils import keccak
from embit import script, transaction

from usb_cold_wallet.btc import sign_btc_psbt
from usb_cold_wallet.companion_btc import BitcoinCompanion
from usb_cold_wallet.companion_core import (
    CHAIN_ID, CompanionSession, canonical, pack_envelope,
)
from usb_cold_wallet.companion_crossboot import CrossBootManager
from usb_cold_wallet.companion_web import create_server
from usb_cold_wallet.evm import decode_signed_eip1559
from usb_cold_wallet.keys import btc_address, evm_account, root_from_mnemonic, watch_only

MNEMONIC = "abandon " * 11 + "about"
ROOT = root_from_mnemonic(MNEMONIC)
WATCH = watch_only(ROOT, count=2)
ADDRESS = WATCH["evm"]["address"]
RECIPIENT = "0x000000000000000000000000000000000000dEaD"
BTC_RECEIVE = WATCH["bitcoin"]["receive_addresses"][0]
BTC_TARGET = btc_address(ROOT, 0, 1)


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


class FakeBtcEsplora:
    display_endpoint = "https://mock-bitcoin-testnet.invalid"

    def __init__(self, sats=150_000):
        previous = transaction.Transaction(
            version=2,
            vin=[transaction.TransactionInput(bytes.fromhex("ab" * 32), 0, sequence=0xFFFFFFFF)],
            vout=[transaction.TransactionOutput(sats, script.address_to_scriptpubkey(BTC_RECEIVE))],
            locktime=0,
        )
        self.previous_transaction = previous
        self.txid = previous.txid().hex()
        self.sats = sats
        self.sent = []

    def utxos(self, address):
        if address != BTC_RECEIVE:
            return []
        return [{"txid": self.txid, "vout": 0, "value": self.sats,
                 "status": {"confirmed": True}}]

    def activity(self, address):
        return {"chain_stats": {"funded_txo_count": 0},
                "mempool_stats": {"funded_txo_count": 0}}

    def previous(self, txid):
        assert txid == self.txid
        return self.previous_transaction

    def fee_rate(self):
        return 2

    def send(self, raw_hex):
        self.sent.append(raw_hex)
        return transaction.Transaction.parse(bytes.fromhex(raw_hex)).txid().hex()

    def status(self, txid):
        return {"confirmed": False}


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


def test_btc_psbt_survives_restart_and_reverifies_without_broadcast(tmp_path):
    manager = CrossBootManager(tmp_path)
    evm, _unused_btc, _ = fresh_sessions()
    btc_rpc = FakeBtcEsplora()
    btc = BitcoinCompanion(btc_rpc)
    btc.import_wallet(WATCH)
    prepared = btc.prepare(BTC_TARGET, "0.0005")
    request_id = prepared["pending"]["request_id"]
    encoded = prepared["envelope"]["payload"]

    manager.export_current(evm, btc)
    signed = sign_btc_psbt(ROOT, encoded, BTC_TARGET, 50_000, 50_000, 0)
    response = pack_envelope("btc-signed", signed)
    manager.exchange.joinpath(f"response-{request_id}.json").write_text(
        json.dumps(response), encoding="ascii"
    )

    restored_evm, _discard, _ = fresh_sessions()
    restored_btc = BitcoinCompanion(FakeBtcEsplora())
    restored_btc.import_wallet(WATCH)
    restored_evm.pending = None
    restored_btc.pending = None
    assert manager.restore(restored_evm, restored_btc)
    status = manager.resume_response(restored_evm, restored_btc)
    assert status["asset"] == "bitcoin-testnet"
    assert status["stage"] == "verified"
    assert restored_btc.pending["request_id"] == request_id
    assert restored_btc.pending["recipient"] == BTC_TARGET
    assert restored_btc.pending["amount_sats"] == 50_000
    assert btc_rpc.sent == []


def test_crossboot_http_api_persists_and_exports_without_broadcast(tmp_path):
    manager = CrossBootManager.auto(tmp_path)
    server, app, token = create_server(FakeRpc(), 0, NoNetworkEsplora(), manager)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    port = server.server_port

    def request(method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
        headers = {
            "Host": f"127.0.0.1:{port}",
            "Origin": f"http://127.0.0.1:{port}",
            "X-Companion-Token": token,
        }
        raw = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            raw = canonical(body)
        conn.request(method, path, body=raw, headers=headers)
        response = conn.getresponse()
        data = json.loads(response.read())
        status = response.status
        conn.close()
        return status, data

    try:
        code, imported = request("POST", "/api/import", {"raw": canonical(WATCH).decode()})
        assert code == 200 and imported["loaded"]
        code, prepared = request("POST", "/api/prepare", {
            "recipient": RECIPIENT, "amount_eth": "0.01", "max_fee_gwei": ""
        })
        assert code == 200 and prepared["pending"]["stage"] == "prepared"
        request_id = prepared["pending"]["request_id"]

        code, state = request("GET", "/api/crossboot")
        assert code == 200 and state["can_export"]
        assert state["request_id"] == request_id

        code, exported = request("POST", "/api/crossboot/export", {})
        assert code == 200 and exported["request_id"] == request_id
        assert manager.state_path.is_file()
        assert manager.exchange.joinpath(f"request-{request_id}.json").is_file()
        assert app.rpc.sent == []
    finally:
        server.shutdown()
        server.server_close()
        worker.join(5)
