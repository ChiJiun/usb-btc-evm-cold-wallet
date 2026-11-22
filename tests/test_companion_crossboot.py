"""Single-USB Companion integration against the formal Issue #37 v2 contract."""
import hashlib
import http.client
import json
import threading
from pathlib import Path

import pytest
from embit import script, transaction
from eth_account import Account
from eth_utils import keccak

from usb_cold_wallet.btc import sign_btc_psbt
from usb_cold_wallet.companion_btc import BitcoinCompanion
from usb_cold_wallet.companion_core import CompanionSession, canonical
from usb_cold_wallet.companion_crossboot import CrossBootManager, _package_request, discover_windows_exchange_root
from usb_cold_wallet.companion_web import create_server
from usb_cold_wallet.cross_boot import (
    package_v2_response, verify_v2_request, verify_v2_response,
)
from usb_cold_wallet.evm import decode_signed_eip1559
from usb_cold_wallet.keys import btc_address, evm_account, root_from_mnemonic, watch_only
from usb_cold_wallet.transaction_state import PendingRequestStore

MNEMONIC = "abandon " * 11 + "about"
ROOT = root_from_mnemonic(MNEMONIC)
WATCH = watch_only(ROOT, count=2)
ADDRESS = WATCH["evm"]["address"]
RECIPIENT = "0x000000000000000000000000000000000000dEaD"
BTC_RECEIVE = WATCH["bitcoin"]["receive_addresses"][0]
BTC_TARGET = btc_address(ROOT, 0, 1)


class FakeRpc:
    display_endpoint = "https://mock-sepolia.invalid"

    def __init__(self, *, fail_send=False):
        self.balance = 5 * 10**18
        self.nonce = 3
        self.sent = []
        self.fail_send = fail_send

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
            if self.fail_send:
                raise ValueError("simulated timeout")
            self.sent.append(params[0])
            return "0x" + keccak(hexstr=params[0]).hex()
        if method == "eth_getTransactionReceipt":
            return None
        if method == "eth_getTransactionByHash":
            return {"hash": params[0]}
        raise AssertionError(method)


class NoNetworkEsplora:
    display_endpoint = "https://unused.invalid"


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


def fresh_sessions(rpc=None, btc_api=None):
    rpc = rpc or FakeRpc()
    evm = CompanionSession(rpc)
    evm.import_wallet(canonical(WATCH))
    btc = BitcoinCompanion(btc_api or NoNetworkEsplora())
    btc.import_wallet(WATCH)
    return evm, btc, rpc


def signed_evm_payload(tx, *, recipient=None):
    signed_tx = dict(tx)
    if recipient is not None:
        signed_tx["to"] = recipient
    account = evm_account(ROOT)
    signed = Account.sign_transaction(signed_tx, account.key)
    raw = "0x" + signed.raw_transaction.hex()
    decoded = decode_signed_eip1559(raw)
    return {
        "chain_id": 11155111,
        "from": account.address,
        "to": signed_tx["to"],
        "value_wei": signed_tx["value"],
        "max_fee_wei": signed_tx["gas"] * signed_tx["maxFeePerGas"],
        "max_total_wei": signed_tx["value"] + signed_tx["gas"] * signed_tx["maxFeePerGas"],
        "decoded_transaction": decoded,
        "transaction_hash": decoded["transaction_hash"],
        "signed_raw_transaction": raw,
    }


def load_request(manager, request_id):
    return json.loads(manager.exchange.joinpath(f"request-{request_id}.json").read_text())


def write_response(manager, request_id, response):
    manager.exchange.joinpath(f"response-{request_id}.json").write_text(
        json.dumps(response, sort_keys=True, separators=(",", ":")), encoding="ascii"
    )


def test_windows_adapter_emits_formal_v2_request_and_official_state(tmp_path):
    manager = CrossBootManager.auto(tmp_path)
    online, btc, _ = fresh_sessions()
    prepared = online.prepare(RECIPIENT, "0.01")
    request_id = prepared["pending"]["request_id"]

    manager.export_current(online, btc)
    request = load_request(manager, request_id)
    checked = verify_v2_request(
        request, expected_account=ADDRESS, allow_no_trusted_clock=True
    )
    assert checked["requestId"] == request_id
    assert checked["version"] == 2
    assert checked["intent"]["recipient"] == RECIPIENT
    assert checked["intent"]["amount"] == 10**16
    assert checked["expiryAssurance"] == "unverified"

    snap = PendingRequestStore(manager.state_root).get(request_id)
    assert snap.state == "EXPORTED"
    assert snap.request_digest == request["sha256"]
    assert snap.transaction_digest == request["transactionDigest"]


def test_sepolia_response_survives_restart_and_reverifies_before_broadcast(tmp_path):
    manager = CrossBootManager(tmp_path)
    online, btc, rpc = fresh_sessions()
    prepared = online.prepare(RECIPIENT, "0.01")
    request_id = prepared["pending"]["request_id"]
    manager.export_current(online, btc)
    request = load_request(manager, request_id)
    original_tx = dict(online.pending["tx"])
    response = package_v2_response(
        request, signed_evm_payload(original_tx),
        expected_account=ADDRESS, allow_no_trusted_clock=True,
    )
    write_response(manager, request_id, response)

    restored, restored_btc, _ = fresh_sessions(rpc)
    restored.pending = None
    restored_btc.pending = None
    assert manager.restore(restored, restored_btc)
    status = manager.resume_response(restored, restored_btc)
    assert status["stage"] == "verified"
    assert status["state"] == "IMPORTED_VERIFIED"
    assert restored.pending["request_id"] == request_id
    assert restored.pending["tx"] == original_tx
    assert restored.pending["tx_hash"] == response["payload"]["transaction_hash"]
    assert restored.pending["tx"]["chainId"] == 11155111
    assert restored.pending["tx"]["nonce"] == original_tx["nonce"]
    assert restored.pending["tx"]["gas"] == original_tx["gas"]
    assert restored.pending["tx"]["to"] == original_tx["to"]
    assert restored.pending["tx"]["value"] == original_tx["value"]
    assert restored.pending["tx"].get("data", "0x") in ("", "0x")
    assert rpc.sent == []
    verify_v2_response(
        request, response, expected_account=ADDRESS, allow_no_trusted_clock=True
    )


def test_changed_signed_transaction_is_rejected_even_with_rehashed_v2_metadata(tmp_path):
    manager = CrossBootManager(tmp_path)
    online, btc, _ = fresh_sessions()
    prepared = online.prepare(RECIPIENT, "0.01")
    request_id = prepared["pending"]["request_id"]
    manager.export_current(online, btc)
    request = load_request(manager, request_id)
    response = package_v2_response(
        request, signed_evm_payload(online.pending["tx"]),
        expected_account=ADDRESS, allow_no_trusted_clock=True,
    )
    response["payload"] = signed_evm_payload(
        online.pending["tx"], recipient="0x1111111111111111111111111111111111111111"
    )
    response["signedResultDigest"] = hashlib.sha256(
        canonical(response["payload"])
    ).hexdigest()
    unsigned_response = {k: v for k, v in response.items() if k != "sha256"}
    response["sha256"] = hashlib.sha256(canonical(unsigned_response)).hexdigest()
    write_response(manager, request_id, response)

    restored, restored_btc, _ = fresh_sessions()
    restored.pending = None
    restored_btc.pending = None
    manager.restore(restored, restored_btc)
    with pytest.raises(ValueError, match="does not match|differs|mismatch"):
        manager.resume_response(restored, restored_btc)
    assert PendingRequestStore(manager.state_root).get(request_id).state == "EXPORTED"


def test_btc_psbt_v2_roundtrip_survives_restart(tmp_path):
    manager = CrossBootManager(tmp_path)
    evm, _unused, _ = fresh_sessions()
    btc_api = FakeBtcEsplora()
    btc = BitcoinCompanion(btc_api)
    btc.import_wallet(WATCH)
    prepared = btc.prepare(BTC_TARGET, "0.0005")
    request_id = prepared["pending"]["request_id"]
    original_pending = btc.pending_view()
    manager.export_current(evm, btc)
    request = load_request(manager, request_id)
    checked = verify_v2_request(
        request,
        expected_account=WATCH["bitcoin"]["master_fingerprint"],
        allow_no_trusted_clock=True,
    )
    assert checked["intent"]["amount"] == 50_000

    signed = sign_btc_psbt(ROOT, request["payload"], BTC_TARGET, 50_000,
                           checked["intent"]["fee"], 0)
    response = package_v2_response(
        request, signed,
        expected_account=WATCH["bitcoin"]["master_fingerprint"],
        allow_no_trusted_clock=True,
    )
    write_response(manager, request_id, response)

    restored_evm, _discard, _ = fresh_sessions()
    restored_btc = BitcoinCompanion(FakeBtcEsplora())
    restored_btc.import_wallet(WATCH)
    restored_evm.pending = None
    restored_btc.pending = None
    assert manager.restore(restored_evm, restored_btc)
    status = manager.resume_response(restored_evm, restored_btc)
    assert status["asset"] == "bitcoin-testnet"
    assert status["stage"] == "verified"
    assert restored_btc.pending["recipient"] == BTC_TARGET
    assert restored_btc.pending["amount_sats"] == 50_000
    assert restored_btc.pending["fee_sats"] == original_pending["fee_sats"]
    assert restored_btc.pending["fee_rate"] == original_pending["fee_rate"] == 2
    assert restored_btc.pending["change_sats"] == original_pending["change_sats"]
    assert restored_btc.pending["change_index"] == original_pending["change_index"] == 0
    assert restored_btc.pending["change_address"] == original_pending["change_address"]
    assert restored_btc.pending["inputs"] == original_pending["inputs"] == [{
        "txid": btc_api.txid, "vout": 0, "value": 150_000, "address": BTC_RECEIVE,
    }]
    assert restored_btc.pending["outputs"] == original_pending["outputs"]
    assert len(restored_btc.pending["outputs"]) == 2
    assert {item["address"] for item in restored_btc.pending["outputs"]} == {
        BTC_TARGET, restored_btc._address(1, 0),
    }
    assert {item["value"] for item in restored_btc.pending["outputs"]} == {
        50_000, original_pending["change_sats"],
    }
    finalized = transaction.Transaction.parse(bytes.fromhex(signed["finalized_tx_hex"]))
    assert restored_btc.pending["txid"] == finalized.txid().hex()


def _http(server, token, method, path, body=None):
    port = server.server_port
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
    code = response.status
    conn.close()
    return code, data


def _run_server(rpc, root):
    manager = CrossBootManager.auto(root)
    server, session, token = create_server(rpc, 0, NoNetworkEsplora(), manager)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    return manager, server, session, token, worker


def _stop(server, worker):
    server.shutdown()
    server.server_close()
    worker.join(5)


def test_http_cancel_records_failed_and_removes_active_exchange(tmp_path):
    rpc = FakeRpc()
    manager, server, _session, token, worker = _run_server(rpc, tmp_path)
    try:
        code, imported = _http(server, token, "POST", "/api/import",
                               {"raw": canonical(WATCH).decode()})
        assert code == 200 and imported["loaded"]
        code, prepared = _http(server, token, "POST", "/api/prepare", {
            "recipient": RECIPIENT, "amount_eth": "0.01", "max_fee_gwei": ""
        })
        assert code == 200
        request_id = prepared["pending"]["request_id"]
        code, exported = _http(server, token, "POST", "/api/crossboot/export", {})
        assert code == 200 and exported["state"] == "EXPORTED"
        request_file = manager.exchange / f"request-{request_id}.json"
        assert request_file.exists()

        code, cancelled = _http(server, token, "POST", "/api/cancel", {})
        assert code == 200 and cancelled["cancelled"]
        assert not request_file.exists()
        assert PendingRequestStore(manager.state_root).get(request_id).state == "FAILED"
    finally:
        _stop(server, worker)


def test_restart_auto_imports_verified_response_and_never_double_broadcasts(tmp_path):
    rpc = FakeRpc()
    manager, server, session, token, worker = _run_server(rpc, tmp_path)
    code, _ = _http(server, token, "POST", "/api/import",
                    {"raw": canonical(WATCH).decode()})
    assert code == 200
    code, prepared = _http(server, token, "POST", "/api/prepare", {
        "recipient": RECIPIENT, "amount_eth": "0.01", "max_fee_gwei": ""
    })
    assert code == 200
    request_id = prepared["pending"]["request_id"]
    assert _http(server, token, "POST", "/api/crossboot/export", {})[0] == 200
    request = load_request(manager, request_id)
    response = package_v2_response(
        request, signed_evm_payload(session.pending["tx"]),
        expected_account=ADDRESS, allow_no_trusted_clock=True,
    )
    write_response(manager, request_id, response)
    _stop(server, worker)

    manager2, server2, session2, token2, worker2 = _run_server(rpc, tmp_path)
    try:
        assert session2.pending["stage"] == "verified"
        assert rpc.sent == []
        code, result = _http(server2, token2, "POST", "/api/broadcast", {})
        assert code == 200 and result["stage"] == "broadcasted"
        assert len(rpc.sent) == 1
        assert PendingRequestStore(manager2.state_root).get(request_id).state == "BROADCASTED"
    finally:
        _stop(server2, worker2)

    _manager3, server3, session3, token3, worker3 = _run_server(rpc, tmp_path)
    try:
        assert session3.pending is None
        code, _ = _http(server3, token3, "POST", "/api/broadcast", {})
        assert code == 400
        assert len(rpc.sent) == 1
    finally:
        _stop(server3, worker3)


def test_unknown_broadcast_recovers_status_only_after_restart(tmp_path):
    rpc = FakeRpc(fail_send=True)
    manager, server, session, token, worker = _run_server(rpc, tmp_path)
    _http(server, token, "POST", "/api/import", {"raw": canonical(WATCH).decode()})
    _, prepared = _http(server, token, "POST", "/api/prepare", {
        "recipient": RECIPIENT, "amount_eth": "0.01", "max_fee_gwei": ""
    })
    request_id = prepared["pending"]["request_id"]
    _http(server, token, "POST", "/api/crossboot/export", {})
    request = load_request(manager, request_id)
    response = package_v2_response(
        request, signed_evm_payload(session.pending["tx"]),
        expected_account=ADDRESS, allow_no_trusted_clock=True,
    )
    write_response(manager, request_id, response)
    _stop(server, worker)

    manager2, server2, session2, token2, worker2 = _run_server(rpc, tmp_path)
    try:
        assert session2.pending["stage"] == "verified"
        code, _ = _http(server2, token2, "POST", "/api/broadcast", {})
        assert code == 400
        assert session2.pending["stage"] == "broadcast_unknown"
        snap = PendingRequestStore(manager2.state_root).get(request_id)
        assert snap.state == "BROADCAST_REQUESTED"
        assert snap.metadata["txid"] == session2.pending["tx_hash"]
    finally:
        _stop(server2, worker2)

    rpc.fail_send = False
    manager3, server3, session3, token3, worker3 = _run_server(rpc, tmp_path)
    try:
        assert session3.pending["stage"] == "broadcast_unknown"
        code, _ = _http(server3, token3, "POST", "/api/broadcast", {})
        assert code == 400
        assert rpc.sent == []
        code, reconciled = _http(server3, token3, "POST", "/api/crossboot/reconcile", {})
        assert code == 400
        assert "advisory only" in reconciled["error"]
        assert session3.pending["stage"] == "broadcast_unknown"
        assert rpc.sent == []
        assert PendingRequestStore(manager3.state_root).get(request_id).state == "BROADCAST_REQUESTED"
        assert manager3._request_path(request_id).is_file()
        assert manager3._response_path(request_id).is_file()
    finally:
        _stop(server3, worker3)


def _prepared_imported_evm(tmp_path):
    manager = CrossBootManager(tmp_path)
    online, btc, _ = fresh_sessions()
    prepared = online.prepare(RECIPIENT, "0.01")
    request_id = prepared["pending"]["request_id"]
    manager.export_current(online, btc)
    request = load_request(manager, request_id)
    response = package_v2_response(
        request, signed_evm_payload(online.pending["tx"]),
        expected_account=ADDRESS, allow_no_trusted_clock=True,
    )
    write_response(manager, request_id, response)
    manager.resume_response(online, btc)
    return manager, online, btc, request_id


def _delete_online_journal(manager):
    for path in manager.state_root.glob("*"):
        if path.is_file():
            path.unlink()


def test_deleted_online_journal_after_imported_verified_fails_closed(tmp_path):
    manager, online, btc, _request_id = _prepared_imported_evm(tmp_path)
    _delete_online_journal(manager)
    restored, restored_btc, _ = fresh_sessions()
    restored.pending = None
    restored_btc.pending = None
    with pytest.raises(ValueError, match="authoritative online journal missing|fails closed"):
        CrossBootManager(tmp_path).restore(restored, restored_btc)


def test_deleted_online_journal_after_broadcast_requested_fails_closed(tmp_path):
    manager, online, btc, _request_id = _prepared_imported_evm(tmp_path)
    txid = online.pending["tx_hash"]
    manager.mark_broadcast_requested(online, btc, txid)
    online.pending["stage"] = "broadcast_unknown"
    _delete_online_journal(manager)
    restored, restored_btc, _ = fresh_sessions()
    restored.pending = None
    restored_btc.pending = None
    with pytest.raises(ValueError, match="authoritative online journal missing|fails closed"):
        CrossBootManager(tmp_path).restore(restored, restored_btc)


def test_deleted_broadcasted_state_with_restored_old_exchange_fails_closed(tmp_path):
    manager, online, btc, request_id = _prepared_imported_evm(tmp_path)
    request_bytes = manager._request_path(request_id).read_bytes()
    response_bytes = manager._response_path(request_id).read_bytes()
    txid = online.pending["tx_hash"]
    manager.mark_broadcast_requested(online, btc, txid)
    manager.mark_broadcasted(online, btc, txid)
    _delete_online_journal(manager)
    manager.exchange.mkdir(parents=True, exist_ok=True)
    manager._request_path(request_id).write_bytes(request_bytes)
    manager._response_path(request_id).write_bytes(response_bytes)
    restored, restored_btc, _ = fresh_sessions()
    restored.pending = None
    restored_btc.pending = None
    with pytest.raises(ValueError, match="authoritative online journal missing|fails closed"):
        CrossBootManager(tmp_path).restore(restored, restored_btc)


def test_public_v2_codec_preserves_merged_evm_nonce_bound():
    tx = {
        "type": 2, "chainId": 11155111, "nonce": 1 << 53,
        "to": RECIPIENT, "value": 1, "gas": 21000,
        "maxFeePerGas": 2_000_000_000, "maxPriorityFeePerGas": 1_000_000_000,
    }
    with pytest.raises(ValueError, match="nonce"):
        _package_request(
            "evm-request", tx, request_id="ab" * 16, account=ADDRESS,
            recipient=RECIPIENT, amount=1,
        )


def test_windows_label_only_autodiscovery_is_disabled_until_layout_contract(monkeypatch):
    import usb_cold_wallet.companion_crossboot as module
    monkeypatch.setattr(module.os, "name", "nt")
    with pytest.raises(ValueError, match="validated GPT/layout identity"):
        discover_windows_exchange_root()
