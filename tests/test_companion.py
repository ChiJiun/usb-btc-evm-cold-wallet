"""Online Companion tests: PUBLIC compromised BIP39 vector only; no real funds/RPC."""
import copy
import hashlib
import http.client
import json
import threading
from urllib.parse import urlsplit

import pytest
from eth_account import Account

from usb_cold_wallet.companion_core import (
    CompanionSession, JsonRpc, canonical, pack_envelope, parse_watch_only, decode_json,
    checked_address, CHAIN_ID,
)
from usb_cold_wallet.companion_web import create_server
from usb_cold_wallet.keys import root_from_mnemonic, watch_only, evm_account

PUBLIC_TEST_MNEMONIC = "abandon " * 11 + "about"  # publicly known and unusable for real funds
TEST_ROOT = root_from_mnemonic(PUBLIC_TEST_MNEMONIC)
PUBLIC = watch_only(TEST_ROOT, count=2)
ADDRESS = PUBLIC["evm"]["address"]
TO = "0x000000000000000000000000000000000000dEaD"


class FakeRpc:
    display_endpoint = "https://mock-sepolia.test"

    def __init__(self):
        self.balance = 5 * 10**18
        self.nonce = 7
        self.chain_ok = True
        self.receipt = None
        self.found = True
        self.timeout_on_send = False
        self.fake_hash = False
        self.sent = []

    def assert_sepolia(self):
        if not self.chain_ok:
            raise ValueError("RPC chain mismatch")

    def account_state(self, address):
        self.assert_sepolia()
        assert address == ADDRESS
        return self.balance, self.nonce

    def fee_quote(self):
        return 2_000_000_000, 1_000_000_000

    def call(self, method, params):
        self.assert_sepolia()
        if method == "eth_getTransactionCount":
            return hex(self.nonce)
        if method == "eth_sendRawTransaction":
            self.sent.append(params[0])
            if self.timeout_on_send:
                raise ValueError("network timeout")
            return "0x" + "0" * 64 if self.fake_hash else "0x" + __import__("eth_utils").keccak(hexstr=params[0]).hex()
        if method == "eth_getTransactionReceipt":
            return self.receipt
        if method == "eth_getTransactionByHash":
            return {"hash": params[0]} if self.found else None
        raise AssertionError(f"Unexpected RPC {method}")


def session_with_wallet():
    rpc = FakeRpc()
    app = CompanionSession(rpc)
    app.import_wallet(canonical(PUBLIC))
    return app, rpc


def sign_result(tx=None, account=None):
    if tx is None:
        raise AssertionError("Supply the requested transaction")
    account = account or evm_account(TEST_ROOT)
    signed = Account.sign_transaction(tx, account.key)
    return {
        "chain_id": CHAIN_ID,
        "from": account.address,
        "to": tx["to"],
        "value_wei": tx["value"],
        "transaction_hash": signed.hash.hex(),
        "signed_raw_transaction": "0x" + signed.raw_transaction.hex(),
    }


def prepare_session():
    app, rpc = session_with_wallet()
    req = app.prepare(TO, "0.01")
    return app, rpc, req


def test_imports_bare_and_issue5_exchange_watch_only():
    assert parse_watch_only(canonical(PUBLIC))["evm"]["address"] == ADDRESS
    exported = pack_envelope("watch-only", PUBLIC)
    assert parse_watch_only(canonical(exported))["bitcoin"]["account_tpub"].startswith("tpub")
    assert pack_envelope("evm-request", {"chainId": CHAIN_ID})["network"] == "sepolia"


def test_watch_only_rejects_secret_malformed_btc_wrong_network_and_duplicate():
    with pytest.raises(ValueError, match="Duplicate"):
        parse_watch_only(b'{"bitcoin":1,"bitcoin":2,"evm":3}')
    compromised = copy.deepcopy(PUBLIC)
    compromised["evm"]["seed"] = "never import secrets"
    with pytest.raises(ValueError, match="Secret"):
        parse_watch_only(canonical(compromised))
    compromised = copy.deepcopy(PUBLIC)
    compromised["bitcoin"]["receive_addresses"][0] = compromised["bitcoin"]["receive_addresses"][1]
    with pytest.raises(ValueError, match="do not match"):
        parse_watch_only(canonical(compromised))
    compromised = copy.deepcopy(PUBLIC)
    compromised["evm"]["chain_id"] = 1
    with pytest.raises(ValueError, match="Unsupported"):
        parse_watch_only(canonical(compromised))
    enveloped = pack_envelope("watch-only", copy.deepcopy(PUBLIC))
    enveloped["payload"]["evm"]["address"] = TO
    with pytest.raises(ValueError, match="integrity"):
        parse_watch_only(canonical(enveloped))
    with pytest.raises(ValueError):
        decode_json(b"x" * 210000)


@pytest.mark.parametrize("addr", ["0x1", "0xZ" + "0" * 39, "0x000000000000000000000000000000000000dEAD"])
def test_rejects_invalid_ethereum_address(addr):
    with pytest.raises(ValueError):
        checked_address(addr)


def test_prepare_review_session_binding_and_replay_control():
    app, rpc, req = prepare_session()
    tx = req["pending"]["tx"]
    assert tx["nonce"] == 7
    assert tx["chainId"] == CHAIN_ID
    assert tx["gas"] == 21000
    assert tx["maxFeePerGas"] == 2_000_000_000
    assert req["pending"]["digest"] == hashlib.sha256(canonical(tx)).hexdigest()
    assert req["envelope"] == app.request_envelope()
    assert req["envelope"]["payload"] == tx
    assert app.overview()["balance_wei"] == str(rpc.balance)
    assert app.public_view()["btc_addresses"] == PUBLIC["bitcoin"]["receive_addresses"]
    with pytest.raises(ValueError, match="previous request"):
        app.prepare(TO, "0.02")
    with pytest.raises(ValueError, match="Cancel"):
        app.import_wallet(canonical(PUBLIC))
    app.cancel()
    with pytest.raises(ValueError, match="No pending"):
        app.request_envelope()
    assert app.prepare(TO, "0.01")["pending"]["request_id"] != req["pending"]["request_id"]


@pytest.mark.parametrize("amount,fee", [
    ("0", ""), ("-0.5", ""), ("0.0000000000000000001", ""), ("1e3", ""),
    ("0.1", "1001"), ("0.1", "0.1"), ("0.1", "5e2")
])
def test_rejects_invalid_amount_and_fees(amount, fee):
    app, _ = session_with_wallet()
    with pytest.raises(ValueError):
        app.prepare(TO, amount, fee)


def test_insufficient_balance_and_wrong_rpc_chain():
    app, rpc = session_with_wallet()
    rpc.balance = 1
    with pytest.raises(ValueError, match="Insufficient"):
        app.prepare(TO, "0.01")
    rpc.balance = 5 * 10**18
    rpc.chain_ok = False
    with pytest.raises(ValueError, match="chain"):
        app.prepare(TO, "0.01")


def test_accept_signed_raw_transaction_verify_broadcast_and_status():
    app, rpc, req = prepare_session()
    signed = sign_result(req["pending"]["tx"])
    response = pack_envelope("evm-signed", signed)
    verified = app.accept_signed(canonical(response))
    assert verified["stage"] == "verified"
    assert verified["tx_hash"] == "0x" + signed["transaction_hash"].removeprefix("0x")
    assert "signed" not in json.dumps(verified)
    with pytest.raises(ValueError, match="No unsigned"):
        app.accept_signed(canonical(response))
    submitted = app.broadcast()
    assert submitted["stage"] == "broadcasted" and len(rpc.sent) == 1
    with pytest.raises(ValueError, match="cannot repeat"):
        app.broadcast()
    assert app.check_status()["result"] == "pending"
    rpc.receipt = {"transactionHash": submitted["tx_hash"], "blockNumber": "0x20", "status": "0x1"}
    assert app.check_status()["result"] == "confirmed"
    rpc.receipt["status"] = "0x0"
    assert app.check_status()["result"] == "reverted"


@pytest.mark.parametrize("mutation", [
    lambda tx: tx.update(to="0x0000000000000000000000000000000000000001"),
    lambda tx: tx.update(chainId=1),
    lambda tx: tx.update(nonce=tx["nonce"]+1),
    lambda tx: tx.update(value=tx["value"]+1),
    lambda tx: tx.update(maxFeePerGas=tx["maxFeePerGas"]+1),
    lambda tx: tx.update(maxPriorityFeePerGas=tx["maxPriorityFeePerGas"]+1),
    lambda tx: tx.update(gas=22000),
    lambda tx: tx.update(data="0x1234"),
])
def test_signed_raw_payload_changes_are_rejected(mutation):
    app, rpc, req = prepare_session()
    tx = dict(req["pending"]["tx"])
    mutation(tx)
    raw = sign_result(tx)
    with pytest.raises(ValueError, match="differs"):
        app.accept_signed(canonical(raw))
    assert app.pending["stage"] == "prepared"
    assert not rpc.sent


def test_other_signer_tampered_metadata_wrong_hash_and_replay():
    app, _, req = prepare_session()
    tx = req["pending"]["tx"]
    different = Account.from_key(bytes.fromhex("11"*32))
    with pytest.raises(ValueError, match="differs"):
        app.accept_signed(canonical(sign_result(tx, different)))
    signed = sign_result(tx)
    signed["transaction_hash"] = "0x" + "f"*64
    with pytest.raises(ValueError, match="mismatch"):
        app.accept_signed(canonical(signed))
    signed = sign_result(tx)
    signed["from"] = TO
    with pytest.raises(ValueError, match="mismatch"):
        app.accept_signed(canonical(signed))
    signed = sign_result(tx)
    signed["value_wei"] += 1
    with pytest.raises(ValueError, match="mismatch"):
        app.accept_signed(canonical(signed))
    # Old signed transaction cannot match a newly prepared request.
    original = sign_result(tx)
    app.cancel()
    app.prepare(TO, "0.02")
    with pytest.raises(ValueError, match="differs"):
        app.accept_signed(canonical(original))


def test_rpc_receipt_disappearance_warns_of_possible_reorg():
    app, rpc, req = prepare_session()
    app.accept_signed(canonical(sign_result(req["pending"]["tx"])))
    result = app.broadcast()
    rpc.receipt = {
        "transactionHash": result["tx_hash"], "status": "0x1",
        "blockNumber": "0x20", "blockHash": "0x" + "1" * 64,
    }
    assert app.check_status()["result"] == "confirmed"
    rpc.receipt = None
    assert app.check_status()["result"] == "reorg_suspected"
    assert app.check_status()["reorg_warning"] is True
    rpc.receipt = {
        "transactionHash": result["tx_hash"], "status": "0x1",
        "blockNumber": "0x21", "blockHash": "0x" + "2" * 64,
    }
    assert app.check_status()["result"] == "confirmed"
    assert app.check_status()["reorg_warning"]


def test_rejects_invalid_signed_raw_and_envelope():
    app, rpc, req = prepare_session()
    signed = sign_result(req["pending"]["tx"])
    broken = dict(signed, signed_raw_transaction="0xabc")
    with pytest.raises(ValueError):
        app.accept_signed(canonical(broken))
    broken = pack_envelope("evm-signed", signed)
    broken["network"] = "ethereum-mainnet"
    with pytest.raises(ValueError, match="network"):
        app.accept_signed(canonical(broken))
    assert not rpc.sent


def test_stale_nonce_blocked_before_broadcast_and_rpc_timeout_no_auto_retry():
    app, rpc, req = prepare_session()
    app.accept_signed(canonical(sign_result(req["pending"]["tx"])))
    rpc.nonce += 1
    with pytest.raises(ValueError, match="Stale nonce"):
        app.broadcast()
    assert not rpc.sent and app.pending["stage"] == "verified"
    rpc.nonce -= 1
    rpc.timeout_on_send = True
    with pytest.raises(ValueError, match="unknown"):
        app.broadcast()
    assert app.pending["stage"] == "broadcast_unknown"
    assert len(rpc.sent) == 1
    with pytest.raises(ValueError, match="cannot repeat"):
        app.broadcast()
    rpc.found = False
    assert app.check_status()["result"] == "not_found"


def test_rpc_wrong_hash_not_auto_rebroadcast():
    app, rpc, req = prepare_session()
    app.accept_signed(canonical(sign_result(req["pending"]["tx"])))
    rpc.fake_hash = True
    with pytest.raises(ValueError, match="different transaction hash"):
        app.broadcast()
    assert len(rpc.sent) == 1 and app.pending["stage"] == "broadcast_unknown"


def test_rpc_url_validation_and_no_credential_echo():
    for url in ["http://evil.example", "ftp://localhost", "https://user:pass@foo.test",
                "http://localhost#secret", "not-a-url"]:
        with pytest.raises(ValueError):
            JsonRpc(url)
    assert JsonRpc("https://example.org/path?token=not-logged").display_endpoint == "https://example.org"
    assert JsonRpc("http://127.0.0.1:8545").display_endpoint == "http://127.0.0.1:8545"


def test_json_rpc_strict_id_response_size_and_explicit_errors(monkeypatch):
    from io import BytesIO
    import usb_cold_wallet.companion_core as core

    class Response:
        def __init__(self, raw):
            self.data = BytesIO(raw)
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, n): return self.data.read(n)

    values = []
    def urlopen(request, timeout):
        payload = json.loads(request.data)
        response = values.pop(0)
        response["id"] = payload["id"] if response.get("id") == "same" else response.get("id")
        return Response(canonical(response))
    monkeypatch.setattr(core, "urlopen", urlopen)
    client = JsonRpc("https://localhost:8545")
    values.extend([{"jsonrpc": "2.0", "id": "same", "result": CHAIN_ID and hex(CHAIN_ID)}])
    client.assert_sepolia()
    values.extend([{"jsonrpc": "2.0", "id": "same", "result": "0x1"}])
    with pytest.raises(ValueError, match="chain mismatch"):
        client.assert_sepolia()
    values.extend([{"jsonrpc": "2.0", "id": 0, "result": "0xaa36a7"}])
    with pytest.raises(ValueError, match="ID mismatch"):
        client.assert_sepolia()


def test_rpc_and_local_http_reject_nonfinite_json_numbers(monkeypatch):
    from io import BytesIO
    import usb_cold_wallet.companion_core as core

    class Reply:
        def __init__(self, payload):
            self.reader = BytesIO(payload)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def read(self, length):
            return self.reader.read(length)

    def poisoned_rpc(request, timeout):
        request_id = json.loads(request.data)["id"]
        return Reply(('{"jsonrpc":"2.0","id":' + str(request_id) +
                      ',"result":{"balance":NaN}}').encode("ascii"))

    monkeypatch.setattr(core, "urlopen", poisoned_rpc)
    with pytest.raises(ValueError, match="Non-finite"):
        JsonRpc("https://example.org").call("eth_getBalance", [])

    server, app, token = create_server(FakeRpc(), 0)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        port = server.server_port
        for literal in (b'{"raw":NaN}', b'{"raw":Infinity}', b'{"raw":-Infinity}'):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
            conn.request("POST", "/api/import", body=literal, headers={
                "Host": f"127.0.0.1:{port}",
                "Origin": f"http://127.0.0.1:{port}",
                "X-Companion-Token": token,
                "Content-Type": "application/json",
            })
            result = conn.getresponse()
            assert result.status == 400
            assert b"Non-finite" in result.read()
            conn.close()
        assert app.wallet is None
    finally:
        server.shutdown()
        server.server_close()
        worker.join(5)


def test_loopback_http_rejects_cross_origin_and_serves_ui_without_remote_resources():
    rpc=FakeRpc()
    server, app, token = create_server(rpc, 0)
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    port=server.server_port

    def call(method, path, body=None, *, host=None, origin=None, token_value=None):
        connection=http.client.HTTPConnection("127.0.0.1",port,timeout=4)
        headers={"Host":host or f"127.0.0.1:{port}"}
        if token_value is not None:
            headers["X-Companion-Token"]=token_value
        if origin is not None:
            headers["Origin"]=origin
        if body is not None:
            headers["Content-Type"]="application/json"
        connection.request(method,path,body=None if body is None else canonical(body),headers=headers)
        response=connection.getresponse()
        status=response.status
        raw=response.read()
        headers_out=dict(response.getheaders())
        connection.close()
        return status,raw,headers_out

    try:
        code, html,_=call("GET","/")
        assert code==200 and b"Watch-only Companion" in html and token.encode() in html
        code, js, headers=call("GET","/companion.js")
        assert code==200 and b"private key" not in js.lower()
        assert "default-src 'none'" in headers["Content-Security-Policy"]
        code,_,_=call("POST","/api/import",{"raw":canonical(PUBLIC).decode()},token_value=token)
        assert code==403
        code,_,_=call("POST","/api/import",{"raw":canonical(PUBLIC).decode()},
                      origin="https://evil.example",token_value=token)
        assert code==403
        code,_,_=call("POST","/api/import",{"raw":canonical(PUBLIC).decode()},
                      host="evil.example",origin=f"http://127.0.0.1:{port}",token_value=token)
        assert code==403
        code,body,_=call("POST","/api/import",{"raw":canonical(PUBLIC).decode()},
                         origin=f"http://127.0.0.1:{port}",token_value=token)
        assert code==200 and json.loads(body)["loaded"]
        code,body,_=call("POST","/api/prepare",
                         {"recipient":TO,"amount_eth":"0.01","max_fee_gwei":""},
                         origin=f"http://127.0.0.1:{port}",token_value=token)
        assert code==200 and json.loads(body)["pending"]["stage"]=="prepared"
        code,body,_=call("GET","/api/request",token_value=token)
        assert code==200 and json.loads(body)["kind"]=="evm-request"
        signed=sign_result(app.pending["tx"])
        code,body,_=call("POST","/api/accept",{"raw":canonical(signed).decode()},
                         origin=f"http://127.0.0.1:{port}",token_value=token)
        assert code==200 and json.loads(body)["stage"]=="verified"
        code,body,_=call("POST","/api/broadcast",{},
                         origin=f"http://127.0.0.1:{port}",token_value=token)
        assert code==200 and json.loads(body)["stage"]=="broadcasted"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
