"""Read-only Companion recovery must never authorize a signature or broadcast."""
import http.client
import json
import threading

import pytest

from usb_cold_wallet.companion_web import create_server, lookup_public_transaction
from usb_cold_wallet.companion_core import CompanionSession
from usb_cold_wallet.companion_btc import BitcoinCompanion


EVM_TX = "0x" + "1" * 64
BTC_TX = "2" * 64


class Rpc:
    display_endpoint = "https://test-sepolia.invalid"

    def __init__(self):
        self.receipt = None
        self.chain_ok = True
        self.found = True
        self.sent = 0
        self.timeout = False

    def assert_sepolia(self):
        if not self.chain_ok:
            raise ValueError("Wrong RPC chain")

    def call(self, method, args):
        if self.timeout:
            raise ValueError("RPC timeout")
        self.assert_sepolia()
        assert method in ("eth_getTransactionReceipt", "eth_getTransactionByHash")
        if method == "eth_getTransactionReceipt":
            return self.receipt
        return {"hash": args[0]} if self.found else None


class Esplora:
    display_endpoint = "https://test-bitcoin.invalid"

    def __init__(self):
        self.response = {"confirmed": False}
        self.sent = 0

    def status(self, txid):
        assert txid == BTC_TX
        return self.response


def pair():
    rpc, esplora = Rpc(), Esplora()
    return CompanionSession(rpc), BitcoinCompanion(esplora), rpc, esplora


def test_read_only_lookup_status_and_recovery_never_broadcast():
    eth, btc, rpc, explorer = pair()
    result = lookup_public_transaction(eth, btc, "sepolia", EVM_TX)
    assert result == {"asset": "sepolia", "txid": EVM_TX, "result": "pending", "untrusted_rpc": True}
    rpc.found = False
    assert lookup_public_transaction(eth, btc, "sepolia", EVM_TX)["result"] == "not_found"
    rpc.receipt = {"transactionHash": EVM_TX, "status": "0x1"}
    assert lookup_public_transaction(eth, btc, "sepolia", EVM_TX)["result"] == "confirmed"
    rpc.receipt["status"] = "0x0"
    assert lookup_public_transaction(eth, btc, "sepolia", EVM_TX)["result"] == "reverted"
    assert lookup_public_transaction(eth, btc, "bitcoin-testnet", BTC_TX)["result"] == "pending"
    explorer.response = {"confirmed": True}
    assert lookup_public_transaction(eth, btc, "bitcoin-testnet", BTC_TX)["result"] == "confirmed"
    explorer.response = None
    assert lookup_public_transaction(eth, btc, "bitcoin-testnet", BTC_TX)["result"] == "not_found"
    assert eth.pending is None and btc.pending is None
    assert rpc.sent == explorer.sent == 0


@pytest.mark.parametrize("asset,hash_value", [
    ("ethereum-mainnet", EVM_TX), ("sepolia", BTC_TX),
    ("bitcoin-testnet", EVM_TX), ("bitcoin-testnet", "a" * 65),
    ("sepolia", "0x" + "z" * 64), ("sepolia", "0x1"),
    (None, EVM_TX), ("bitcoin-testnet", None),
])
def test_lookup_rejects_unknown_network_and_invalid_transaction_hash(asset, hash_value):
    eth, btc, rpc, explorer = pair()
    with pytest.raises(ValueError):
        lookup_public_transaction(eth, btc, asset, hash_value)
    assert rpc.sent == explorer.sent == 0


def test_lookup_fails_closed_on_untrusted_rpc_and_timeout():
    eth, btc, rpc, explorer = pair()
    rpc.chain_ok = False
    with pytest.raises(ValueError, match="chain"):
        lookup_public_transaction(eth, btc, "sepolia", EVM_TX)
    rpc.chain_ok = True
    rpc.receipt = {"transactionHash": "0x" + "e"*64, "status": "0x1"}
    with pytest.raises(ValueError, match="mismatched"):
        lookup_public_transaction(eth, btc, "sepolia", EVM_TX)
    rpc.receipt = {"transactionHash": EVM_TX, "status": "0x2"}
    with pytest.raises(ValueError, match="status"):
        lookup_public_transaction(eth, btc, "sepolia", EVM_TX)
    rpc.receipt = None
    rpc.timeout = True
    with pytest.raises(ValueError, match="timeout"):
        lookup_public_transaction(eth, btc, "sepolia", EVM_TX)
    explorer.response = {"confirmed": 1}
    with pytest.raises(ValueError, match="Invalid"):
        lookup_public_transaction(eth, btc, "bitcoin-testnet", BTC_TX)


def test_lookup_http_requires_loopback_token_origin_and_rejects_broadcast_overrides():
    rpc, explorer = Rpc(), Esplora()
    server, session, token = create_server(rpc, 0, esplora)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port

    def call(path, payload, *, authorized=True, origin=True):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {"Host": f"127.0.0.1:{port}", "Content-Type": "application/json"}
        if authorized:
            headers["X-Companion-Token"] = token
        if origin:
            headers["Origin"] = f"http://127.0.0.1:{port}"
        conn.request("POST", path, body=json.dumps(payload), headers=headers)
        response = conn.getresponse()
        code = response.status
        value = json.loads(response.read())
        conn.close()
        return code, value

    try:
        data = {"asset": "sepolia", "txid": EVM_TX}
        assert call("/api/lookup", data, authorized=False)[0] == 403
        assert call("/api/lookup", data, origin=False)[0] == 403
        assert call("/api/lookup", {**data, "private_key": "never"})[0] == 400
        assert call("/api/lookup", {**data, "asset": "ethereum-mainnet"})[0] == 400
        code, value = call("/api/lookup", data)
        assert code == 200 and value["result"] == "pending"
        assert call("/api/broadcast", {})[0] == 400
        assert call("/api/btc/broadcast", {})[0] == 400
        assert session.pending is None and rpc.sent == explorer.sent == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
