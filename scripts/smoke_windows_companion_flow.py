"""Exercise real frozen Windows EXE request/sign/explicit mock broadcast.

The deliberately compromised mnemonic exists ONLY in this external test harness;
the PyInstaller archive guard verifies that signer modules are absent in the EXE.
All RPC calls go to a local stub, never a real chain.
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from eth_account import Account
from eth_utils import keccak
from usb_cold_wallet.keys import root_from_mnemonic, watch_only, evm_account
from usb_cold_wallet.evm import decode_signed_eip1559
from usb_cold_wallet.exchange import verify as offline_verify

MNEMONIC = "abandon " * 11 + "about"
RECIPIENT = "0x000000000000000000000000000000000000dEaD"


class RpcStub(BaseHTTPRequestHandler):
    sent = []
    def log_message(self, *_args):
        pass

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        req = json.loads(self.rfile.read(n))
        method = req["method"]
        if method == "eth_chainId":
            result = hex(11155111)
        elif method == "eth_getBalance":
            result = hex(5 * 10**18)
        elif method == "eth_getTransactionCount":
            result = hex(7)
        elif method == "eth_getBlockByNumber":
            result = {"baseFeePerGas": hex(1_000_000_000)}
        elif method == "eth_maxPriorityFeePerGas":
            result = hex(1_000_000_000)
        elif method == "eth_sendRawTransaction":
            self.sent.append(req["params"][0])
            result = "0x" + keccak(hexstr=req["params"][0]).hex()
        else:
            raise AssertionError(f"Unexpected RPC call: {method}")
        body = json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def api(origin, path, token, data=None):
    headers = {"X-Companion-Token": token}
    if data is not None:
        headers["Origin"] = origin
        headers["Content-Type"] = "application/json"
        data = json.dumps(data).encode()
    with urlopen(Request(origin + path, data=data, headers=headers,
                         method="POST" if data is not None else "GET"), timeout=12) as response:
        return response.read()


def main():
    exe = Path(sys.argv[1]).resolve(strict=True)
    with ThreadingHTTPServer(("127.0.0.1", 0), RpcStub) as rpc:
        thread = threading.Thread(target=rpc.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        RpcStub.sent = []
        proc = subprocess.Popen(
            [str(exe), "--no-browser", "--port", str(port),
             "--rpc-url", f"http://127.0.0.1:{rpc.server_port}"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 80
            while True:
                if proc.poll() is not None:
                    raise AssertionError("Frozen EXE quit: " + proc.stderr.read(4096).decode(errors="replace"))
                try:
                    with urlopen(origin, timeout=2) as response:
                        markup = response.read().decode()
                    break
                except (URLError, TimeoutError):
                    if time.monotonic() > deadline:
                        raise AssertionError("Frozen EXE failed to launch")
                    time.sleep(0.5)
            token = re.search(r'<meta name="companion-token" content="([^"]+)"', markup).group(1)
            root = root_from_mnemonic(MNEMONIC)
            wallet = watch_only(root, count=2)
            result = json.loads(api(origin, "/api/import", token, {"raw": json.dumps(wallet)}))
            assert result["loaded"] is True, result
            overview = json.loads(api(origin, "/api/overview", token))
            assert int(overview["balance_wei"]) == 5 * 10**18, overview
            prepared = json.loads(api(origin, "/api/prepare", token, {
                "recipient": RECIPIENT, "amount_eth": "0.1", "max_fee_gwei": "",
            }))
            assert prepared["pending"]["stage"] == "prepared", prepared
            assert not RpcStub.sent, "Unexpected automatic broadcast during prepare"
            raw = api(origin, "/api/request-raw", token)
            envelope = json.loads(raw)
            tx = offline_verify(envelope, "evm-request")
            assert tx["value"] == 100_000_000_000_000_000
            assert b"100000000000000000" in raw, "Wei must be preserved as a JSON integer"
            assert not RpcStub.sent, "Unsigned download caused broadcast"
            account = evm_account(root)
            signed = Account.sign_transaction(tx, account.key)
            signed_raw = "0x" + signed.raw_transaction.hex()
            decoded = decode_signed_eip1559(signed_raw)
            payload = {
                "chain_id": 11155111, "from": account.address, "to": tx["to"],
                "value_wei": tx["value"],
                "max_fee_wei": tx["gas"] * tx["maxFeePerGas"],
                "max_total_wei": tx["value"] + tx["gas"] * tx["maxFeePerGas"],
                "decoded_transaction": decoded,
                "transaction_hash": decoded["transaction_hash"],
                "signed_raw_transaction": signed_raw,
            }
            # Signer tests run OUTSIDE the EXE; the frozen app only verifies.
            from usb_cold_wallet.exchange import package as offline_package
            response = offline_package("evm-signed", payload)
            accepted = json.loads(api(origin, "/api/accept", token, {"raw": json.dumps(response)}))
            assert accepted["stage"] == "verified", accepted
            assert not RpcStub.sent, "Signed import must not auto-broadcast"
            broadcast = json.loads(api(origin, "/api/broadcast", token, {}))
            assert broadcast["stage"] == "broadcasted", broadcast
            assert RpcStub.sent == [signed_raw], "Unexpected or repeated RPC submission"
            try:
                api(origin, "/api/broadcast", token, {})
            except HTTPError as err:
                assert err.code == 400
            else:
                raise AssertionError("Second broadcast unexpectedly succeeded")
            assert len(RpcStub.sent) == 1
            print("Frozen EXE: watch-only import, mock RPC, exact Wei, offline envelope, "
                  "signed import and explicit one-shot mock broadcast passed")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=12)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=12)
            rpc.shutdown()


if __name__ == "__main__":
    main()
