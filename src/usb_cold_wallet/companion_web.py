"""Loopback-only browser UI for the public-data Online Companion.

No wallet secret import, no remote web assets, no RPC input from browser.
"""
from __future__ import annotations

import argparse
import hmac
import html
import json
import re
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .companion_core import CompanionSession, JsonRpc, MAX_EXCHANGE_BYTES, _quantity
from .companion_btc import BitcoinCompanion, TestnetEsplora
from .companion_crossboot import CrossBootManager

STATIC = Path(__file__).parent / "companion_static"
POST_LIMIT = MAX_EXCHANGE_BYTES + 65_536
EVM_HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")
BTC_HASH = re.compile(r"[0-9a-fA-F]{64}\Z")


def lookup_public_transaction(session: CompanionSession, btc_session: BitcoinCompanion,
                              asset: str, txid: str) -> dict:
    """Read-only status check, not a recovery of authorization to broadcast."""
    if type(asset) is not str or type(txid) is not str:
        raise ValueError("Asset and transaction hash must be strings")
    if asset == "sepolia":
        if not EVM_HASH.fullmatch(txid):
            raise ValueError("Invalid Sepolia transaction hash")
        session.rpc.assert_sepolia()
        receipt = session.rpc.call("eth_getTransactionReceipt", [txid])
        if receipt is None:
            tx = session.rpc.call("eth_getTransactionByHash", [txid])
            if tx is not None and (not isinstance(tx, dict)
                    or not isinstance(tx.get("hash"), str)
                    or tx["hash"].lower() != txid.lower()):
                raise ValueError("RPC supplied mismatched transaction hash")
            result = "pending" if tx is not None else "not_found"
        else:
            if (not isinstance(receipt, dict)
                    or not isinstance(receipt.get("transactionHash"), str)
                    or receipt["transactionHash"].lower() != txid.lower()):
                raise ValueError("RPC supplied mismatched receipt")
            status = _quantity(receipt.get("status"), "receipt status")
            if status not in (0, 1):
                raise ValueError("Invalid receipt status")
            # Match the existing session status policy. A bare receipt status
            # without an inclusion height must not be presented as confirmed.
            _quantity(receipt.get("blockNumber"), "block number")
            block_hash = receipt.get("blockHash")
            if block_hash is not None and (not isinstance(block_hash, str)
                    or not EVM_HASH.fullmatch(block_hash)):
                raise ValueError("Invalid receipt block hash")
            result = "confirmed" if status == 1 else "reverted"
        return {"asset": asset, "txid": txid, "result": result, "untrusted_rpc": True}
    if asset == "bitcoin-testnet":
        if not BTC_HASH.fullmatch(txid):
            raise ValueError("Invalid Bitcoin testnet TXID")
        info = btc_session.api.status(txid.lower())
        if info is None:
            result = "not_found"
        elif not isinstance(info, dict) or type(info.get("confirmed")) is not bool:
            raise ValueError("Invalid Bitcoin testnet transaction response")
        else:
            # Esplora normally returns only a status object. If an identifier
            # is supplied, it must match the request; never trust a bare
            # confirmed flag without a valid inclusion block hash.
            supplied_txid = info.get("txid")
            if supplied_txid is not None and (not isinstance(supplied_txid, str)
                    or not BTC_HASH.fullmatch(supplied_txid)
                    or supplied_txid.lower() != txid.lower()):
                raise ValueError("Bitcoin explorer supplied mismatched transaction ID")
            if info["confirmed"]:
                block_hash = info.get("block_hash")
                if not isinstance(block_hash, str) or not BTC_HASH.fullmatch(block_hash):
                    raise ValueError("Confirmed BTC status missing block hash")
            result = "confirmed" if info["confirmed"] else "pending"
        return {"asset": asset, "txid": txid.lower(), "result": result, "untrusted_rpc": True}
    raise ValueError("Unsupported network; mainnet is disabled")


def handler_for(session: CompanionSession, btc_session: BitcoinCompanion, token: str,
                crossboot: CrossBootManager | None = None):
    class CompanionHandler(BaseHTTPRequestHandler):
        server_version = "USBCompanion/0.1"
        sys_version = ""

        def log_message(self, fmt, *args):
            # Never echo attacker-controlled request bodies, URLs or file names.
            return

        def _headers(self, mime: str, length: int, status: int = 200):
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'self'; style-src 'self'; "
                             "connect-src 'self'; img-src 'self'; form-action 'none'; "
                             "base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()

        def _send(self, raw: bytes, mime: str = "application/json; charset=utf-8", status=200):
            self._headers(mime, len(raw), status)
            self.wfile.write(raw)

        def _json(self, data, status=200):
            # UI-only integer representation: JavaScript Numbers cannot preserve
            # EVM 256-bit Wei. Keep exchange envelopes as original JSON integers.
            if self.path in ("/api/wallet", "/api/prepare", "/api/accept",
                             "/api/broadcast", "/api/status") and isinstance(data, dict):
                data = dict(data)
                if isinstance(data.get("pending"), dict):
                    pending = dict(data["pending"])
                    if isinstance(pending.get("tx"), dict):
                        pending["tx"] = {
                            key: str(val) if type(val) is int and abs(val) > (2 ** 53 - 1) else val
                            for key, val in pending["tx"].items()
                        }
                    data["pending"] = pending
                if isinstance(data.get("tx"), dict):
                    data["tx"] = {
                        key: str(val) if type(val) is int and abs(val) > (2 ** 53 - 1) else val
                        for key, val in data["tx"].items()
                    }
            self._send(json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8"), status=status)

        def _allowed_host(self):
            port = self.server.server_port
            return self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")

        def _same_origin(self):
            port = self.server.server_port
            return self.headers.get("Origin") in (
                f"http://127.0.0.1:{port}", f"http://localhost:{port}"
            )

        def _authorized(self):
            return hmac.compare_digest(self.headers.get("X-Companion-Token", ""), token)

        def do_GET(self):
            if not self._allowed_host():
                self._json({"error": "Host not allowed"}, 403)
                return
            if self.path == "/":
                html_text = (STATIC / "index.html").read_text(encoding="utf-8")
                html_text = html_text.replace("__COMPANION_TOKEN__", html.escape(token, quote=True))
                self._send(html_text.encode("utf-8"), "text/html; charset=utf-8")
            elif self.path in ("/companion.css", "/companion.js"):
                mime = "text/css; charset=utf-8" if self.path.endswith(".css") else "application/javascript; charset=utf-8"
                self._send((STATIC / self.path.lstrip("/")).read_bytes(), mime)
            elif self.path == "/api/wallet" and self._authorized():
                self._json(session.public_view())
            elif self.path == "/api/crossboot" and self._authorized():
                self._json(crossboot.status(session, btc_session) if crossboot else {
                    "available": False, "error": "Cross-boot manager disabled",
                    "can_export": False, "can_resume": False})
            elif self.path in ("/api/request-raw", "/api/request-legacy") and self._authorized():
                try:
                    raw = session.request_raw_json(legacy=self.path == "/api/request-legacy")
                    self._send(raw, "application/json; charset=utf-8")
                except ValueError as exc:
                    self._json({"error": str(exc)}, 400)
            elif self.path in ("/api/overview", "/api/request", "/api/btc/wallet",
                               "/api/btc/overview", "/api/btc/request",
                               "/api/btc/request-plain") and self._authorized():
                try:
                    values = {
                        "/api/overview": session.overview,
                        "/api/request": session.request_envelope,
                        "/api/btc/wallet": btc_session.public_view,
                        "/api/btc/overview": btc_session.overview,
                        "/api/btc/request": btc_session.request_envelope,
                        "/api/btc/request-plain": btc_session.request_psbt_base64,
                    }
                    self._json(values[self.path]())
                except ValueError as exc:
                    self._json({"error": str(exc)}, 400)
            else:
                self._json({"error": "Not found or not authorized"}, 404)

        def do_POST(self):
            if not self._allowed_host() or not self._same_origin() or not self._authorized():
                self._json({"error": "Request not authorized"}, 403)
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                self._json({"error": "JSON Content-Type required"}, 415)
                return
            try:
                size_str = self.headers.get("Content-Length")
                if not size_str or not size_str.isascii() or not size_str.isdecimal():
                    raise ValueError("Content-Length is required")
                length = int(size_str)
                if length > POST_LIMIT:
                    self._json({"error": "Request too large"}, 413)
                    return
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("Incomplete request")
                data = json.loads(raw.decode("utf-8"), object_pairs_hook=self._unique,
                                  parse_constant=lambda v: (_ for _ in ()).throw(ValueError("Non-finite HTTP JSON number")))
                if not isinstance(data, dict):
                    raise ValueError("Expected JSON object")
                if self.path == "/api/import":
                    if set(data) != {"raw"} or not isinstance(data["raw"], str):
                        raise ValueError("Expected public watch-only file")
                    with session.lock, btc_session.lock:
                        if btc_session.pending is not None:
                            raise ValueError("Cancel pending BTC transaction before replacing wallet")
                        result = session.import_wallet(data["raw"].encode("utf-8"))
                        btc_session.import_wallet(session.wallet)
                        if crossboot is not None and crossboot.available:
                            crossboot.remember_wallet(session, btc_session)
                elif self.path == "/api/prepare":
                    if set(data) != {"recipient", "amount_eth", "max_fee_gwei"}:
                        raise ValueError("Invalid transfer form fields")
                    result = session.prepare(**data)
                elif self.path == "/api/accept":
                    if set(data) != {"raw"} or not isinstance(data["raw"], str):
                        raise ValueError("Expected signed file")
                    result = session.accept_signed(data["raw"].encode("utf-8"))
                elif self.path == "/api/broadcast":
                    if data:
                        raise ValueError("Broadcast does not accept transaction overrides")
                    if crossboot is not None and crossboot.available:
                        if session.pending is None or session.pending.get("stage") != "verified":
                            raise ValueError("Broadcast requires a verified pending transaction")
                        crossboot.mark_broadcast_requested(
                            session, btc_session, session.pending["tx_hash"]
                        )
                    result = session.broadcast()
                    if crossboot is not None and crossboot.available and result.get("stage") == "broadcasted":
                        # A matching RPC acknowledgement is not authenticated
                        # chain evidence. Preserve the durable broadcast reservation.
                        session.pending["stage"] = "broadcast_unknown"
                        result = session.pending_view()
                elif self.path == "/api/status":
                    if data:
                        raise ValueError("Status query does not accept overrides")
                    result = session.check_status()
                elif self.path == "/api/cancel":
                    if data:
                        raise ValueError("Cancel does not accept overrides")
                    request_id = session.pending.get("request_id") if session.pending else None
                    if crossboot is not None and crossboot.available and request_id:
                        # Refuse to erase an ambiguous durable reservation BEFORE
                        # clearing the volatile session or any exchange evidence.
                        crossboot.cancel(session, btc_session, request_id)
                    result = session.cancel()
                elif self.path == "/api/crossboot/export":
                    if data or crossboot is None:
                        raise ValueError("Cross-boot export requires TX_TRANSFER and accepts no overrides")
                    result = crossboot.export_current(session, btc_session)
                elif self.path == "/api/crossboot/resume":
                    if data or crossboot is None:
                        raise ValueError("Cross-boot resume requires TX_TRANSFER and accepts no overrides")
                    result = crossboot.resume_response(session, btc_session)
                elif self.path == "/api/crossboot/reconcile":
                    if data or crossboot is None:
                        raise ValueError("Broadcast reconciliation accepts no transaction override")
                    reservation = crossboot.broadcast_reservation(session, btc_session)
                    observed = lookup_public_transaction(
                        session, btc_session, reservation["asset"], reservation["txid"]
                    )
                    result = crossboot.reconcile_broadcast(session, btc_session, observed)
                elif self.path == "/api/lookup":
                    if set(data) != {"asset", "txid"}:
                        raise ValueError("Only public asset and transaction hash allowed")
                    result = lookup_public_transaction(session, btc_session,
                                                       data["asset"], data["txid"])
                elif self.path == "/api/btc/prepare":
                    if set(data) != {"recipient", "amount_btc", "max_fee_sats", "fee_rate_sat_vb"}:
                        raise ValueError("Invalid BTC transfer form")
                    result = btc_session.prepare(**data)
                elif self.path == "/api/btc/accept":
                    if set(data) != {"raw"} or not isinstance(data["raw"], str):
                        raise ValueError("Expected signed Bitcoin PSBT file")
                    result = btc_session.accept_signed(data["raw"].encode("utf-8"))
                elif self.path in ("/api/btc/broadcast", "/api/btc/status", "/api/btc/cancel"):
                    if data:
                        raise ValueError("BTC operation does not accept overrides")
                    if self.path == "/api/btc/cancel":
                        request_id = btc_session.pending.get("request_id") if btc_session.pending else None
                        if crossboot is not None and crossboot.available and request_id:
                            crossboot.cancel(session, btc_session, request_id)
                        result = btc_session.cancel()
                    elif self.path == "/api/btc/broadcast":
                        if crossboot is not None and crossboot.available:
                            if btc_session.pending is None or btc_session.pending.get("stage") != "verified":
                                raise ValueError("BTC broadcast requires a verified pending transaction")
                            crossboot.mark_broadcast_requested(
                                session, btc_session, btc_session.pending["txid"]
                            )
                        result = btc_session.broadcast()
                        if crossboot is not None and crossboot.available and result.get("stage") == "broadcasted":
                            # An Esplora acknowledgement may be fabricated.
                            # Keep the reserved txid and exchange evidence.
                            btc_session.pending["stage"] = "broadcast_unknown"
                            result = btc_session.pending_view()
                    else:
                        result = btc_session.check_status()
                else:
                    self._json({"error": "Unknown endpoint"}, 404)
                    return
                self._json(result)
            except (UnicodeError, ValueError, TypeError, json.JSONDecodeError, OSError) as exc:
                self._json({"error": str(exc)}, 400)

        @staticmethod
        def _unique(pairs):
            obj = {}
            for k, v in pairs:
                if k in obj:
                    raise ValueError("Duplicate HTTP JSON field")
                obj[k] = v
            return obj

    return CompanionHandler


def create_server(rpc: JsonRpc, port: int = 8765, esplora: TestnetEsplora | None = None,
                  crossboot: CrossBootManager | None = None):
    if not 0 <= port <= 65535:
        raise ValueError("Invalid port")
    session = CompanionSession(rpc)
    btc_session = BitcoinCompanion(esplora if esplora is not None else TestnetEsplora())
    token = secrets.token_urlsafe(32)
    if crossboot is not None and crossboot.available:
        try:
            crossboot.restore(session, btc_session)
            status = crossboot.status(session, btc_session)
            if status.get("can_resume"):
                crossboot.resume_response(session, btc_session)
        except ValueError as exc:
            # Start the public UI for recovery, but never authorize a malformed
            # state/request/response or synthesize a replacement transaction.
            crossboot.error = str(exc)
            session.pending = None
            btc_session.pending = None
    server = ThreadingHTTPServer(("127.0.0.1", port), handler_for(session, btc_session, token, crossboot))
    server.daemon_threads = True
    return server, session, token


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="usb-cold-companion",
        description="LOCAL ONLINE watch-only companion. Sepolia only; NO private keys."
    )
    parser.add_argument("--rpc-url", required=True, help="HTTPS Sepolia RPC (or local HTTP node). No credentials in URL.")
    parser.add_argument("--btc-esplora", default="https://blockstream.info/testnet/api",
                        help="HTTPS Bitcoin testnet Esplora API (or local HTTP).")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open-browser", action="store_true")
    parser.add_argument("--exchange-root", default=None,
                        help="Test/development TX_TRANSFER override; Windows portable mode auto-detects it")
    args = parser.parse_args(argv)
    try:
        crossboot = CrossBootManager.auto(args.exchange_root)
        server, _session, _token = create_server(JsonRpc(args.rpc_url), args.port,
                                                 TestnetEsplora(args.btc_esplora), crossboot)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    url = f"http://127.0.0.1:{server.server_port}"
    print(f"Online Companion: {url} (Sepolia testnet only, no private key import)")
    print("The browser interface is local-only. Press Ctrl+C to stop and erase in-memory pending state.")
    if args.open_browser:
        threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
