"""Loopback-only browser UI for the public-data Online Companion.

No wallet secret import, no remote web assets, no RPC input from browser.
"""
from __future__ import annotations

import argparse
import hmac
import html
import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .companion_core import CompanionSession, JsonRpc, MAX_EXCHANGE_BYTES
from .companion_btc import BitcoinCompanion, TestnetEsplora

STATIC = Path(__file__).parent / "companion_static"
POST_LIMIT = MAX_EXCHANGE_BYTES + 65_536


def handler_for(session: CompanionSession, btc_session: BitcoinCompanion, token: str):
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
                data = json.loads(raw.decode("utf-8"), object_pairs_hook=self._unique)
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
                    result = session.broadcast()
                elif self.path == "/api/status":
                    if data:
                        raise ValueError("Status query does not accept overrides")
                    result = session.check_status()
                elif self.path == "/api/cancel":
                    if data:
                        raise ValueError("Cancel does not accept overrides")
                    result = session.cancel()
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
                    commands = {
                        "/api/btc/broadcast": btc_session.broadcast,
                        "/api/btc/status": btc_session.check_status,
                        "/api/btc/cancel": btc_session.cancel
                    }
                    result = commands[self.path]()
                else:
                    self._json({"error": "Unknown endpoint"}, 404)
                    return
                self._json(result)
            except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
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


def create_server(rpc: JsonRpc, port: int = 8765, esplora: TestnetEsplora | None = None):
    if not 0 <= port <= 65535:
        raise ValueError("Invalid port")
    session = CompanionSession(rpc)
    btc_session = BitcoinCompanion(esplora if esplora is not None else TestnetEsplora())
    token = secrets.token_urlsafe(32)
    server = ThreadingHTTPServer(("127.0.0.1", port), handler_for(session, btc_session, token))
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
    args = parser.parse_args(argv)
    try:
        server, _session, _token = create_server(JsonRpc(args.rpc_url), args.port,
                                                 TestnetEsplora(args.btc_esplora))
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
