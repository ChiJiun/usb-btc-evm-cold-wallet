"""Bitcoin TESTNET watch-only spending: Esplora -> checked PSBT v0 -> offline.

Never imports any seed/vault/key. Network-supplied data is untrusted. Input
transaction history and the raw transaction do NOT prove an output unspent.
The offline BIP84 signer must independently check origins, values, outputs,
fee and human authorization.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import secrets
import threading
from decimal import Decimal, InvalidOperation
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, Request

from embit import bip32, ec, networks, psbt, script, transaction

from .companion_core import (canonical, decode_json, pack_envelope,
                             unpack_envelope, MAX_EXCHANGE_BYTES)

NETWORK = networks.NETWORKS["test"]
MAX_INPUTS = 20
SCAN_GAP = 20
MAX_FEE_SATS = 50_000
MAX_FEE_RATE = 250  # sat/vB
MAX_SATS = 21_000_000 * 100_000_000
MAX_HTTP_BYTES = 300_000
DUST = 546  # conservative P2WPKH change dust policy, NOT a consensus rule
TXID_RE = re.compile(r"^[0-9a-fA-F]{64}$")
FP_RE = re.compile(r"^[0-9a-f]{8}$")
HARDENED = 0x80000000


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _endpoint(url: str) -> str:
    parsed = urlsplit(url)
    if (parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment or parsed.query
            or (parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"))):
        raise ValueError("Esplora endpoint must use HTTPS or localhost HTTP; URL credentials forbidden")
    # Disallow arbitrary extension paths and browser-controlled URLs.
    if not re.fullmatch(r"/[A-Za-z0-9/_-]{0,120}", parsed.path):
        raise ValueError("Invalid Esplora path")
    return url.rstrip("/")


class TestnetEsplora:
    """Fixed testnet endpoint; bounded responses and no redirects/retries."""

    def __init__(self, url="https://blockstream.info/testnet/api", timeout=8):
        self.url = _endpoint(url)
        if type(timeout) not in (float, int) or not 1 <= timeout <= 30:
            raise ValueError("Invalid timeout")
        self.timeout = timeout
        self.display_endpoint = self.url
        self._opener = build_opener(_NoRedirect())

    def _request(self, path, *, body=None, limit=MAX_HTTP_BYTES):
        if not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9/_-]+", path):
            raise ValueError("Invalid Esplora endpoint path")
        request = Request(
            self.url + path, data=body,
            headers={"Accept": "application/json" if body is None else "text/plain",
                     "Content-Type": "text/plain" if body is not None else "application/json"},
            method="POST" if body is not None else "GET"
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                result = response.read(limit + 1)
        except HTTPError as exc:
            if exc.code == 404 and body is None:
                return None
            raise ValueError(f"Esplora HTTP error {exc.code}; no automatic retry") from None
        except (URLError, OSError, TimeoutError) as exc:
            raise ValueError("Esplora unavailable or timed out; no automatic retry") from None
        if len(result) > limit:
            raise ValueError("Esplora response too large")
        try:
            return result.decode("utf-8").strip()
        except UnicodeError as exc:
            raise ValueError("Esplora response is not UTF-8") from exc

    def json_get(self, path):
        raw = self._request(path)
        if raw is None:
            return None
        return decode_json(raw.encode("utf-8"))

    def utxos(self, address):
        return self.json_get("/address/" + address + "/utxo")

    def activity(self, address):
        return self.json_get("/address/" + address)

    def previous(self, txid):
        raw = self._request("/tx/" + txid + "/hex")
        if raw is None or len(raw) > MAX_HTTP_BYTES:
            raise ValueError("Previous transaction unavailable")
        try:
            tx = transaction.Transaction.parse(bytes.fromhex(raw))
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid previous transaction") from exc
        if tx.txid().hex() != txid.lower():
            raise ValueError("Previous transaction TXID mismatch")
        return tx

    def fee_rate(self):
        values = self.json_get("/fee-estimates")
        if not isinstance(values, dict) or "6" not in values:
            raise ValueError("Esplora missing 6-block fee estimate")
        try:
            value = Decimal(str(values["6"]))
        except InvalidOperation as exc:
            raise ValueError("Invalid fee estimate") from exc
        if not value.is_finite() or not 0 < value <= MAX_FEE_RATE:
            raise ValueError("Fee estimate exceeds bound")
        return max(1, int(value.to_integral_value(rounding="ROUND_CEILING")))

    def send(self, raw_hex):
        return self._request("/tx", body=raw_hex.encode("ascii"), limit=256)

    def status(self, txid):
        return self.json_get("/tx/" + txid + "/status")


def checked_recipient(addr: str) -> bytes:
    if not isinstance(addr, str) or not 15 <= len(addr) <= 90:
        raise ValueError("Invalid Bitcoin testnet destination")
    try:
        out = script.address_to_scriptpubkey(addr)
        canonical_address = out.address(NETWORK)
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError("Invalid Bitcoin testnet destination") from exc
    if canonical_address != addr or len(out.data) != 22 or out.data[:2] != b"\x00\x14":
        raise ValueError("Only canonical Bitcoin testnet BIP84 P2WPKH destinations are supported")
    return out.data


def _parse_sats(value: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{1,8})?", value):
        raise ValueError("BTC value must be positive decimal with up to 8 places")
    try:
        sats = int(Decimal(value) * 100_000_000)
    except InvalidOperation as exc:
        raise ValueError("Invalid BTC amount") from exc
    if not 0 < sats <= MAX_SATS:
        raise ValueError("BTC amount out of range")
    return sats


class BitcoinCompanion:
    """One BTC transaction at a time, independent of EVM state."""

    def __init__(self, esplora: TestnetEsplora):
        self.api = esplora
        self.wallet = None
        self.pending = None
        self.lock = threading.RLock()

    def import_wallet(self, wallet: dict):
        with self.lock:
            if self.pending is not None:
                raise ValueError("Cancel active Bitcoin request before changing account")
            self.wallet = wallet["bitcoin"]

    def _account(self):
        if self.wallet is None:
            raise ValueError("Import a public watch-only wallet first")
        return bip32.HDKey.from_base58(self.wallet["account_tpub"])

    def _address(self, branch: int, index: int) -> str:
        pub = self._account().derive(f"{branch}/{index}").key
        return script.p2wpkh(pub).address(NETWORK)

    def public_view(self):
        with self.lock:
            return {"endpoint": self.api.display_endpoint, "network": "Bitcoin testnet",
                    "spending_ready": self.wallet is not None and self.wallet.get("master_fingerprint") is not None,
                    "pending": self.pending_view()}

    def pending_view(self):
        if self.pending is None:
            return None
        p = self.pending
        return {k: p.get(k) for k in ("stage", "request_id", "digest", "recipient",
                "amount_sats", "fee_sats", "fee_rate", "change_sats", "change_index",
                "input_count", "txid", "result", "reorg_warning")}

    def _scan(self):
        self._account()
        all_utxos = []
        used_outpoints = set()
        balance = 0
        # Scope is explicit: export's receiving addresses + fixed 20 internal
        # change addresses. Not full wallet history discovery.
        for branch, count in ((0, len(self.wallet["receive_addresses"])), (1, SCAN_GAP)):
            for index in range(count):
                address = self._address(branch, index)
                entries = self.api.utxos(address)
                if not isinstance(entries, list) or len(entries) > 150:
                    raise ValueError("Invalid or excessive Esplora UTXO list")
                for entry in entries:
                    if not isinstance(entry, dict) or set(entry) != {"txid", "vout", "value", "status"}:
                        raise ValueError("Unexpected Esplora UTXO response")
                    txid, vout, sats, status = (entry[k] for k in ("txid", "vout", "value", "status"))
                    if (type(txid) is not str or not TXID_RE.fullmatch(txid)
                            or type(vout) is not int or not 0 <= vout < 100_000
                            or type(sats) is not int or not 0 < sats <= MAX_SATS
                            or not isinstance(status, dict) or type(status.get("confirmed")) is not bool):
                        raise ValueError("Malformed Esplora UTXO")
                    outpoint = (txid.lower(), vout)
                    if outpoint in used_outpoints:
                        raise ValueError("Duplicate UTXO across wallet addresses")
                    used_outpoints.add(outpoint)
                    if status["confirmed"]:
                        all_utxos.append({"txid": txid.lower(), "vout": vout, "sats": sats,
                                          "branch": branch, "index": index, "address": address})
                        balance += sats
                        if balance > MAX_SATS:
                            raise ValueError("UTXO total exceeds Bitcoin supply")
        return all_utxos, balance

    def overview(self):
        with self.lock:
            utxos, confirmed = self._scan()
            return {"network": "Bitcoin testnet", "endpoint": self.api.display_endpoint,
                    "confirmed_sats": confirmed, "confirmed_utxo_count": len(utxos),
                    "fee_rate_sat_vb": self.api.fee_rate(),
                    "scan_receive_addresses": len(self.wallet["receive_addresses"]),
                    "scan_change_addresses": SCAN_GAP,
                    "spending_ready": self.wallet.get("master_fingerprint") is not None}

    def _unused_change(self):
        # UTXO balance alone is NOT enough: already-spent change addresses
        # must not be silently reused.
        for index in range(SCAN_GAP):
            address = self._address(1, index)
            stats = self.api.activity(address)
            if not isinstance(stats, dict):
                raise ValueError("Missing change address history")
            counts = []
            for key in ("chain_stats", "mempool_stats"):
                section = stats.get(key)
                if not isinstance(section, dict):
                    raise ValueError("Invalid change address history")
                num = section.get("funded_txo_count")
                if type(num) is not int or not 0 <= num < 2**31:
                    raise ValueError("Invalid funded output count")
                counts.append(num)
            if sum(counts) == 0:
                return index
        raise ValueError("Change gap exhausted; re-export wallet with extended history support")

    def prepare(self, recipient: str, amount_btc: str, max_fee_sats: int = MAX_FEE_SATS,
                fee_rate_sat_vb: int | None = None):
        with self.lock:
            if self.wallet is None or self.wallet.get("master_fingerprint") is None:
                raise ValueError("Re-export public wallet from updated Offline Signer with master fingerprint")
            if self.pending is not None:
                raise ValueError("Cancel or finish the prior BTC transaction first")
            target_script = checked_recipient(recipient)
            sats = _parse_sats(amount_btc)
            if sats < DUST:
                raise ValueError("Recipient amount is below conservative P2WPKH dust threshold")
            if type(max_fee_sats) is not int or not 0 < max_fee_sats <= MAX_FEE_SATS:
                raise ValueError("Maximum fee outside allowed range")
            rate = self.api.fee_rate() if fee_rate_sat_vb is None else fee_rate_sat_vb
            if type(rate) is not int or not 1 <= rate <= MAX_FEE_RATE:
                raise ValueError("Invalid fee rate")
            unspent, _ = self._scan()
            if not unspent:
                raise ValueError("No confirmed Bitcoin testnet UTXOs found")
            change_index = self._unused_change()
            change_script = script.address_to_scriptpubkey(self._address(1, change_index))
            if target_script == change_script.data:
                raise ValueError("Recipient cannot equal designated change output")
            picked = []
            total = 0
            change = 0
            fee = 0
            sufficient = False
            # Deterministic, bounded greedy coin selection, largest first; no
            # RBF, no coinjoin, no path outside BIP84 0..19.
            for item in sorted(unspent, key=lambda x: (-x["sats"], x["txid"], x["vout"])):
                if len(picked) >= MAX_INPUTS:
                    break
                picked.append(item)
                total += item["sats"]
                estimate_two_outputs = 12 + 70 * len(picked) + 2 * 32
                expected_fee = math.ceil(rate * estimate_two_outputs)
                if total >= sats + expected_fee + DUST:
                    change = total - sats - expected_fee
                    fee = expected_fee
                    sufficient = True
                    break
                estimate_one_output = 12 + 70 * len(picked) + 32
                expected_fee = math.ceil(rate * estimate_one_output)
                if total >= sats + expected_fee:
                    change = 0
                    fee = total - sats
                    sufficient = True
                    break
            if not sufficient:
                raise ValueError("Insufficient confirmed UTXOs (max 20 inputs)")
            if not 0 < fee <= max_fee_sats:
                raise ValueError("Calculated miner fee outside user cap")
            outputs = [transaction.TransactionOutput(sats, script.Script(target_script))]
            if change >= DUST:
                outputs.append(transaction.TransactionOutput(change, change_script))
            # Stronger limitation: builder cannot produce transaction if output
            # sum or change policy contradicts original recipient intent.
            if sum(out.value for out in outputs) + fee != total:
                raise ValueError("Coin selection fee invariant violated")
            vins = [transaction.TransactionInput(bytes.fromhex(item["txid"]), item["vout"],
                    sequence=0xFFFFFFFF) for item in picked]
            unsigned = transaction.Transaction(version=2, vin=vins, vout=outputs, locktime=0)
            p = psbt.PSBT(unsigned)
            p.unknown = {}
            fp = bytes.fromhex(self.wallet["master_fingerprint"])
            for idx, item in enumerate(picked):
                previous = self.api.previous(item["txid"])
                if item["vout"] >= len(previous.vout):
                    raise ValueError("Referenced previous output does not exist")
                prevout = previous.vout[item["vout"]]
                expected_script = script.address_to_scriptpubkey(item["address"])
                if prevout.value != item["sats"] or prevout.script_pubkey.data != expected_script.data:
                    raise ValueError("Esplora UTXO value/script mismatches original transaction")
                scope = p.inputs[idx]
                scope.unknown = {}
                scope.non_witness_utxo = previous
                scope.witness_utxo = prevout
                derived = self._account().derive(f"{item['branch']}/{item['index']}").key
                path = [84 | HARDENED, 1 | HARDENED, 0 | HARDENED,
                        item["branch"], item["index"]]
                scope.bip32_derivations[derived] = psbt.DerivationPath(fp, path)
            for scope in p.outputs:
                scope.unknown = {}
            encoded = p.to_base64()
            if len(encoded) > 180_000:
                raise ValueError("PSBT too large for bounded transport")
            # v0 PSBT input origin contains the PUBLIC master fingerprint, but
            # tpub cannot prove the claimed root fingerprint to the online PC.
            digest = hashlib.sha256(p.serialize()).hexdigest()
            self.pending = {"stage": "prepared", "request_id": secrets.token_hex(16),
                "digest": digest, "psbt_base64": encoded, "recipient": recipient, "amount_sats": sats,
                "fee_sats": fee, "fee_rate": rate, "change_sats": change,
                "change_index": change_index if change >= DUST else None,
                "input_count": len(picked), "unsigned": p}
            return {"pending": self.pending_view(), "envelope": pack_envelope("btc-request", encoded)}

    def request_envelope(self):
        with self.lock:
            if self.pending is None or self.pending["stage"] != "prepared":
                raise ValueError("No pending BTC request")
            return pack_envelope("btc-request", self.pending["psbt_base64"])

    def request_psbt_base64(self):
        with self.lock:
            if self.pending is None or self.pending["stage"] != "prepared":
                raise ValueError("No pending unsigned BTC PSBT")
            return self.pending["psbt_base64"]

    def accept_signed(self, raw: bytes):
        with self.lock:
            if self.pending is None or self.pending["stage"] != "prepared":
                raise ValueError("No pending BTC transaction awaiting signature")
            obj = decode_json(raw)
            payload = unpack_envelope(obj, "btc-signed") if isinstance(obj, dict) and obj.get("format") else obj
            required = {"network", "recipient", "amount_sats", "fee_sats", "signature_count", "signed_psbt_base64"}
            if (not isinstance(payload, dict) or not required <= set(payload)
                    or set(payload) - required - {"finalized_tx_hex"}
                    or payload["network"] != "bitcoin-testnet"
                    or payload["recipient"] != self.pending["recipient"]
                    or type(payload["amount_sats"]) is not int or payload["amount_sats"] != self.pending["amount_sats"]
                    or type(payload["fee_sats"]) is not int or payload["fee_sats"] != self.pending["fee_sats"]
                    or type(payload["signature_count"]) is not int or payload["signature_count"] != self.pending["input_count"]):
                raise ValueError("Signed Bitcoin metadata does not match unsigned intent")
            b64 = payload["signed_psbt_base64"]
            if not isinstance(b64, str) or len(b64) > 180_000:
                raise ValueError("Invalid signed PSBT size")
            try:
                raw_psbt = base64.b64decode(b64, validate=True)
                signed = psbt.PSBT.parse(raw_psbt)
                if signed.serialize() != raw_psbt:
                    raise ValueError("Signed PSBT is non-canonical or contains extra bytes")
            except Exception as exc:
                raise ValueError("Cannot parse canonical signed PSBT") from exc
            unsigned = self.pending["unsigned"]
            if signed.version is not None or len(signed.inputs) != len(unsigned.inputs):
                raise ValueError("Signed PSBT version or input count mismatch")
            try:
                finalized = transaction.Transaction.parse(signed.tx.serialize())
                for idx, inp in enumerate(signed.inputs):
                    if len(inp.partial_sigs) != 1:
                        raise ValueError("Exactly one signature per input is required")
                    pub, signature = next(iter(inp.partial_sigs.items()))
                    if len(signature) < 2 or signature[-1] != 1 or pub not in inp.bip32_derivations:
                        raise ValueError("Wrong PSBT signature or sighash type")
                    if not pub.verify(ec.Signature.parse(signature[:-1]), signed.sighash(idx, sighash=1)):
                        raise ValueError("PSBT cryptographic signature verification failed")
                    finalized.vin[idx].witness = transaction.Witness([signature, pub.sec()])
                    # Strip ONLY expected signature fields, then compare entire
                    # canonical PSBT bytes to the original request.
                    inp.partial_sigs = {}
                if signed.serialize() != unsigned.serialize():
                    raise ValueError("Signed PSBT changed unsigned transaction / UTXO / derivation / metadata")
                final_hex = finalized.serialize().hex()
                if "finalized_tx_hex" in payload and payload["finalized_tx_hex"] != final_hex:
                    raise ValueError("Cold signer finalized transaction does not match verified signatures")
                txid = finalized.txid().hex()
            except ValueError:
                raise
            except Exception as exc:
                raise ValueError("Invalid PSBT signatures or finalization") from exc
            self.pending.update({"stage": "verified", "signed_tx": final_hex, "txid": txid})
            return self.pending_view()

    def broadcast(self):
        with self.lock:
            if self.pending is None or self.pending["stage"] != "verified":
                raise ValueError("Only one previously verified BTC transaction can be broadcast")
            txid = self.pending["txid"]
            self.pending["stage"] = "broadcast_unknown"
            try:
                received = self.api.send(self.pending["signed_tx"])
            except ValueError:
                raise ValueError("BTC broadcast outcome unknown; query status, never automatically re-submit") from None
            if not isinstance(received, str) or received.lower() != txid:
                raise ValueError("Bitcoin explorer returned an unexpected transaction ID")
            self.pending["stage"] = "broadcasted"
            return self.pending_view()

    def check_status(self):
        with self.lock:
            if self.pending is None or self.pending.get("txid") is None:
                raise ValueError("No signed BTC transaction to query")
            status = self.api.status(self.pending["txid"])
            old = self.pending.get("result")
            if status is None:
                self.pending["result"] = "reorg_suspected" if old == "confirmed" else "not_found"
            elif not isinstance(status, dict) or type(status.get("confirmed")) is not bool:
                raise ValueError("Invalid Bitcoin transaction status response")
            elif status["confirmed"]:
                block_hash = status.get("block_hash")
                if not isinstance(block_hash, str) or not TXID_RE.fullmatch(block_hash):
                    raise ValueError("Confirmed BTC status missing block hash")
                if self.pending.get("block_hash") and self.pending["block_hash"] != block_hash:
                    self.pending["reorg_warning"] = True
                self.pending["block_hash"] = block_hash
                self.pending["result"] = "confirmed"
            else:
                self.pending["result"] = "reorg_suspected" if old == "confirmed" else "pending"
            if self.pending["result"] == "reorg_suspected":
                self.pending["reorg_warning"] = True
            return self.pending_view()

    def cancel(self):
        with self.lock:
            self.pending = None
            return {"cancelled": True}
