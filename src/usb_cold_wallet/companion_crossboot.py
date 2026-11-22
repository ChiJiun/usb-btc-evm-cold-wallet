"""Public-only Windows adapter for the Issue #37 v2 cross-boot contract.

The canonical on-wire contract remains src/usb_cold_wallet/cross_boot.py.  This
adapter intentionally does not import that cold-side module because it imports
signing/review modules that are forbidden from the Windows Portable EXE.
Compatibility tests pass every request/response through the formal v2 API.
"""
from __future__ import annotations

import base64
import binascii
import ctypes
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from pathlib import Path

from embit import networks, psbt
from eth_utils import to_checksum_address

from .companion_core import canonical, pack_envelope, unpack_envelope
from .transaction_state import PendingRequestStore
from .cross_boot_public import (
    VERSION, FORMAT, REQUEST_ID_RE, HEX64_RE, REQUEST_FIELDS, RESPONSE_FIELDS,
    NETWORK, REQUEST_TO_RESPONSE, parse_psbt as _parse_psbt,
    package_v2_request, verify_v2_request as _verify_request_public,
    verify_v2_response_envelope as _verify_response_public,
    sha_value as _sha, envelope_sha as _envelope_sha,
)

LABEL = "TX_TRANSFER"
BASE_DIR = ".usb-cold-wallet"
EXCHANGE_DIR = "exchange"
ONLINE_STATE_DIR = "state/online"
WATCH_FILE = "watch-only.json"
MAX_BYTES = 200_000
RESPONSE_KIND = REQUEST_TO_RESPONSE
ACTIVE_STATES = {"DRAFT", "EXPORTED", "IMPORTED_VERIFIED", "BROADCAST_REQUESTED"}


def _strict_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("Duplicate JSON property")
        out[key] = value
    return out


def _read_json(path: Path, *, max_bytes: int = MAX_BYTES):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError("Cross-boot file is unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Cross-boot path is not a regular file")
        raw = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    if not raw or len(raw) > max_bytes:
        raise ValueError("Cross-boot file size is invalid")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON number")),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Cross-boot file is invalid JSON") from exc


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        wrote = os.write(fd, view)
        if wrote <= 0:
            raise OSError("Short cross-boot write")
        view = view[wrote:]
    os.fsync(fd)


def _create_only(path: Path, value: dict) -> None:
    """Publish a completed JSON object without overwriting an existing request."""
    raw = canonical(value) + b"\n"
    if len(raw) > MAX_BYTES:
        raise ValueError("Cross-boot envelope exceeds maximum size")
    path.parent.mkdir(parents=True, exist_ok=True)
    stage = path.with_name(f".{path.name}.{secrets.token_hex(8)}.partial")
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        _write_all(fd, raw)
    finally:
        os.close(fd)
    try:
        if os.name == "nt":
            os.rename(stage, path)  # Windows rename is create-only when dst exists.
        else:
            os.link(stage, path, follow_symlinks=False)
            stage.unlink()
        try:
            parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        except OSError:
            pass
    except Exception:
        try:
            stage.unlink()
        except OSError:
            pass
        raise


def _replace_public(path: Path, value: dict) -> None:
    """Atomic replacement is used only for public watch-only account metadata."""
    raw = canonical(value) + b"\n"
    if len(raw) > MAX_BYTES:
        raise ValueError("Watch-only file exceeds maximum size")
    path.parent.mkdir(parents=True, exist_ok=True)
    stage = path.with_name(f".{path.name}.{secrets.token_hex(8)}.partial")
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        _write_all(fd, raw)
    finally:
        os.close(fd)
    os.replace(stage, path)


def _package_request(kind: str, payload, *, request_id: str, account: str,
                     recipient: str, amount: int) -> dict:
    return package_v2_request(
        kind, payload, request_id=request_id, account=account,
        recipient=recipient, amount=amount,
        expiry={"mode": "no-trusted-clock", "notAfter": None},
    )


def discover_windows_exchange_root() -> Path:
    """Fail closed until the merged single-USB GPT/layout contract is shared here.

    Volume labels and DRIVE_REMOVABLE/DRIVE_FIXED are presentation metadata,
    not device identity. PR #76 owns the authoritative disk/partition contract;
    automatic discovery must remain disabled rather than accept a spoofable
    TX_TRANSFER label before that contract is merged and consumed.
    """
    if os.name != "nt":
        raise ValueError("Automatic TX_TRANSFER discovery requires Windows")
    raise ValueError(
        "Automatic TX_TRANSFER discovery is disabled until validated GPT/layout identity is integrated"
    )


class CrossBootManager:
    """UI/filesystem adapter backed by the formal PendingRequestStore journal."""

    def __init__(self, root: Path | None, error: str | None = None):
        self.root = Path(root) if root is not None else None
        self.error = error
        self.base = self.root / BASE_DIR if self.root else None
        self.exchange = self.base / EXCHANGE_DIR if self.base else None
        self.state_root = self.base / ONLINE_STATE_DIR if self.base else None
        self.watch_path = self.base / WATCH_FILE if self.base else None

    @classmethod
    def auto(cls, explicit_root: str | Path | None = None):
        if explicit_root is not None:
            root = Path(explicit_root)
            return cls(root) if root.is_dir() else cls(None, "Configured exchange root does not exist")
        try:
            return cls(discover_windows_exchange_root())
        except ValueError as exc:
            return cls(None, str(exc))

    @property
    def available(self) -> bool:
        return self.root is not None

    def _require(self):
        if not self.available:
            raise ValueError(self.error or "TX_TRANSFER exchange partition unavailable")

    def _store(self) -> PendingRequestStore:
        self._require()
        return PendingRequestStore(self.state_root)

    def remember_wallet(self, session, btc_session) -> None:
        self._require()
        if session.wallet is None:
            return
        envelope = pack_envelope("watch-only", session.wallet)
        _replace_public(self.watch_path, envelope)

    def _load_wallet(self, session, btc_session) -> bool:
        if not self.watch_path.exists():
            return False
        data = _read_json(self.watch_path)
        wallet = unpack_envelope(data, "watch-only")
        session.wallet = wallet
        btc_session.import_wallet(wallet)
        return True

    def _request_path(self, request_id: str) -> Path:
        return self.exchange / f"request-{request_id}.json"

    def _response_path(self, request_id: str) -> Path:
        return self.exchange / f"response-{request_id}.json"

    def _load_request(self, request_id: str, expected_account: str | None = None):
        data = _read_json(self._request_path(request_id))
        _verify_request_public(
            data, expected_account=expected_account, allow_no_trusted_clock=True
        )
        return data

    def _request_from_pending(self, session, btc_session):
        if session.pending is not None and btc_session.pending is not None:
            raise ValueError("Only one BTC or Sepolia transaction may be pending")
        if session.pending is not None:
            p = session.pending
            if p.get("stage") != "prepared" or session.wallet is None:
                raise ValueError("Sepolia request is not exportable")
            return _package_request(
                "evm-request", p["tx"], request_id=p["request_id"],
                account=session.wallet["evm"]["address"], recipient=p["tx"]["to"],
                amount=p["tx"]["value"],
            ), session, "sepolia"
        if btc_session.pending is not None:
            p = btc_session.pending
            if p.get("stage") != "prepared" or btc_session.wallet is None:
                raise ValueError("BTC request is not exportable")
            if p.get("change_index") is None or type(p.get("change_sats")) is not int or p["change_sats"] <= 0:
                raise ValueError("BTC cross-boot requires a change output to preserve fee-rate provenance")
            return _package_request(
                "btc-request", p["psbt_base64"], request_id=p["request_id"],
                account=btc_session.wallet["master_fingerprint"], recipient=p["recipient"],
                amount=p["amount_sats"],
            ), btc_session, "bitcoin-testnet"
        raise ValueError("Exactly one pending BTC or Sepolia transaction is required")

    def _reconstruct(self, request: dict, session, btc_session):
        kind = request["kind"]
        if kind == "evm-request":
            tx = request["payload"]
            session.pending = {
                "stage": "prepared", "request_id": request["requestId"],
                "digest": request["transactionDigest"], "tx": tx,
                "envelope": pack_envelope("evm-request", tx),
            }
            return session
        parsed, _raw = _parse_psbt(request["payload"])
        intent = request["intent"]
        input_total = sum(item["value"] for item in intent["utxos"])
        inputs = []
        for index, item in enumerate(intent["utxos"]):
            scope = parsed.inputs[index]
            address = scope.witness_utxo.script_pubkey.address(networks.NETWORKS["test"])
            inputs.append({**item, "address": address})
        outputs = []
        change_index = None
        change_address = None
        for out in parsed.tx.vout:
            address = out.script_pubkey.address(networks.NETWORKS["test"])
            outputs.append({"address": address, "value": out.value})
            if not (address == intent["recipient"] and out.value == intent["amount"]):
                matches = [i for i in range(20) if btc_session._address(1, i) == address]
                if len(matches) != 1 or change_index is not None:
                    raise ValueError("BTC change output cannot be derived from watch-only account")
                change_index, change_address = matches[0], address
        change_sats = input_total - intent["amount"] - intent["fee"]
        if (change_sats > 0) != (change_index is not None):
            raise ValueError("BTC change amount/output mismatch after reboot")
        if change_sats <= 0 or len(parsed.tx.vout) != 2 or change_index is None:
            raise ValueError("BTC fee-rate provenance is unavailable after reboot")
        estimated_vbytes = 12 + 70 * len(parsed.inputs) + 32 * len(parsed.tx.vout)
        if intent["fee"] % estimated_vbytes:
            raise ValueError("BTC fee rate is not losslessly recoverable from persisted PSBT")
        fee_rate = intent["fee"] // estimated_vbytes
        if not 1 <= fee_rate <= 500:
            raise ValueError("BTC fee rate outside supported policy")
        btc_session.pending = {
            "stage": "prepared", "request_id": request["requestId"],
            "digest": request["transactionDigest"], "psbt_base64": request["payload"],
            "recipient": intent["recipient"], "amount_sats": intent["amount"],
            "fee_sats": intent["fee"], "fee_rate": fee_rate,
            "change_sats": change_sats, "change_index": change_index,
            "change_address": change_address, "inputs": inputs, "outputs": outputs,
            "input_count": len(parsed.inputs), "unsigned": parsed,
        }
        return btc_session

    def _active_request_ids(self):
        if not self.exchange.exists():
            return []
        store = self._store()
        active = []
        for path in sorted(self.exchange.glob("request-*.json")):
            match = re.fullmatch(r"request-([0-9a-f]{32})\.json", path.name)
            if match is None:
                raise ValueError("Unexpected request filename in TX_TRANSFER")
            request_id = match.group(1)
            request = _verify_request_public(_read_json(path), allow_no_trusted_clock=True)
            if request["requestId"] != request_id:
                raise ValueError("Request filename does not match v2 requestId")
            snap = store.get(request_id)
            if snap is None:
                # The exchange is attacker-writable. A missing authoritative
                # journal is indistinguishable from deletion/rollback, so never
                # synthesize state from a request file.
                raise ValueError("Authoritative online journal missing; recovery fails closed")
            elif snap.state == "DRAFT":
                store.exported(request)
                active.append(request_id)
            elif snap.state in ACTIVE_STATES:
                active.append(request_id)
            elif snap.state == "FAILED":
                reason = snap.metadata.get("reason", "")
                if "broadcast outcome unknown" in reason and self._response_path(request_id).is_file():
                    active.append(request_id)
                else:
                    self._cleanup_files(request_id)
            elif snap.state == "BROADCASTED":
                self._cleanup_files(request_id)
            else:
                raise ValueError("Unsupported persisted online state")
        return active

    def restore(self, session, btc_session) -> bool:
        self._require()
        self._load_wallet(session, btc_session)
        active = self._active_request_ids()
        if not active:
            return session.wallet is not None
        if len(active) != 1:
            raise ValueError("Multiple active cross-boot requests found")
        request_id = active[0]
        request = self._load_request(request_id)
        if session.wallet is None:
            raise ValueError("Active request has no persisted watch-only account")
        expected = (session.wallet["evm"]["address"] if request["kind"] == "evm-request"
                    else session.wallet["bitcoin"]["master_fingerprint"])
        request = self._load_request(request_id, expected)
        owner = self._reconstruct(request, session, btc_session)
        snap = self._store().get(request_id)
        if snap.state in {"IMPORTED_VERIFIED", "BROADCAST_REQUESTED"}:
            response = _read_json(self._response_path(request_id))
            payload = _verify_response_public(
                request, response, expected_account=expected, allow_no_trusted_clock=True
            )
            owner.accept_signed(canonical(payload))
            if snap.state == "BROADCAST_REQUESTED":
                owner.pending["stage"] = "broadcast_unknown"
        return True

    def export_current(self, session, btc_session) -> dict:
        self._require()
        request, _owner, _asset = self._request_from_pending(session, btc_session)
        request_id = request["requestId"]
        store = self._store()
        if store.get(request_id) is not None:
            raise ValueError("Request ID was already persisted")
        for active_id in self._active_request_ids():
            if active_id != request_id:
                raise ValueError("Another cross-boot request is still active")
        self.remember_wallet(session, btc_session)
        self.exchange.mkdir(parents=True, exist_ok=True)
        _create_only(self._request_path(request_id), request)
        store.create(request)
        store.exported(request)
        return self.status(session, btc_session)

    def resume_response(self, session, btc_session) -> dict:
        self._require()
        request, owner, _asset = self._request_from_pending(session, btc_session)
        request_id = request["requestId"]
        store = self._store()
        snap = store.get(request_id)
        if snap is None or snap.state != "EXPORTED":
            raise ValueError("Pending request is not in EXPORTED state")
        persisted = self._load_request(request_id, request["account"])
        if persisted != request:
            raise ValueError("Persisted v2 request differs from in-memory request")
        response = _read_json(self._response_path(request_id))
        payload = _verify_response_public(
            request, response, expected_account=request["account"], allow_no_trusted_clock=True
        )
        owner.accept_signed(canonical(payload))
        store.import_verified(
            request, response, allow_no_trusted_clock=True, verifier=_verify_response_public
        )
        return self.status(session, btc_session)

    def mark_broadcast_requested(self, session, btc_session, txid: str) -> None:
        """Durably reserve the only broadcast attempt before network I/O."""
        request, owner, _asset = self._request_from_any(session, btc_session)
        if owner.pending.get("stage") != "verified":
            raise ValueError("Only a verified signed result may request broadcast")
        snap = self._store().get(request["requestId"])
        if snap is None or snap.state != "IMPORTED_VERIFIED":
            raise ValueError("Broadcast request is not bound to IMPORTED_VERIFIED state")
        self._store().broadcast_requested(request, txid)

    def broadcast_reservation(self, session, btc_session) -> dict:
        request, owner, asset = self._request_from_any(session, btc_session)
        snap = self._store().get(request["requestId"])
        if snap is None or snap.state != "BROADCAST_REQUESTED":
            raise ValueError("No ambiguous broadcast reservation is pending")
        txid = snap.metadata.get("txid")
        actual = owner.pending.get("tx_hash") if asset == "sepolia" else owner.pending.get("txid")
        if type(txid) is not str or actual != txid or owner.pending.get("stage") != "broadcast_unknown":
            raise ValueError("Broadcast reservation does not match retained signed transaction")
        return {"asset": asset, "txid": txid, "request_id": request["requestId"]}

    def reconcile_broadcast(self, session, btc_session, observed: dict) -> dict:
        reservation = self.broadcast_reservation(session, btc_session)
        if (type(observed) is not dict or observed.get("asset") != reservation["asset"]
                or observed.get("txid") != reservation["txid"]
                or observed.get("result") not in {"pending", "confirmed", "reverted"}
                or observed.get("untrusted_rpc") is not True):
            raise ValueError("Chain status lookup did not match the reserved transaction")
        # Public RPC/Esplora status is advisory: a hostile endpoint can claim that
        # an arbitrary txid is pending/confirmed.  Never consume the durable
        # BROADCAST_REQUESTED reservation or delete its signed exchange files
        # based only on that unauthenticated observation.  A future transition
        # requires independently authenticated chain evidence.
        raise ValueError(
            "Untrusted chain status is advisory only; BROADCAST_REQUESTED remains fail closed"
        )

    def mark_broadcasted(self, session, btc_session, txid: str) -> None:
        """No unauthenticated remote acknowledgement may finalize state."""
        raise ValueError(
            "Authenticated chain evidence required before finalizing broadcast"
        )

    def mark_failed(self, session, btc_session, reason: str) -> None:
        try:
            request, _owner, _asset = self._request_from_any(session, btc_session)
        except ValueError:
            return
        snap = self._store().get(request["requestId"])
        if snap is not None and snap.state in {"DRAFT", "EXPORTED", "IMPORTED_VERIFIED"}:
            self._store().failed(request, (reason[:256] or "failed"))
            self._cleanup_files(request["requestId"])

    def cancel(self, session, btc_session, request_id: str | None) -> None:
        if not request_id or REQUEST_ID_RE.fullmatch(request_id) is None:
            return
        try:
            request = self._load_request(request_id)
        except ValueError:
            return
        snap = self._store().get(request_id)
        if snap is not None and snap.state in {"DRAFT", "EXPORTED", "IMPORTED_VERIFIED"}:
            self._store().failed(request, "cancelled by user")
        self._cleanup_files(request_id)

    def _request_from_any(self, session, btc_session):
        for owner, asset in ((session, "sepolia"), (btc_session, "bitcoin-testnet")):
            if owner.pending is not None:
                request_id = owner.pending.get("request_id")
                if REQUEST_ID_RE.fullmatch(request_id or "") is None:
                    raise ValueError("Pending Request ID invalid")
                return self._load_request(request_id), owner, asset
        raise ValueError("No persisted cross-boot request")

    def _cleanup_files(self, request_id: str) -> None:
        if self.exchange is None:
            return
        for path in (self._request_path(request_id), self._response_path(request_id)):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def status(self, session=None, btc_session=None) -> dict:
        result = {
            "available": self.available,
            "root": str(self.root) if self.root else None,
            "error": self.error,
            "can_export": False,
            "can_resume": False,
            "asset": None,
            "request_id": None,
            "stage": None,
            "protocol_version": VERSION,
            "expiry_assurance": "unverified",
            "guidance": (
                "建立交易後儲存到單 USB，完全關閉 Companion，重新開機並在 UEFI 選擇此 USB；"
                "離線 GUI 完整核對並人工簽署後關機，返回 Windows 再啟動 Companion。"
                "回覆只會驗證；Broadcast 永遠需要人工確認。"
            ),
        }
        if not self.available or session is None or btc_session is None:
            return result
        pending = None
        asset = None
        if session.pending is not None:
            pending, asset = session.pending, "sepolia"
        elif btc_session.pending is not None:
            pending, asset = btc_session.pending, "bitcoin-testnet"
        if pending is None:
            return result
        request_id = pending.get("request_id")
        result.update({"asset": asset, "request_id": request_id, "stage": pending.get("stage")})
        if REQUEST_ID_RE.fullmatch(request_id or "") is None:
            return result
        snap = self._store().get(request_id)
        result["can_export"] = pending.get("stage") == "prepared" and snap is None
        if snap is not None:
            result["state"] = snap.state
            if snap.state == "EXPORTED":
                result["can_resume"] = self._response_path(request_id).is_file()
        return result
