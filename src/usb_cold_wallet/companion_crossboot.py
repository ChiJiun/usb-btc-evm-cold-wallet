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

VERSION = 2
FORMAT = "usb-cold-wallet-exchange"
LABEL = "TX_TRANSFER"
BASE_DIR = ".usb-cold-wallet"
EXCHANGE_DIR = "exchange"
ONLINE_STATE_DIR = "state/online"
WATCH_FILE = "watch-only.json"
MAX_BYTES = 200_000
REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
REQUEST_FIELDS = {
    "format", "version", "kind", "network", "requestId", "account",
    "transactionDigest", "intent", "expiry", "payload", "sha256",
}
RESPONSE_FIELDS = {
    "format", "version", "kind", "network", "requestId", "account",
    "transactionDigest", "requestEnvelopeDigest", "signedResultDigest",
    "expiryAssurance", "payload", "sha256",
}
NETWORK = {"evm-request": "sepolia", "btc-request": "bitcoin-testnet"}
RESPONSE_KIND = {"evm-request": "evm-signed", "btc-request": "btc-signed"}
ACTIVE_STATES = {"DRAFT", "EXPORTED", "IMPORTED_VERIFIED"}


def _sha(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _envelope_sha(value: dict) -> str:
    return _sha({k: v for k, v in value.items() if k != "sha256"})


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


def _parse_psbt(value: str):
    if not isinstance(value, str) or not value or len(value) > 180_000:
        raise ValueError("BTC PSBT size invalid")
    try:
        raw = base64.b64decode(value, validate=True)
        parsed = psbt.PSBT.parse(raw)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("BTC PSBT invalid") from exc
    except Exception as exc:
        raise ValueError("BTC PSBT cannot be parsed") from exc
    if not raw.startswith(b"psbt\xff") or parsed.version is not None or parsed.serialize() != raw:
        raise ValueError("BTC PSBT must be canonical v0")
    return parsed, raw


def _evm_intent(payload: dict, recipient: str, amount: int) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("EVM request payload invalid")
    required = {"type", "chainId", "nonce", "to", "value", "gas",
                "maxFeePerGas", "maxPriorityFeePerGas"}
    if required - payload.keys() or set(payload) - required - {"data", "accessList"}:
        raise ValueError("Unsupported EVM request fields")
    if payload["type"] != 2 or payload["chainId"] != 11155111:
        raise ValueError("Sepolia EIP-1559 request required")
    for field in ("nonce", "value", "gas", "maxFeePerGas", "maxPriorityFeePerGas"):
        if type(payload[field]) is not int or payload[field] < 0:
            raise ValueError(f"Invalid EVM {field}")
    if payload["gas"] != 21_000 or payload["maxFeePerGas"] < payload["maxPriorityFeePerGas"]:
        raise ValueError("Unsupported EVM gas policy")
    if payload.get("data", "0x") not in ("", "0x") or payload.get("accessList", []) != []:
        raise ValueError("Contract data/access list is not supported")
    try:
        actual = to_checksum_address(payload["to"])
        expected = to_checksum_address(recipient)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid EVM recipient") from exc
    if actual != expected or type(amount) is not int or payload["value"] != amount:
        raise ValueError("EVM recipient/amount mismatch")
    return {
        "recipient": actual,
        "amount": amount,
        "fee": payload["gas"] * payload["maxFeePerGas"],
        "nonce": payload["nonce"],
        "utxos": [],
    }


def _btc_intent(payload: str, account: str, recipient: str, amount: int) -> dict:
    parsed, _raw = _parse_psbt(payload)
    if not re.fullmatch(r"^[0-9a-f]{8}$", account or ""):
        raise ValueError("BTC account fingerprint invalid")
    if not 1 <= len(parsed.inputs) <= 20:
        raise ValueError("BTC input count out of bounds")
    input_total = 0
    utxos = []
    for index, scope in enumerate(parsed.inputs):
        if scope.witness_utxo is None or scope.non_witness_utxo is None:
            raise ValueError("BTC request requires witness and non-witness UTXO")
        vin = parsed.tx.vin[index]
        if scope.non_witness_utxo.txid() != vin.txid or not 0 <= vin.vout < len(scope.non_witness_utxo.vout):
            raise ValueError("BTC previous transaction mismatch")
        prev = scope.non_witness_utxo.vout[vin.vout]
        if (prev.value != scope.witness_utxo.value
                or prev.script_pubkey.data != scope.witness_utxo.script_pubkey.data):
            raise ValueError("BTC UTXO metadata mismatch")
        if len(scope.bip32_derivations) != 1:
            raise ValueError("BTC request needs one BIP32 origin per input")
        origin = next(iter(scope.bip32_derivations.values()))
        if origin.fingerprint.hex() != account:
            raise ValueError("BTC input account fingerprint mismatch")
        input_total += prev.value
        utxos.append({"txid": vin.txid.hex(), "vout": vin.vout, "value": prev.value})
    output_total = sum(out.value for out in parsed.tx.vout)
    fee = input_total - output_total
    if fee < 0:
        raise ValueError("BTC request has negative fee")
    hits = 0
    for out in parsed.tx.vout:
        try:
            address = out.script_pubkey.address(networks.NETWORKS["test"])
        except Exception:
            continue
        if address == recipient and out.value == amount:
            hits += 1
    if hits != 1:
        raise ValueError("BTC recipient/amount must occur exactly once")
    return {"recipient": recipient, "amount": amount, "fee": fee, "nonce": None, "utxos": utxos}


def _transaction_digest(kind: str, payload) -> str:
    if kind == "btc-request":
        _parsed, raw = _parse_psbt(payload)
        return hashlib.sha256(raw).hexdigest()
    return hashlib.sha256(canonical(payload)).hexdigest()


def _package_request(kind: str, payload, *, request_id: str, account: str,
                     recipient: str, amount: int) -> dict:
    if kind not in NETWORK or REQUEST_ID_RE.fullmatch(request_id or "") is None:
        raise ValueError("Invalid v2 request kind or Request ID")
    if kind == "evm-request":
        try:
            account = to_checksum_address(account)
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid EVM request account") from exc
        intent = _evm_intent(payload, recipient, amount)
    else:
        if not re.fullmatch(r"^[0-9a-f]{8}$", account or ""):
            raise ValueError("Invalid BTC request account")
        intent = _btc_intent(payload, account, recipient, amount)
    content = {
        "format": FORMAT,
        "version": VERSION,
        "kind": kind,
        "network": NETWORK[kind],
        "requestId": request_id,
        "account": account,
        "transactionDigest": _transaction_digest(kind, payload),
        "intent": intent,
        "expiry": {"mode": "no-trusted-clock", "notAfter": None},
        "payload": payload,
    }
    return {**content, "sha256": _sha(content)}


def _verify_request_public(data: dict, expected_kind: str | None = None, *,
                           expected_account: str | None = None,
                           trusted_time=None, allow_no_trusted_clock: bool = False) -> dict:
    if type(data) is not dict or set(data) != REQUEST_FIELDS:
        raise ValueError("Invalid v2 request envelope fields")
    kind = data.get("kind")
    if (data.get("format") != FORMAT or data.get("version") != VERSION or kind not in NETWORK
            or data.get("network") != NETWORK[kind]
            or (expected_kind is not None and expected_kind != kind)
            or REQUEST_ID_RE.fullmatch(data.get("requestId", "")) is None):
        raise ValueError("V2 request format/type/network mismatch")
    account = data.get("account")
    if kind == "evm-request":
        try:
            if to_checksum_address(account) != account:
                raise ValueError("EVM request account must be checksummed")
        except Exception as exc:
            raise ValueError("Invalid EVM request account") from exc
    elif not re.fullmatch(r"^[0-9a-f]{8}$", account or ""):
        raise ValueError("Invalid BTC request account")
    if expected_account is not None and account != expected_account:
        raise ValueError("V2 request account does not match expected wallet")
    expiry = data.get("expiry")
    if expiry != {"mode": "no-trusted-clock", "notAfter": None} or not allow_no_trusted_clock:
        raise ValueError("Cross-boot Companion requires explicit no-trusted-clock restricted mode")
    intent = data.get("intent")
    if type(intent) is not dict:
        raise ValueError("Invalid v2 request intent")
    derived = (_evm_intent(data["payload"], intent.get("recipient"), intent.get("amount"))
               if kind == "evm-request"
               else _btc_intent(data["payload"], account, intent.get("recipient"), intent.get("amount")))
    if intent != derived:
        raise ValueError("V2 request intent does not match raw transaction")
    digest = _transaction_digest(kind, data["payload"])
    if not hmac.compare_digest(data.get("transactionDigest", ""), digest):
        raise ValueError("V2 request transaction digest mismatch")
    if not hmac.compare_digest(data.get("sha256", ""), _envelope_sha(data)):
        raise ValueError("V2 request envelope integrity check failed")
    return {**data, "expiryAssurance": "unverified"}


def _verify_response_public(request: dict, response: dict, *, expected_account: str | None = None,
                            trusted_time=None, allow_no_trusted_clock: bool = False) -> dict:
    checked = _verify_request_public(
        request, expected_account=expected_account,
        trusted_time=trusted_time, allow_no_trusted_clock=allow_no_trusted_clock,
    )
    if type(response) is not dict or set(response) != RESPONSE_FIELDS:
        raise ValueError("Invalid v2 signed response fields")
    expected_kind = RESPONSE_KIND[request["kind"]]
    if (response.get("format") != FORMAT or response.get("version") != VERSION
            or response.get("kind") != expected_kind or response.get("network") != request["network"]
            or response.get("requestId") != request["requestId"]
            or response.get("account") != request["account"]
            or response.get("transactionDigest") != request["transactionDigest"]
            or response.get("expiryAssurance") != checked["expiryAssurance"]):
        raise ValueError("Signed response does not match pending request")
    for field in ("requestEnvelopeDigest", "signedResultDigest", "sha256"):
        if not isinstance(response.get(field), str) or HEX64_RE.fullmatch(response[field]) is None:
            raise ValueError(f"Invalid signed response {field}")
    if not hmac.compare_digest(response["requestEnvelopeDigest"], _sha(request)):
        raise ValueError("Signed response request digest mismatch")
    if not hmac.compare_digest(response["signedResultDigest"], _sha(response["payload"])):
        raise ValueError("Signed response result digest mismatch")
    if not hmac.compare_digest(response["sha256"], _envelope_sha(response)):
        raise ValueError("Signed response envelope integrity check failed")
    return response["payload"]


def _windows_volume_label(root: str) -> str:
    kernel = ctypes.windll.kernel32
    label = ctypes.create_unicode_buffer(261)
    fsname = ctypes.create_unicode_buffer(261)
    serial = ctypes.c_ulong()
    max_component = ctypes.c_ulong()
    flags = ctypes.c_ulong()
    ok = kernel.GetVolumeInformationW(
        ctypes.c_wchar_p(root), label, len(label), ctypes.byref(serial),
        ctypes.byref(max_component), ctypes.byref(flags), fsname, len(fsname)
    )
    return label.value if ok else ""


def discover_windows_exchange_root() -> Path:
    if os.name != "nt":
        raise ValueError("Automatic TX_TRANSFER discovery requires Windows")
    kernel = ctypes.windll.kernel32
    mask = kernel.GetLogicalDrives()
    if not mask:
        raise ValueError("Windows drive enumeration failed")
    matches = []
    for index in range(26):
        if not mask & (1 << index):
            continue
        root = f"{chr(65 + index)}:\\"
        if kernel.GetDriveTypeW(ctypes.c_wchar_p(root)) not in (2, 3):
            continue
        if _windows_volume_label(root) == LABEL:
            matches.append(Path(root))
    if len(matches) != 1:
        raise ValueError("TX_TRANSFER unavailable or ambiguous; exactly one labelled volume is required")
    return matches[0]


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
        btc_session.pending = {
            "stage": "prepared", "request_id": request["requestId"],
            "digest": request["transactionDigest"], "psbt_base64": request["payload"],
            "recipient": intent["recipient"], "amount_sats": intent["amount"],
            "fee_sats": intent["fee"], "fee_rate": None,
            "change_sats": input_total - intent["amount"] - intent["fee"],
            "change_index": None, "input_count": len(parsed.inputs), "unsigned": parsed,
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
                # Crash after publish but before DRAFT journal append.
                store.create(request)
                store.exported(request)
                active.append(request_id)
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
        if snap.state in {"IMPORTED_VERIFIED", "FAILED"}:
            response = _read_json(self._response_path(request_id))
            payload = _verify_response_public(
                request, response, expected_account=expected, allow_no_trusted_clock=True
            )
            owner.accept_signed(canonical(payload))
            if snap.state == "FAILED":
                if "broadcast outcome unknown" not in snap.metadata.get("reason", ""):
                    raise ValueError("Failed request is not recoverable")
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

    def mark_broadcasted(self, session, btc_session, txid: str) -> None:
        request, _owner, _asset = self._request_from_any(session, btc_session)
        snap = self._store().get(request["requestId"])
        if snap is None or snap.state != "IMPORTED_VERIFIED":
            raise ValueError("Broadcast result is not bound to IMPORTED_VERIFIED state")
        self._store().broadcasted(request, txid)
        self._cleanup_files(request["requestId"])

    def mark_failed(self, session, btc_session, reason: str) -> None:
        try:
            request, _owner, _asset = self._request_from_any(session, btc_session)
        except ValueError:
            return
        snap = self._store().get(request["requestId"])
        if snap is not None and snap.state in {"DRAFT", "EXPORTED", "IMPORTED_VERIFIED"}:
            text = reason[:256] or "failed"
            self._store().failed(request, text)
            if "broadcast outcome unknown" not in text:
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
