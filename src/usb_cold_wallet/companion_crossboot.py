"""Single-USB Windows/Offline cross-boot state.

Canonical transaction bytes stay in the existing exchange envelope. This file
only persists public Companion state across Windows/process reboots.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
from pathlib import Path

from .btc import _read_psbt
from .companion_core import canonical, pack_envelope, unpack_envelope

STATE_FORMAT = "usb-cold-wallet-companion-state"
STATE_VERSION = 1
STATE_DIR = ".usb-cold-wallet"
EXCHANGE_DIR = "exchange"
STATE_NAME = "pending-state.json"
LABEL = "TX_TRANSFER"
ID_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_STATE_BYTES = 450_000
STAGES = {"prepared", "verified", "broadcast_unknown", "broadcasted"}


def _json_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _atomic_replace(path: Path, data: bytes) -> None:
    if not data or len(data) > MAX_STATE_BYTES:
        raise ValueError("Cross-boot state size invalid")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name("." + path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise OSError("Short state write")
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    try:
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except OSError:
        # Windows/FAT commonly does not expose directory fsync.
        pass


def _read_json(path: Path):
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError("Cross-boot state unreadable") from exc
    if not raw or len(raw) > MAX_STATE_BYTES:
        raise ValueError("Cross-boot state size invalid")
    try:
        return json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Cross-boot state invalid JSON") from exc


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
        raise ValueError(
            "TX_TRANSFER exchange partition unavailable or ambiguous; "
            "exactly one labelled volume is required"
        )
    return matches[0]


class CrossBootManager:
    def __init__(self, root: Path | None, error: str | None = None):
        self.root = Path(root) if root is not None else None
        self.error = error
        self.base = self.root / STATE_DIR if self.root else None
        self.exchange = self.base / EXCHANGE_DIR if self.base else None
        self.state_path = self.base / STATE_NAME if self.base else None

    @classmethod
    def auto(cls, explicit_root: str | Path | None = None):
        if explicit_root is not None:
            root = Path(explicit_root)
            if root.is_dir():
                return cls(root)
            return cls(None, "Configured exchange root does not exist")
        try:
            return cls(discover_windows_exchange_root())
        except ValueError as exc:
            return cls(None, str(exc))

    @property
    def available(self) -> bool:
        return self.root is not None

    def _require(self) -> None:
        if not self.available:
            raise ValueError(self.error or "TX_TRANSFER exchange partition unavailable")

    @staticmethod
    def _request_id(pending) -> str:
        request_id = pending.get("request_id", "") if pending else ""
        if not ID_RE.fullmatch(request_id):
            raise ValueError("Pending Request ID invalid")
        return request_id

    def _evm_state(self, session):
        p = session.pending
        if p is None:
            return None
        if p.get("stage") not in STAGES:
            raise ValueError("Invalid EVM pending stage")
        request_id = self._request_id(p)
        tx = p.get("tx")
        request = p.get("envelope") or pack_envelope("evm-request", tx)
        if unpack_envelope(request, "evm-request") != tx:
            raise ValueError("EVM request envelope mismatch")
        digest = hashlib.sha256(canonical(tx)).hexdigest()
        if digest != p.get("digest"):
            raise ValueError("EVM request digest mismatch")
        state = {
            "request_id": request_id, "digest": digest, "stage": p["stage"],
            "request": request,
        }
        if p.get("response_envelope") is not None:
            state["response"] = p["response_envelope"]
        for key in ("result", "reorg_warning", "block_number"):
            if key in p:
                state[key] = p[key]
        return state

    def _btc_state(self, btc_session):
        p = btc_session.pending
        if p is None:
            return None
        if p.get("stage") not in STAGES:
            raise ValueError("Invalid BTC pending stage")
        request_id = self._request_id(p)
        unsigned = _read_psbt(p.get("psbt_base64"))
        digest = hashlib.sha256(unsigned.serialize()).hexdigest()
        if digest != p.get("digest"):
            raise ValueError("BTC request digest mismatch")
        state = {
            key: p.get(key) for key in (
                "stage", "digest", "psbt_base64", "recipient", "amount_sats",
                "fee_sats", "fee_rate", "change_sats", "change_index", "input_count",
                "result", "reorg_warning",
            )
        }
        state["request_id"] = request_id
        state["request"] = pack_envelope("btc-request", p["psbt_base64"])
        if p.get("response_envelope") is not None:
            state["response"] = p["response_envelope"]
        return state

    def save(self, session, btc_session) -> None:
        self._require()
        wallet = session.wallet
        if wallet is not None:
            pack_envelope("watch-only", wallet)
        content = {
            "format": STATE_FORMAT, "version": STATE_VERSION, "wallet": wallet,
            "evm": self._evm_state(session), "btc": self._btc_state(btc_session),
        }
        body = _json_bytes(content)
        doc = {**content, "sha256": hashlib.sha256(body).hexdigest()}
        _atomic_replace(self.state_path, _json_bytes(doc) + b"\n")

    def restore(self, session, btc_session) -> bool:
        self._require()
        if not self.state_path.exists():
            return False
        doc = _read_json(self.state_path)
        required = {"format", "version", "wallet", "evm", "btc", "sha256"}
        if set(doc) != required:
            raise ValueError("Unexpected cross-boot state fields")
        content = {k: doc[k] for k in ("format", "version", "wallet", "evm", "btc")}
        if doc["format"] != STATE_FORMAT or doc["version"] != STATE_VERSION:
            raise ValueError("Unsupported cross-boot state version")
        if hashlib.sha256(_json_bytes(content)).hexdigest() != doc["sha256"]:
            raise ValueError("Cross-boot state checksum mismatch")

        wallet = doc["wallet"]
        if wallet is not None:
            pack_envelope("watch-only", wallet)
            session.wallet = wallet
            btc_session.import_wallet(wallet)

        evm = doc["evm"]
        if evm is not None:
            tx = unpack_envelope(evm["request"], "evm-request")
            digest = hashlib.sha256(canonical(tx)).hexdigest()
            if digest != evm.get("digest") or tx.get("chainId") != 11155111:
                raise ValueError("Restored EVM request binding mismatch")
            request_id = self._request_id(evm)
            session.pending = {
                "request_id": request_id, "digest": digest, "tx": tx,
                "stage": "prepared", "envelope": evm["request"],
            }
            if evm.get("response") is not None:
                session.accept_signed(_json_bytes(evm["response"]))
            stage = evm.get("stage")
            if stage not in STAGES:
                raise ValueError("Restored EVM stage invalid")
            if stage != "prepared":
                if session.pending.get("stage") != "verified":
                    raise ValueError("Restored EVM response did not re-verify")
                session.pending["stage"] = stage
                for key in ("result", "reorg_warning", "block_number"):
                    if key in evm:
                        session.pending[key] = evm[key]

        btc = doc["btc"]
        if btc is not None:
            b64 = unpack_envelope(btc["request"], "btc-request")
            unsigned = _read_psbt(b64)
            digest = hashlib.sha256(unsigned.serialize()).hexdigest()
            if digest != btc.get("digest"):
                raise ValueError("Restored BTC request binding mismatch")
            request_id = self._request_id(btc)
            pending = {
                "stage": "prepared", "request_id": request_id, "digest": digest,
                "psbt_base64": b64, "recipient": btc.get("recipient"),
                "amount_sats": btc.get("amount_sats"), "fee_sats": btc.get("fee_sats"),
                "fee_rate": btc.get("fee_rate"), "change_sats": btc.get("change_sats"),
                "change_index": btc.get("change_index"),
                "input_count": btc.get("input_count"), "unsigned": unsigned,
            }
            if (not isinstance(pending["recipient"], str)
                    or type(pending["amount_sats"]) is not int
                    or type(pending["fee_sats"]) is not int
                    or type(pending["input_count"]) is not int):
                raise ValueError("Restored BTC intent metadata invalid")
            btc_session.pending = pending
            if btc.get("response") is not None:
                btc_session.accept_signed(_json_bytes(btc["response"]))
            stage = btc.get("stage")
            if stage not in STAGES:
                raise ValueError("Restored BTC stage invalid")
            if stage != "prepared":
                if btc_session.pending.get("stage") != "verified":
                    raise ValueError("Restored BTC response did not re-verify")
                btc_session.pending["stage"] = stage
                for key in ("result", "reorg_warning"):
                    if key in btc:
                        btc_session.pending[key] = btc[key]
        return True

    @staticmethod
    def _active(session, btc_session):
        candidates = []
        if session.pending is not None:
            candidates.append(("sepolia", session, session.pending))
        if btc_session.pending is not None:
            candidates.append(("bitcoin-testnet", btc_session, btc_session.pending))
        if len(candidates) != 1:
            raise ValueError("Exactly one pending BTC or Sepolia transaction is required")
        return candidates[0]

    def export_current(self, session, btc_session) -> dict:
        self._require()
        _asset, owner, pending = self._active(session, btc_session)
        if pending.get("stage") != "prepared":
            raise ValueError("Only prepared requests can be exported")
        request_id = self._request_id(pending)
        self.exchange.mkdir(parents=True, exist_ok=True)
        others = [p for p in self.exchange.glob("request-*.json")
                  if p.name != f"request-{request_id}.json"]
        if others:
            raise ValueError("Another pending request already exists on TX_TRANSFER")
        _atomic_replace(
            self.exchange / f"request-{request_id}.json",
            _json_bytes(owner.request_envelope()) + b"\n",
        )
        self.save(session, btc_session)
        return self.status(session, btc_session)

    def resume_response(self, session, btc_session) -> dict:
        self._require()
        _asset, owner, pending = self._active(session, btc_session)
        if pending.get("stage") != "prepared":
            return self.status(session, btc_session)
        request_id = self._request_id(pending)
        exact = self.exchange / f"response-{request_id}.json"
        candidates = list(self.exchange.glob(f"response-{request_id}*.json"))
        if len(candidates) != 1 or candidates[0] != exact:
            raise ValueError("Signed response missing or ambiguous for this Request ID")
        raw = exact.read_bytes()
        if not raw or len(raw) > 220_000:
            raise ValueError("Signed response size invalid")
        owner.accept_signed(raw)
        self.save(session, btc_session)
        return self.status(session, btc_session)

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
            "guidance": (
                "建立交易後儲存到單 USB，完全關閉 Companion，重新開機並在 UEFI 選擇此 USB；"
                "離線 GUI 解鎖、完整核對並人工簽署後關機，返回 Windows 再啟動 Companion。"
                "回覆只會自動驗證，Broadcast 永遠需要人工確認。"
            ),
        }
        if not self.available or session is None or btc_session is None:
            return result
        try:
            asset, _owner, pending = self._active(session, btc_session)
        except ValueError:
            return result
        request_id = pending.get("request_id")
        result.update({
            "asset": asset, "request_id": request_id, "stage": pending.get("stage"),
            "can_export": pending.get("stage") == "prepared",
        })
        if pending.get("stage") == "prepared":
            result["can_resume"] = (
                self.exchange / f"response-{request_id}.json"
            ).is_file()
        return result
