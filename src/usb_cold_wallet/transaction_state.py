"""Crash-recoverable cross-boot transaction state journals.

State is intentionally split by authority.  Online state never authorizes cold
signing; cold state never authorizes online broadcast.  Journal hashes detect
corruption/forks within the currently visible history, but without an external
monotonic anchor they cannot prove that an attacker did not roll the whole
store back.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _official_verifier(name: str):
    # Keep offline signer/secret-key dependencies out of Windows journal imports.
    module = importlib.import_module("." + "cross_boot", __package__)
    return getattr(module, name)


FORMAT = "usb-cold-wallet-cross-boot-state"
VERSION = 1
MAX_RECORD_BYTES = 16384
MAX_RECORDS = 4096

ONLINE_STATES = {"DRAFT", "EXPORTED", "IMPORTED_VERIFIED", "BROADCAST_REQUESTED", "BROADCASTED", "FAILED"}
COLD_STATES = {"COLD_REVIEWED", "SIGNED", "FAILED"}
ONLINE_TRANSITIONS = {
    None: {"DRAFT"},
    "DRAFT": {"EXPORTED", "FAILED"},
    "EXPORTED": {"IMPORTED_VERIFIED", "FAILED"},
    "IMPORTED_VERIFIED": {"BROADCAST_REQUESTED", "FAILED"},
    "BROADCAST_REQUESTED": {"BROADCASTED"},
    "BROADCASTED": set(),
    "FAILED": set(),
}
COLD_TRANSITIONS = {
    None: {"COLD_REVIEWED"},
    "COLD_REVIEWED": {"SIGNED", "FAILED"},
    "SIGNED": set(),
    "FAILED": set(),
}
_RECORD_RE = re.compile(r"^(?P<request>[0-9a-f]{32})\.(?P<counter>[0-9]{8})\.(?P<digest>[0-9a-f]{64})\.json$")


class StateCorruptionError(ValueError):
    pass


class RollbackDetected(StateCorruptionError):
    pass


@dataclass(frozen=True)
class StateSnapshot:
    owner: str
    request_id: str
    state: str
    counter: int
    request_digest: str
    transaction_digest: str
    record_digest: str
    previous_digest: str | None
    metadata: dict


def _strict_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise StateCorruptionError("Duplicate JSON key in state record")
        out[key] = value
    return out


def _digest_record(content: dict) -> str:
    return hashlib.sha256(_canonical(content)).hexdigest()


def _bounded_read(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise StateCorruptionError("State journal entry is not a regular file")
        raw = os.read(fd, MAX_RECORD_BYTES + 1)
        if len(raw) > MAX_RECORD_BYTES:
            raise StateCorruptionError("State journal entry too large")
        return raw
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError("Short write while persisting transaction state")
        offset += written
    os.fsync(fd)


def _append_windows(root: Path, name: str, raw: bytes) -> None:
    """Create-only Windows journal append.

    NTFS os.rename fails when the destination exists. A crash may leave a
    .partial file; readers ignore bounded .partial files and keep the last
    fully published immutable record.
    """
    import secrets

    stage = root / f".{name}.{secrets.token_hex(8)}.partial"
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _write_all(fd, raw)
    finally:
        os.close(fd)
    try:
        os.rename(stage, root / name)
    except Exception:
        try:
            stage.unlink()
        except OSError:
            pass
        raise


def _append_posix(root: Path, name: str, raw: bytes) -> None:
    vault = importlib.import_module("." + "vault", __package__)

    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        vault.atomic_create_at(parent, name, raw)
    finally:
        os.close(parent)


def _append(root: Path, name: str, raw: bytes) -> None:
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("State record too large")
    if os.name == "nt":
        _append_windows(root, name, raw)
    else:
        _append_posix(root, name, raw)


class _Journal:
    def __init__(self, root: Path, owner: str, *, expected_tip: str | None = None):
        if owner not in {"online", "cold"}:
            raise ValueError("Invalid state owner")
        self.root = Path(root)
        self.owner = owner
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            self.root.chmod(0o700)
        self._records, self.recovery_warnings = self._load()
        self._validate_chains()
        if expected_tip is not None:
            if HEX64_RE.fullmatch(expected_tip) is None:
                raise ValueError("Invalid expected state anchor")
            if self.tip_anchor() != expected_tip:
                raise RollbackDetected("State journal tip differs from externally pinned anchor")

    @contextmanager
    def _locked(self):
        """Serialize state transitions across processes on the same journal root."""
        path = self.root / ".journal.lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise StateCorruptionError("State lock is not a regular file")
            if os.name == "nt":
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    _write_all(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _reload(self):
        # A live process can detect the disappearance/rewrite of previously
        # observed records even if no external monotonic anchor is configured.
        observed = {
            (entry["requestId"], entry["counter"], entry["recordDigest"])
            for entry in self._records
        }
        updated, warnings = self._load()
        available = {
            (entry["requestId"], entry["counter"], entry["recordDigest"])
            for entry in updated
        }
        if not observed.issubset(available):
            raise RollbackDetected("Previously observed journal history was removed or rewritten")
        self._records, self.recovery_warnings = updated, warnings
        self._validate_chains()

    def _load(self):
        records = []
        warnings = []
        entries = list(os.scandir(self.root))
        if len(entries) > MAX_RECORDS * 2:
            raise StateCorruptionError("Too many state journal entries")
        for entry in entries:
            name = entry.name
            if name == ".journal.lock":
                if not entry.is_file(follow_symlinks=False):
                    raise StateCorruptionError("Invalid state lock file")
                continue
            if name.startswith(".") and name.endswith(".partial"):
                if entry.is_file(follow_symlinks=False):
                    warnings.append(f"incomplete:{name}")
                    continue
                raise StateCorruptionError("Invalid partial journal entry")
            match = _RECORD_RE.fullmatch(name)
            if match is None:
                raise StateCorruptionError("Unexpected file in state journal")
            if not entry.is_file(follow_symlinks=False):
                raise StateCorruptionError("State journal entry must be a regular file")
            try:
                data = json.loads(
                    _bounded_read(Path(entry.path)).decode("utf-8"),
                    object_pairs_hook=_strict_object,
                    parse_constant=lambda _: (_ for _ in ()).throw(
                        StateCorruptionError("Non-finite JSON in state record")
                    ),
                )
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise StateCorruptionError("Corrupt state journal JSON") from exc
            records.append(self._parse_record(data, match))
        if len(records) > MAX_RECORDS:
            raise StateCorruptionError("Too many state records")
        return records, warnings

    def _parse_record(self, data: Any, match) -> dict:
        fields = {
            "format", "version", "owner", "requestId", "state", "counter",
            "previousDigest", "requestDigest", "transactionDigest", "metadata",
            "recordDigest",
        }
        if type(data) is not dict or set(data) != fields:
            raise StateCorruptionError("Invalid state record fields")
        if data["format"] != FORMAT or data["version"] != VERSION or data["owner"] != self.owner:
            raise StateCorruptionError("State record format/owner mismatch")
        if REQUEST_ID_RE.fullmatch(data["requestId"] or "") is None:
            raise StateCorruptionError("Invalid state requestId")
        if type(data["counter"]) is not int or not 1 <= data["counter"] <= MAX_RECORDS:
            raise StateCorruptionError("Invalid state counter")
        for field in ("requestDigest", "transactionDigest", "recordDigest"):
            if type(data[field]) is not str or HEX64_RE.fullmatch(data[field]) is None:
                raise StateCorruptionError(f"Invalid {field}")
        if data["previousDigest"] is not None and (
            type(data["previousDigest"]) is not str or HEX64_RE.fullmatch(data["previousDigest"]) is None
        ):
            raise StateCorruptionError("Invalid previous state digest")
        if type(data["metadata"]) is not dict:
            raise StateCorruptionError("State metadata must be an object")
        content = {key: value for key, value in data.items() if key != "recordDigest"}
        digest = _digest_record(content)
        if data["recordDigest"] != digest:
            raise StateCorruptionError("State record digest mismatch")
        if (match.group("request") != data["requestId"] or
                int(match.group("counter")) != data["counter"] or
                match.group("digest") != digest):
            raise StateCorruptionError("State filename does not match record")
        return data

    def _validate_chains(self) -> None:
        grouped = {}
        for record in self._records:
            grouped.setdefault(record["requestId"], []).append(record)
        transitions = ONLINE_TRANSITIONS if self.owner == "online" else COLD_TRANSITIONS
        allowed_states = ONLINE_STATES if self.owner == "online" else COLD_STATES
        for request_id, records in grouped.items():
            records.sort(key=lambda item: item["counter"])
            expected_counter = 1
            previous = None
            request_digest = records[0]["requestDigest"]
            tx_digest = records[0]["transactionDigest"]
            previous_state = None
            for record in records:
                if record["state"] not in allowed_states:
                    raise StateCorruptionError("State belongs to the wrong owner")
                if record["counter"] != expected_counter or record["previousDigest"] != previous:
                    raise StateCorruptionError("State journal chain has a gap or fork")
                if (record["requestDigest"] != request_digest or
                        record["transactionDigest"] != tx_digest):
                    raise StateCorruptionError("Immutable request binding changed in state journal")
                if record["state"] not in transitions[previous_state]:
                    raise StateCorruptionError("Invalid persisted state transition")
                previous = record["recordDigest"]
                previous_state = record["state"]
                expected_counter += 1

    def _for_request(self, request_id: str) -> list[dict]:
        return sorted(
            [record for record in self._records if record["requestId"] == request_id],
            key=lambda item: item["counter"],
        )

    def get(self, request_id: str) -> StateSnapshot | None:
        if REQUEST_ID_RE.fullmatch(request_id or "") is None:
            raise ValueError("Invalid requestId")
        records = self._for_request(request_id)
        if not records:
            return None
        record = records[-1]
        return StateSnapshot(
            owner=self.owner,
            request_id=request_id,
            state=record["state"],
            counter=record["counter"],
            request_digest=record["requestDigest"],
            transaction_digest=record["transactionDigest"],
            record_digest=record["recordDigest"],
            previous_digest=record["previousDigest"],
            metadata=copy.deepcopy(record["metadata"]),
        )

    def _transition(
        self,
        request_id: str,
        state: str,
        request_digest: str,
        transaction_digest: str,
        metadata: dict | None = None,
    ) -> StateSnapshot:
        with self._locked():
            return self._transition_locked(
                request_id, state, request_digest, transaction_digest, metadata
            )

    def _transition_locked(
        self, request_id: str, state: str, request_digest: str,
        transaction_digest: str, metadata: dict | None = None,
    ) -> StateSnapshot:
        self._reload()
        if state == "BROADCAST_REQUESTED" and self.recovery_warnings:
            raise StateCorruptionError("Unresolved journal write; broadcast is blocked")
        if REQUEST_ID_RE.fullmatch(request_id or "") is None:
            raise ValueError("Invalid requestId")
        for value, label in ((request_digest, "request digest"), (transaction_digest, "transaction digest")):
            if type(value) is not str or HEX64_RE.fullmatch(value) is None:
                raise ValueError(f"Invalid {label}")
        metadata = {} if metadata is None else metadata
        if type(metadata) is not dict:
            raise ValueError("State metadata must be an object")
        metadata = copy.deepcopy(metadata)
        current = self.get(request_id)
        transitions = ONLINE_TRANSITIONS if self.owner == "online" else COLD_TRANSITIONS
        previous_state = None if current is None else current.state
        if state not in transitions[previous_state]:
            raise ValueError(f"Invalid {self.owner} state transition {previous_state!r} -> {state}")
        if current is not None and (
            current.request_digest != request_digest or current.transaction_digest != transaction_digest
        ):
            raise ValueError("State transition changed immutable request binding")
        counter = 1 if current is None else current.counter + 1
        previous_digest = None if current is None else current.record_digest
        content = {
            "format": FORMAT,
            "version": VERSION,
            "owner": self.owner,
            "requestId": request_id,
            "state": state,
            "counter": counter,
            "previousDigest": previous_digest,
            "requestDigest": request_digest,
            "transactionDigest": transaction_digest,
            "metadata": metadata,
        }
        digest = _digest_record(content)
        record = {**content, "recordDigest": digest}
        name = f"{request_id}.{counter:08d}.{digest}.json"
        raw = _canonical(record) + b"\n"
        _append(self.root, name, raw)
        self._records.append(record)
        return self.get(request_id)

    def tip_anchor(self) -> str:
        """Digest the visible immutable journal tips for optional external pinning."""
        tips = []
        request_ids = sorted({record["requestId"] for record in self._records})
        for request_id in request_ids:
            snap = self.get(request_id)
            tips.append([request_id, snap.counter, snap.record_digest])
        return hashlib.sha256(_canonical(tips)).hexdigest()

    @property
    def rollback_resistant(self) -> bool:
        # A local hash chain cannot distinguish a whole-store rollback.
        return False


class PendingRequestStore(_Journal):
    def __init__(self, root: Path, *, expected_tip: str | None = None):
        super().__init__(root, "online", expected_tip=expected_tip)

    def create(self, request: dict) -> StateSnapshot:
        return self._transition(
            request["requestId"], "DRAFT", request["sha256"], request["transactionDigest"],
            {"network": request["network"], "account": request["account"]},
        )

    def exported(self, request: dict) -> StateSnapshot:
        return self._transition(
            request["requestId"], "EXPORTED", request["sha256"], request["transactionDigest"]
        )

    def import_verified(
        self,
        request: dict,
        response: dict,
        *,
        trusted_time: int | None = None,
        allow_no_trusted_clock: bool = False,
        verifier=None,
    ) -> StateSnapshot:
        current = self.get(request["requestId"])
        expected_account = current.metadata.get("account") if current is not None else None
        verify = verifier or _official_verifier("verify_v2_response")
        verify(
            request,
            response,
            expected_account=expected_account,
            trusted_time=trusted_time,
            allow_no_trusted_clock=allow_no_trusted_clock,
        )
        return self._transition(
            request["requestId"], "IMPORTED_VERIFIED", request["sha256"],
            request["transactionDigest"], {"responseDigest": response["sha256"]},
        )

    def broadcast_requested(self, request: dict, txid: str) -> StateSnapshot:
        """Durably reserve the single allowed broadcast attempt BEFORE network I/O.

        After a crash or an ambiguous network result, do not resubmit. Query
        the chain by txid and reconcile this record only after confirmation.
        """
        self._check_broadcast_txid(request, txid)
        return self._transition(
            request["requestId"], "BROADCAST_REQUESTED", request["sha256"],
            request["transactionDigest"], {"txid": txid},
        )

    @staticmethod
    def _check_broadcast_txid(request: dict, txid: str) -> None:
        if type(txid) is not str:
            raise ValueError("Invalid broadcast transaction id")
        network = request.get("network")
        if network == "sepolia":
            match = re.fullmatch(r"0x[0-9a-f]{64}", txid)
        elif network == "bitcoin-testnet":
            match = HEX64_RE.fullmatch(txid)
        else:
            raise ValueError("Invalid broadcast network")
        if match is None:
            raise ValueError("Invalid broadcast transaction id")

    def broadcasted(self, request: dict, txid: str) -> StateSnapshot:
        self._check_broadcast_txid(request, txid)
        current = self.get(request["requestId"])
        if (current is None or current.state != "BROADCAST_REQUESTED" or
                current.metadata.get("txid") != txid):
            raise ValueError("Broadcast result must match a durable pre-broadcast reservation")
        return self._transition(
            request["requestId"], "BROADCASTED", request["sha256"],
            request["transactionDigest"], {"txid": txid},
        )

    def failed(self, request: dict, reason: str) -> StateSnapshot:
        if type(reason) is not str or not 1 <= len(reason) <= 256:
            raise ValueError("Invalid failure reason")
        return self._transition(
            request["requestId"], "FAILED", request["sha256"],
            request["transactionDigest"], {"reason": reason},
        )


class ReplayLedger(_Journal):
    def __init__(self, root: Path, *, expected_tip: str | None = None):
        super().__init__(root, "cold", expected_tip=expected_tip)

    def _ensure_unseen(self, request: dict) -> None:
        self._reload()
        if self.get(request["requestId"]) is not None:
            raise ValueError("Duplicate requestId already reviewed")
        intent = request["intent"]
        requested_outpoints = {
            (item["txid"], item["vout"]) for item in intent["utxos"]
        }
        for record in self._records:
            if record["transactionDigest"] == request["transactionDigest"]:
                raise ValueError("Transaction digest already reviewed under another requestId")
            if record["state"] != "COLD_REVIEWED":
                continue
            prior = record["metadata"]
            if request["network"] == "sepolia" and (
                prior.get("network") == "sepolia" and
                prior.get("account") == request["account"] and
                prior.get("nonce") == intent["nonce"]
            ):
                raise ValueError("EVM account nonce already reserved by an earlier request")
            if request["network"] == "bitcoin-testnet" and (
                prior.get("network") == "bitcoin-testnet" and
                requested_outpoints.intersection(
                    tuple(point) for point in prior.get("outpoints", [])
                )
            ):
                raise ValueError("Bitcoin UTXO already reserved by an earlier request")

    def review_once(
        self,
        request: dict,
        *,
        expected_account: str,
        trusted_time: int | None = None,
        allow_no_trusted_clock: bool = False,
        verifier=None,
    ) -> StateSnapshot:
        verify = verifier or _official_verifier("verify_v2_request")
        checked = verify(
            request,
            expected_account=expected_account,
            trusted_time=trusted_time,
            allow_no_trusted_clock=allow_no_trusted_clock,
        )
        with self._locked():
            self._ensure_unseen(checked)
            return self._transition_locked(
                request["requestId"], "COLD_REVIEWED", request["sha256"],
                request["transactionDigest"], {
                    "network": request["network"],
                    "account": request["account"],
                    "expiryAssurance": checked["expiryAssurance"],
                    "nonce": checked["intent"]["nonce"],
                    "outpoints": [
                        [item["txid"], item["vout"]] for item in checked["intent"]["utxos"]
                    ],
                },
            )

    def mark_signed(
        self,
        request: dict,
        response: dict,
        *,
        trusted_time: int | None = None,
        allow_no_trusted_clock: bool = False,
        verifier=None,
    ) -> StateSnapshot:
        current = self.get(request["requestId"])
        if current is None or current.state != "COLD_REVIEWED":
            raise ValueError("Request must be cold-reviewed before signing")
        verify = verifier or _official_verifier("verify_v2_response")
        verify(
            request,
            response,
            expected_account=current.metadata.get("account"),
            trusted_time=trusted_time,
            allow_no_trusted_clock=allow_no_trusted_clock,
        )
        return self._transition(
            request["requestId"], "SIGNED", request["sha256"],
            request["transactionDigest"], {"responseDigest": response["sha256"]},
        )

    def failed(self, request: dict, reason: str) -> StateSnapshot:
        if type(reason) is not str or not 1 <= len(reason) <= 256:
            raise ValueError("Invalid failure reason")
        return self._transition(
            request["requestId"], "FAILED", request["sha256"],
            request["transactionDigest"], {"reason": reason},
        )
