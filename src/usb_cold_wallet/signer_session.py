"""Fail-closed, local-only short-lived signer session state machine.

The machine never persists secrets or accepts remote commands. The caller owns
its in-memory BIP32 root; callbacks must discard that reference on lock.
"""
from __future__ import annotations

from enum import Enum
import math
import re
import time
from typing import Callable


class State(str, Enum):
    LOCKED = "LOCKED"
    UNLOCKING = "UNLOCKING"
    REVIEWING = "REVIEWING"
    APPROVED = "APPROVED"
    SIGNED = "SIGNED"


DEFAULT_IDLE_SECONDS = 600
MAX_IDLE_SECONDS = 600
DEFAULT_MAX_TRANSACTIONS = 3
MAX_TRANSACTIONS = 5
MAX_SESSION_SECONDS = 900
UNLOCK_DEADLINE_SECONDS = 120
BACKOFF_SECONDS = (2, 4, 8, 16, 32, 60)


class SignerSession:
    """Clock-injected state model for a physically attended, testnet signer.

    No state is serialized. Locking must always clear the GUI's own root and
    review references through on_lock. A new request requires a fresh approval.
    """

    def __init__(
        self,
        *,
        audit: Callable[[], bool],
        on_lock: Callable[[], None],
        clock: Callable[[], float] = time.monotonic,
        idle_seconds: int = DEFAULT_IDLE_SECONDS,
        max_transactions: int = DEFAULT_MAX_TRANSACTIONS,
        max_session_seconds: int = MAX_SESSION_SECONDS,
    ):
        if type(idle_seconds) is not int or not 0 < idle_seconds <= MAX_IDLE_SECONDS:
            raise ValueError("Idle period must be in 1..600 seconds")
        if type(max_transactions) is not int or not 0 < max_transactions <= MAX_TRANSACTIONS:
            raise ValueError("Transaction count outside configured safety limit")
        if type(max_session_seconds) is not int or not 0 < max_session_seconds <= MAX_SESSION_SECONDS:
            raise ValueError("Absolute signing session lifetime is limited to 900 seconds")
        self._audit = audit
        self._on_lock = on_lock
        self._clock = clock
        self.idle_seconds = idle_seconds
        self.max_transactions = max_transactions
        self.max_session_seconds = max_session_seconds
        self.state = State.LOCKED
        self._last_activity = None
        self._unlocked_at = None
        self._unlock_started_at = None
        self._failed_attempts = 0
        self._next_unlock_at = 0.0
        self._transaction_count = 0
        self._review_digest = None

    @property
    def transaction_count(self) -> int:
        return self._transaction_count

    @property
    def failed_attempts(self) -> int:
        return self._failed_attempts

    def _now(self) -> float:
        try:
            now = self._clock()
            if type(now) not in (int, float) or not math.isfinite(now):
                raise ValueError("Invalid monotonic clock")
            return float(now)
        except Exception as exc:
            self.lock("clock_invalid")
            raise ValueError("Invalid monotonic clock; wallet locked") from exc

    @property
    def remaining_backoff(self) -> float:
        return max(0.0, self._next_unlock_at - self._now())

    @property
    def unlocked(self) -> bool:
        return self.state != State.LOCKED

    def _safe_audit(self) -> bool:
        try:
            return self._audit() is True
        except Exception:
            return False

    def lock(self, reason: str = "locked") -> None:
        self.state = State.LOCKED
        self._review_digest = None
        self._last_activity = None
        self._unlocked_at = None
        self._unlock_started_at = None
        self._transaction_count = 0
        self._on_lock()

    def _expire(self) -> None:
        if self.state == State.LOCKED:
            return
        now = self._now()
        if self.state == State.UNLOCKING:
            if (self._unlock_started_at is None or now < self._unlock_started_at or
                    now - self._unlock_started_at >= UNLOCK_DEADLINE_SECONDS):
                self.lock("unlock_timeout")
                raise ValueError("Unlock attempt timed out; wallet locked")
            return
        if (self._last_activity is None or self._unlocked_at is None or
                now < self._last_activity or now < self._unlocked_at or
                now - self._last_activity >= self.idle_seconds or
                now - self._unlocked_at >= self.max_session_seconds):
            self.lock("expired")
            raise ValueError("Signer session expired; wallet locked")

    def tick(self) -> bool:
        if self.state == State.LOCKED:
            return False
        try:
            self._expire()
            if not self._safe_audit():
                self.lock("audit_failed")
                return True
        except ValueError:
            return True
        return False

    def begin_unlock(self) -> None:
        if self.unlocked:
            raise ValueError("Already unlocked")
        if self.remaining_backoff > 0:
            raise ValueError("Unlock temporarily rate limited")
        if not self._safe_audit():
            self.lock("audit_failed")
            raise ValueError("Offline runtime safety audit failed")
        self._unlock_started_at = self._now()
        self.state = State.UNLOCKING

    def unlock_failed(self) -> None:
        if self.state != State.UNLOCKING:
            raise ValueError("Not in unlocking state")
        self._failed_attempts += 1
        seconds = BACKOFF_SECONDS[min(self._failed_attempts - 1, len(BACKOFF_SECONDS) - 1)]
        self._next_unlock_at = self._now() + seconds
        self.lock("failed_unlock")

    def unlock_succeeded(self) -> None:
        if self.state != State.UNLOCKING:
            raise ValueError("Not in unlocking state")
        self._expire()
        if not self._safe_audit():
            self.lock("audit_failed")
            raise ValueError("Offline runtime safety audit failed")
        now = self._now()
        self._unlocked_at = now
        self._unlock_started_at = None
        self._last_activity = now
        self._failed_attempts = 0
        self._next_unlock_at = 0.0
        self._transaction_count = 0
        self.state = State.REVIEWING

    def activity(self) -> None:
        if self.state != State.LOCKED:
            self._expire()
            self._last_activity = self._now()

    def start_review(self, digest: str) -> None:
        self._expire()
        if self.state not in (State.REVIEWING, State.SIGNED):
            raise ValueError("Signer not ready for a new review")
        if self._transaction_count >= self.max_transactions:
            self.lock("limit")
            raise ValueError("Transaction quota reached; unlock again")
        if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest):
            self.lock("invalid_review")
            raise ValueError("Review digest is invalid")
        self._review_digest = digest
        self.state = State.REVIEWING

    def approve(self, digest: str) -> None:
        self._expire()
        if self.state != State.REVIEWING or self._review_digest is None:
            raise ValueError("No active transaction review")
        if digest != self._review_digest:
            self.lock("changed_request")
            raise ValueError("Transaction changed; signer locked")
        if not self._safe_audit():
            self.lock("audit_failed")
            raise ValueError("Offline runtime safety audit failed")
        self.state = State.APPROVED

    def signing(self, digest: str) -> None:
        self._expire()
        if self.state != State.APPROVED or digest != self._review_digest:
            self.lock("unapproved")
            raise ValueError("Every transaction requires independent approval")
        if not self._safe_audit():
            self.lock("audit_failed")
            raise ValueError("Offline runtime safety audit failed")
        # Caller signs synchronously here, never in a background worker.

    def signed(self, digest: str) -> None:
        self._expire()
        if self.state != State.APPROVED or digest != self._review_digest:
            self.lock("unapproved")
            raise ValueError("Unapproved transaction was not signed")
        self._transaction_count += 1
        self._review_digest = None
        self.state = State.SIGNED
        # Retain the unlocked root only for a short, attended, bounded session.
        if self._transaction_count >= self.max_transactions:
            self.lock("quota")
