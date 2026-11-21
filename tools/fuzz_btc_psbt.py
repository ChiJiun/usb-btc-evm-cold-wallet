"""Bounded line-coverage-guided Bitcoin PSBT parser/policy fuzzer (public seeds).

Run:
  python tools/fuzz_btc_psbt.py --seconds 30 --seed 20261121

Uses stdlib tracing to retain inputs with previously unseen lines of btc.py.
Every campaign first proves the unmodified valid fixture passes both parsing and
wallet review. Separate parser/policy counters prevent line coverage from being
mistaken for successful security-policy execution.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import random
import signal
import sys
import time
from pathlib import Path

try:
    import resource  # POSIX only; Windows smoke tests remain portable.
except ImportError:
    resource = None

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tests"))
sys.path.insert(0, str(PROJECT / "src"))

from test_btc_hardening import ROOT, DEST, vector  # noqa: E402
from usb_cold_wallet.btc import _read_psbt, review_btc_psbt  # noqa: E402

MAX_CASE_BYTES = 200_001
MAX_CORPUS = 256


class CaseTimeout(BaseException):
    """Out-of-band bound: cannot be normalized into a parser ValueError."""


@dataclass(frozen=True)
class Observation:
    coverage: frozenset[int]
    parser_accepted: bool
    policy_accepted: bool


def mutate(data: bytes, rng: random.Random) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randrange(1, 5)):
        mode = rng.randrange(6)
        offset = rng.randrange(len(buf) + 1) if buf else 0
        if mode == 0 and offset < len(buf):
            buf[offset] ^= 1 << rng.randrange(8)
        elif mode == 1 and offset < len(buf):
            buf[offset] = rng.randrange(256)
        elif mode == 2 and len(buf) < MAX_CASE_BYTES:
            buf[offset:offset] = rng.randbytes(rng.randrange(1, min(32, MAX_CASE_BYTES - len(buf)) + 1))
        elif mode == 3 and offset < len(buf):
            del buf[offset:offset + rng.randrange(1, 32)]
        elif mode == 4 and len(buf) + 8 <= MAX_CASE_BYTES:
            buf[offset:offset] = rng.choice([b"\x00", b"\xfd", b"\xfe", b"\xff"]) * rng.randrange(1, 9)
        elif mode == 5 and len(buf) < MAX_CASE_BYTES and data:
            origin = rng.randrange(len(data))
            buf[offset:offset] = data[origin:origin + min(64, MAX_CASE_BYTES - len(buf))]
    return bytes(buf[:MAX_CASE_BYTES])


def execute(raw: bytes) -> Observation:
    """Trace parser and policy separately; normalize only deliberate ValueError denials."""
    coverage: set[int] = set()

    def tracer(frame, event, arg):
        if event == "line" and frame.f_code.co_filename.endswith("/usb_cold_wallet/btc.py"):
            coverage.add(frame.f_lineno)
        return tracer

    previous_trace = sys.gettrace()
    sys.settrace(tracer)
    try:
        payload = base64.b64encode(raw).decode("ascii")
        try:
            _read_psbt(payload)
        except ValueError:
            return Observation(frozenset(coverage), False, False)
        try:
            # This must complete for a policy acceptance; reaching one line is
            # insufficient evidence of a successful offline review.
            review_btc_psbt(ROOT, payload, DEST, 60_000, 1_500, 0)
        except ValueError:
            return Observation(frozenset(coverage), True, False)
        return Observation(frozenset(coverage), True, True)
    finally:
        sys.settrace(previous_trace)


def initial_corpus() -> list[bytes]:
    """One valid policy seed, two valid-PSBT policy denials, and malformed bytes."""
    allowed = vector().serialize()
    unsupported_sighash = vector()
    unsupported_sighash.inputs[0].sighash_type = 2
    unexpected_metadata = vector()
    unexpected_metadata.inputs[0].unknown[b"\xfc\x01"] = b"\x01"
    return [
        allowed,
        unsupported_sighash.serialize(),
        unexpected_metadata.serialize(),
        allowed[:5],
        b"",
        b"psbt\xff" + b"\xff" * 8,
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--seed", type=int, default=20261121)
    parser.add_argument("--max-cases", type=int, default=20000)
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--replay-dir", type=Path, help="Replay saved *.psbt crashes before mutation")
    parser.add_argument("--case-timeout-ms", type=int, default=250, help="POSIX per-case CPU/wall timer")
    args = parser.parse_args()
    if (not 0 < args.seconds <= 3600 or not 1 <= args.max_cases <= 1_000_000
            or not 1 <= args.case_timeout_ms <= 60_000):
        parser.error("seconds/max-cases outside supported bounds")

    has_timer = hasattr(signal, "setitimer")

    def alarm_handler(_signum, _frame):
        raise CaseTimeout("PSBT parser/policy exceeded per-case wall-time bound")

    original_alarm_handler = signal.getsignal(signal.SIGALRM) if has_timer else None
    rng = random.Random(args.seed)
    corpus = initial_corpus()
    explored: set[int] = set()
    crashes = 0
    cases = 0
    metrics = {
        "parser_accepted": 0, "parser_rejected": 0,
        "policy_accepted": 0, "policy_rejected": 0,
    }
    deadline = time.monotonic() + args.seconds

    def run_case(case: bytes, retain_novel: bool) -> Observation | None:
        nonlocal crashes, cases
        cases += 1
        if len(case) > MAX_CASE_BYTES:
            raise ValueError("Fuzzer case exceeds payload bound")
        if has_timer:
            signal.signal(signal.SIGALRM, alarm_handler)
            signal.setitimer(signal.ITIMER_REAL, args.case_timeout_ms / 1000)
        try:
            result = execute(case)
        except (Exception, CaseTimeout) as exc:
            crashes += 1
            digest = hashlib.sha256(case).hexdigest()
            if args.artifact_dir is not None:
                args.artifact_dir.mkdir(parents=True, exist_ok=True)
                (args.artifact_dir / (digest + ".psbt")).write_bytes(case)
            print(json.dumps({"crash_sha256": digest, "type": type(exc).__name__,
                              "message": str(exc)[:200]}), file=sys.stderr)
            return None
        finally:
            if has_timer:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, original_alarm_handler)

        if result.parser_accepted:
            metrics["parser_accepted"] += 1
            if result.policy_accepted:
                metrics["policy_accepted"] += 1
            else:
                metrics["policy_rejected"] += 1
        else:
            metrics["parser_rejected"] += 1

        novel = result.coverage - explored
        if novel:
            explored.update(novel)
            if retain_novel:
                if len(corpus) < MAX_CORPUS:
                    corpus.append(case)
                else:
                    corpus[rng.randrange(6, len(corpus))] = case
        return result

    # This is deliberately the first executed case, not merely a mutation
    # parent. Fail the campaign if the known-good seed ceases to pass policy.
    baseline = run_case(corpus[0], retain_novel=False)
    if baseline is None or not baseline.policy_accepted:
        print("Baseline public PSBT did not pass the offline review", file=sys.stderr)
        return 2

    # Regression corpus is replayed verbatim before any mutation. A previously
    # crashing sample must no longer produce an uncontrolled exception.
    replayed = 0
    replay_failures = 0
    if args.replay_dir is not None:
        for path in sorted(args.replay_dir.glob("*.psbt")):
            if time.monotonic() >= deadline:
                replay_failures += 1  # incomplete replay is never success
                break
            raw = path.read_bytes()
            if len(raw) > MAX_CASE_BYTES:
                replay_failures += 1
                continue
            replayed += 1
            if run_case(raw, retain_novel=False) is None:
                replay_failures += 1

    for seed in corpus[1:args.max_cases]:
        if time.monotonic() >= deadline:
            break
        run_case(seed, retain_novel=False)

    while cases < args.max_cases and time.monotonic() < deadline:
        case = mutate(rng.choice(corpus), rng)
        run_case(case, retain_novel=True)

    print(json.dumps({
        "seed": args.seed, "cases": cases, "coverage_lines": len(explored),
        "corpus_size": len(corpus), "crashes": crashes,
        "baseline_policy_accepted": baseline.policy_accepted,
        "max_case_bytes": MAX_CASE_BYTES, "case_timeout_ms": args.case_timeout_ms,
        "replayed": replayed, "replay_failures": replay_failures,
        "max_rss_kib": (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                        if resource is not None and sys.platform != "darwin" else None),
        "case_timeout_enforced": has_timer,
        **metrics,
    }, sort_keys=True))
    return 1 if crashes or replay_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
