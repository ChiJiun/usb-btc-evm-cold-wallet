"""Bounded, coverage-guided Bitcoin PSBT parser fuzzer (test-only public seeds).

Run:
  python tools/fuzz_btc_psbt.py --seconds 30 --seed 20261121

Uses the stdlib tracer to retain mutations that exercise previously unseen
lines in src/usb_cold_wallet/btc.py. It is slower than a native AFL/Atheris
harness, but requires no additional dependencies or secret material.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tests"))
sys.path.insert(0, str(PROJECT / "src"))

from test_btc_hardening import ROOT, DEST, vector  # noqa: E402
from usb_cold_wallet.btc import _read_psbt, review_btc_psbt  # noqa: E402

MAX_CASE_BYTES = 200_001
MAX_CORPUS = 256


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


def execute(raw: bytes) -> frozenset[int]:
    coverage: set[int] = set()

    def tracer(frame, event, arg):
        if event == "line" and frame.f_code.co_filename.endswith("/usb_cold_wallet/btc.py"):
            coverage.add(frame.f_lineno)
        return tracer

    sys.settrace(tracer)
    try:
        payload = base64.b64encode(raw).decode("ascii")
        try:
            _read_psbt(payload)
            # Exercise the wallet-specific policy as well as the raw parser.
            review_btc_psbt(ROOT, payload, DEST, 60_000, 1_500, 0)
        except ValueError:
            pass  # Expected denial, never a crash.
    finally:
        sys.settrace(None)
    return frozenset(coverage)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--seed", type=int, default=20261121)
    parser.add_argument("--max-cases", type=int, default=20000)
    parser.add_argument("--artifact-dir", type=Path)
    args = parser.parse_args()
    if not 0 < args.seconds <= 3600 or not 1 <= args.max_cases <= 1_000_000:
        parser.error("seconds/max-cases outside supported bounds")

    rng = random.Random(args.seed)
    seed = vector().serialize()
    corpus = [seed, seed[:5], b"", b"psbt\xff" + b"\xff" * 8]
    explored: set[int] = set()
    crashes = 0
    cases = 0
    deadline = time.monotonic() + args.seconds
    while cases < args.max_cases and time.monotonic() < deadline:
        parent = rng.choice(corpus)
        case = mutate(parent, rng)
        cases += 1
        try:
            visited = execute(case)
        except Exception as exc:
            crashes += 1
            digest = hashlib.sha256(case).hexdigest()
            if args.artifact_dir is not None:
                args.artifact_dir.mkdir(parents=True, exist_ok=True)
                (args.artifact_dir / (digest + ".psbt")).write_bytes(case)
            print(json.dumps({"crash_sha256": digest, "type": type(exc).__name__,
                              "message": str(exc)[:200]}), file=sys.stderr)
            continue
        novel = visited - explored
        if novel:
            explored.update(novel)
            if len(corpus) < MAX_CORPUS:
                corpus.append(case)
            else:
                corpus[rng.randrange(4, len(corpus))] = case

    print(json.dumps({"seed": args.seed, "cases": cases, "coverage_lines": len(explored),
                      "corpus_size": len(corpus), "crashes": crashes}, sort_keys=True))
    return 1 if crashes else 0


if __name__ == "__main__":
    raise SystemExit(main())
