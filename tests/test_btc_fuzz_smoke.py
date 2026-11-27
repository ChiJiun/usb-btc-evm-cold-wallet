"""Fuzz harness is executable and bounded with no external fuzzer dependency."""
import random

from test_btc_hardening import vector
from tools.fuzz_btc_psbt import MAX_CASE_BYTES, execute, mutate


def test_valid_psbt_hits_review_and_parser_coverage():
    covered = execute(vector().serialize())
    assert len(covered) >= 25


def test_fuzzer_rejects_raw_mutations_without_uncaught_errors():
    raw = vector().serialize()
    rng = random.Random(20261121)
    parents = [raw, raw[:5], b"", b"psbt\xff" + b"\xff" * 8]
    for i in range(100):
        sample = mutate(parents[rng.randrange(len(parents))], rng)
        assert len(sample) <= MAX_CASE_BYTES
        visited = execute(sample)
        assert isinstance(visited, frozenset)


def test_fuzzer_never_allocates_more_than_raw_limit():
    rng = random.Random(10)
    huge = b"A" * MAX_CASE_BYTES
    for _ in range(10):
        changed = mutate(huge, rng)
        assert len(changed) <= MAX_CASE_BYTES
