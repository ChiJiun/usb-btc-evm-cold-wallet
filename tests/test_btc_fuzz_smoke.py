"""Fuzz harness parser/policy outcomes, reproducibility and bounds."""
import json
import random
import sys

import pytest

from test_btc_hardening import vector
from tools import fuzz_btc_psbt as fuzz
from tools.fuzz_btc_psbt import MAX_CASE_BYTES, execute, initial_corpus, main, mutate


def test_valid_psbt_passes_both_parser_and_offline_policy():
    observation = execute(vector().serialize())
    assert observation.parser_accepted
    assert observation.policy_accepted
    assert len(observation.coverage) >= 25


def test_well_formed_psbt_can_fail_policy_without_failing_parser():
    bad = vector()
    bad.tx.vout[0].value += 1
    observation = execute(bad.serialize())
    assert observation.parser_accepted
    assert not observation.policy_accepted

    malformed = execute(b"")
    assert not malformed.parser_accepted
    assert not malformed.policy_accepted


def test_campaign_executes_unmodified_seed_and_counts_distinct_denials(monkeypatch, capsys):
    assert len(initial_corpus()) == 6
    monkeypatch.setattr(sys, "argv", [
        "fuzz_btc_psbt.py", "--seconds", "10", "--seed", "20261121",
        "--max-cases", "6",
    ])
    assert main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["cases"] == 6
    assert report["baseline_policy_accepted"] is True
    assert report["parser_accepted"] == 3
    assert report["policy_accepted"] == 1
    assert report["policy_rejected"] == 2
    assert report["parser_rejected"] == 3
    assert report["crashes"] == 0
    assert report["coverage_lines"] >= 25


def test_fuzzer_rejects_raw_mutations_without_uncaught_errors():
    rng = random.Random(20261121)
    parents = initial_corpus()
    for _ in range(100):
        sample = mutate(parents[rng.randrange(len(parents))], rng)
        assert len(sample) <= MAX_CASE_BYTES
        observation = execute(sample)
        assert isinstance(observation.coverage, frozenset)
        assert not observation.policy_accepted or observation.parser_accepted


def test_execute_restores_existing_trace_even_if_policy_raises(monkeypatch):
    previous = sys.gettrace()

    def tracer(frame, event, arg):
        return tracer

    sys.settrace(tracer)
    try:
        observation = execute(vector().serialize())
        assert observation.policy_accepted
        assert sys.gettrace() is tracer

        def fail_unexpectedly(*args):
            raise RuntimeError("simulated parser-independent crash")

        monkeypatch.setattr(fuzz, "review_btc_psbt", fail_unexpectedly)
        with pytest.raises(RuntimeError, match="simulated"):
            execute(vector().serialize())
        assert sys.gettrace() is tracer
    finally:
        sys.settrace(previous)


def test_fuzzer_never_allocates_more_than_raw_limit():
    rng = random.Random(10)
    huge = b"A" * MAX_CASE_BYTES
    for _ in range(10):
        changed = mutate(huge, rng)
        assert len(changed) <= MAX_CASE_BYTES
