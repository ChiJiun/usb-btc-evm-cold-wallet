"""Deterministic regression gates for replay, crash artifacts and hostile PSBT maps."""
import base64
import json
import signal
import sys

import pytest

from test_btc_hardening import _inject_map_entry, vector
from tools import fuzz_btc_psbt as fuzz
from usb_cold_wallet.btc import _read_psbt


@pytest.mark.parametrize("map_index,key,value", [
    (0, b"\x00", b"duplicate unsigned transaction"),
    (1, b"\x01", b"duplicate witness utxo"),
    (0, b"\x02", b"\x02\x00\x00\x00"),  # v2-only global key
    (1, b"\x0e", b"\x11" * 32),  # v2-only input prevout
    (2, b"\x03", b"\x01" * 8),  # v2-only output amount
])
def test_hostile_duplicate_and_mixed_version_maps_fail_closed(map_index, key, value):
    # The unsigned tx and witness UTXO are already present in the public seed.
    raw = _inject_map_entry(vector().to_base64(), map_index, key, value)
    with pytest.raises(ValueError):
        _read_psbt(raw)


@pytest.mark.parametrize("prefix", [b"\xfd\xfc\x00", b"\xfe\xff\xff\x00\x00",
                                   b"\xff\xff\xff\xff\xff\x00\x00\x00\x00",
                                   b"\xfd", b"\xfe", b"\xff"])
def test_noncanonical_or_truncated_compactsize_rejected(prefix):
    with pytest.raises(ValueError):
        _read_psbt(base64.b64encode(b"psbt\xff" + prefix).decode())


def test_replay_stored_rejections_and_report_resource_bounds(monkeypatch, tmp_path, capsys):
    (tmp_path / "known-rejection.psbt").write_bytes(b"psbt\xff\xfd")
    monkeypatch.setattr(sys, "argv", ["fuzz_btc_psbt.py", "--seed", "20261122",
        "--seconds", "10", "--max-cases", "7", "--replay-dir", str(tmp_path)])
    assert fuzz.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["replayed"] == 1
    assert result["replay_failures"] == 0
    assert result["max_case_bytes"] == fuzz.MAX_CASE_BYTES
    assert result["case_timeout_ms"] == 250
    assert result["crashes"] == 0
    assert result["cases"] == 7


def test_regression_replay_preserves_unexpected_crashes(monkeypatch, tmp_path, capsys):
    (tmp_path / "regression.psbt").write_bytes(b"boom")
    original = fuzz.execute

    def unexpected(raw):
        if raw == b"boom":
            raise RuntimeError("regression crash")
        return original(raw)

    monkeypatch.setattr(fuzz, "execute", unexpected)
    monkeypatch.setattr(sys, "argv", ["fuzz_btc_psbt.py", "--seconds", "10",
        "--max-cases", "7", "--replay-dir", str(tmp_path),
        "--artifact-dir", str(tmp_path)])
    assert fuzz.main() == 1
    out = json.loads(capsys.readouterr().out)
    assert out["crashes"] == out["replay_failures"] == 1
    assert any(p.name != "regression.psbt" for p in tmp_path.glob("*.psbt"))


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="Linux/POSIX per-case timer")
def test_per_case_timeout_is_a_crash_and_nonzero_exit(monkeypatch, tmp_path, capsys):
    original = fuzz.execute

    def slow(raw):
        if raw == b"boom":
            signal.pause()
        return original(raw)

    (tmp_path / "regression.psbt").write_bytes(b"boom")
    monkeypatch.setattr(fuzz, "execute", slow)
    monkeypatch.setattr(sys, "argv", ["fuzz_btc_psbt.py", "--seconds", "10",
        "--max-cases", "7", "--case-timeout-ms", "10",
        "--replay-dir", str(tmp_path), "--artifact-dir", str(tmp_path)])
    assert fuzz.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert result["crashes"] == 1
    assert result["case_timeout_enforced"] is True
