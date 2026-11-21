"""PSBTv0 counts are bounded before embit transaction and PSBT allocation."""
from __future__ import annotations

import base64
from unittest.mock import patch

import pytest
from embit import script, transaction

from usb_cold_wallet.btc import _read_psbt, _validate_raw_psbt


def _compact_size(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    return b"\xfe" + value.to_bytes(4, "little")


def _unsigned_tx(input_count: int, output_count: int) -> bytes:
    return transaction.Transaction(
        vin=[transaction.TransactionInput(bytes([i]) * 32, 0)
             for i in range(input_count)],
        vout=[transaction.TransactionOutput(1000, script.Script(b"\x51"))
              for _ in range(output_count)],
    ).serialize()


def _raw_psbt(unsigned_tx: bytes, inputs: int = 0, outputs: int = 0) -> bytes:
    # A PSBTv0's unsigned tx is a single global-map entry (key 0x00).
    # Each input/output scope map is terminated by an empty key.
    return (b"psbt\xff" + b"\x01\x00" + _compact_size(len(unsigned_tx))
            + unsigned_tx + b"\x00" + b"\x00" * (inputs + outputs))


@pytest.mark.parametrize(
    "input_count,output_count,reason",
    [
        (0, 1, "input count"),
        (21, 1, "input count"),
        (1, 0, "output count"),
        (1, 3, "output count"),
        (21, 3, "input count"),
    ],
)
def test_unsupported_unsigned_counts_fail_before_any_embit_transaction_parse(
    input_count: int, output_count: int, reason: str,
) -> None:
    unsigned = _unsigned_tx(input_count, output_count)
    # Intentionally omit all PSBT scope maps. The size guard must fire
    # before either embit parser or the scope walk is entered.
    raw = _raw_psbt(unsigned)
    with patch.object(transaction.Transaction, "parse",
                      side_effect=AssertionError("embit transaction parser was called")):
        with pytest.raises(ValueError, match=reason):
            _validate_raw_psbt(raw)


@pytest.mark.parametrize("input_count,output_count", [(1, 1), (20, 2)])
def test_supported_boundary_scope_maps_are_accepted(
    input_count: int, output_count: int,
) -> None:
    unsigned = _unsigned_tx(input_count, output_count)
    raw = _raw_psbt(unsigned, input_count, output_count)
    assert _validate_raw_psbt(raw) == unsigned
    parsed = _read_psbt(base64.b64encode(raw).decode("ascii"))
    assert len(parsed.inputs) == input_count
    assert len(parsed.outputs) == output_count


@pytest.mark.parametrize("input_count,output_count", [(1, 1), (20, 2)])
def test_supported_counts_still_require_complete_scope_maps(
    input_count: int, output_count: int,
) -> None:
    raw = _raw_psbt(_unsigned_tx(input_count, output_count))
    with pytest.raises(ValueError, match="Truncated PSBT"):
        _validate_raw_psbt(raw)


def test_noncanonical_unsigned_input_count_rejected_before_embit() -> None:
    unsigned = _unsigned_tx(1, 1)
    # Replace the 0x01 input-count at byte 4 by noncanonical 0xfd 0x01 0x00.
    mutated = unsigned[:4] + b"\xfd\x01\x00" + unsigned[5:]
    with patch.object(transaction.Transaction, "parse",
                      side_effect=AssertionError("embit transaction parser was called")):
        with pytest.raises(ValueError, match="Non-canonical CompactSize"):
            _validate_raw_psbt(_raw_psbt(mutated))


def test_raw_validation_enforces_size_without_parent_wrapper() -> None:
    with pytest.raises(ValueError, match="size limit"):
        _validate_raw_psbt(b"psbt\xff" + b"x" * 200_000)
