"""Reject oversized raw PSBT input/output maps before embit scope parsing."""

import pytest
from embit import script, transaction

from usb_cold_wallet.btc import _validate_raw_psbt


def _compact_size(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    return b"\xfe" + value.to_bytes(4, "little")


@pytest.mark.parametrize("input_count,output_count", [
    (0, 1), (21, 1), (1, 0), (1, 3), (21, 3),
])
def test_reject_unsupported_raw_transaction_counts_before_scopes(input_count, output_count):
    unsigned = transaction.Transaction(
        vin=[transaction.TransactionInput(bytes([i]) * 32, 0) for i in range(input_count)],
        vout=[transaction.TransactionOutput(1000, script.Script(b"\x51"))
              for _ in range(output_count)],
    ).serialize()
    # The malformed PSBT intentionally stops after the global map. The guard
    # must reject counts before it attempts to walk input/output scope maps.
    raw = b"psbt\xff" + b"\x01\x00" + _compact_size(len(unsigned)) + unsigned + b"\x00"
    with pytest.raises(ValueError, match="count exceeds supported limit"):
        _validate_raw_psbt(raw)
