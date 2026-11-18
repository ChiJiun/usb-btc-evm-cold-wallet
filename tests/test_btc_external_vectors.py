"""Independent PSBT fixtures plus property-based parser/policy tests for Issue #2."""

import base64
import json
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from usb_cold_wallet.btc import _read_psbt, review_btc_psbt
from usb_cold_wallet.keys import btc_address, root_from_mnemonic

from test_btc_hardening import vector

ROOT = root_from_mnemonic("abandon " * 11 + "about")
DEST = btc_address(ROOT, 0, 1)
FIXTURES = json.loads(
    (Path(__file__).parent / "fixtures" / "external_psbt_vectors.json").read_text()
)["vectors"]


def test_shared_bitcoin_core_sparrow_bip174_vector_parses_exactly():
    fixture = FIXTURES["shared_bip174_valid_v0"]
    parsed = _read_psbt(fixture["base64"])

    assert parsed.tx.txid().hex() == fixture["expected_txid"]
    assert len(parsed.tx.vin) == 1
    assert [output.value for output in parsed.tx.vout] == fixture["expected_output_sats"]

    # It is a valid generic PSBT, but not this wallet's native BIP84 P2WPKH policy.
    with pytest.raises(ValueError):
        review_btc_psbt(ROOT, fixture["base64"], DEST, 60_000, 10_000, 0)


@pytest.mark.parametrize(
    "name",
    ["shared_unsigned_tx_with_scriptsig_invalid", "bitcoin_core_psbt_v2"],
)
def test_external_vectors_outside_supported_format_fail_closed(name):
    with pytest.raises(ValueError):
        _read_psbt(FIXTURES[name]["base64"])


@given(max_fee_sats=st.integers(min_value=0, max_value=2_000))
@settings(max_examples=100, deadline=None)
def test_property_fee_bound_is_exact(max_fee_sats):
    psbt_b64 = vector().to_base64()
    if max_fee_sats < 1_000:
        with pytest.raises(ValueError, match="Fee 1000 sats"):
            review_btc_psbt(ROOT, psbt_b64, DEST, 60_000, max_fee_sats, 0)
    else:
        reviewed = review_btc_psbt(ROOT, psbt_b64, DEST, 60_000, max_fee_sats, 0)
        assert reviewed["fee_sats"] == 1_000


@given(payload=st.binary(min_size=0, max_size=4_096))
@settings(max_examples=300, deadline=None)
def test_property_arbitrary_binary_parser_input_is_fail_closed(payload):
    encoded = base64.b64encode(payload).decode()
    try:
        parsed = _read_psbt(encoded)
    except Exception as exc:
        # The public parser boundary must normalize hostile parser failures.
        assert type(exc) is ValueError
    else:
        assert 1 <= len(parsed.inputs) <= 20
        assert 1 <= len(parsed.outputs) <= 2
