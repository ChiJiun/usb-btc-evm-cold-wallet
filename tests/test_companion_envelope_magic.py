"""Keep online PSBT framing byte-compatible with the offline validator."""
import base64

import pytest

from usb_cold_wallet.companion_envelope import package


def test_real_psbt_magic_is_accepted():
    payload = base64.b64encode(bytes.fromhex("70736274ff00")).decode("ascii")
    assert package("btc-request", payload)["payload"] == payload


def test_ascii_escape_string_is_not_psbt_magic():
    payload = base64.b64encode(b"psbt" + bytes([92]) + b"xff" + bytes([0])).decode("ascii")
    with pytest.raises(ValueError, match="Invalid BTC PSBT framing"):
        package("btc-request", payload)
