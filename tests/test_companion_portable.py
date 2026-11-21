"""Portable launcher regression tests without any chain network access."""
import pytest

from usb_cold_wallet import companion_portable as portable
from usb_cold_wallet.companion_core import JsonRpc


def test_double_click_uses_testnets_and_opens_browser(monkeypatch):
    received = []
    monkeypatch.setattr(portable, "web_main", lambda args: received.extend(args) or 0)
    assert portable.main([]) == 0
    assert received == [
        "--rpc-url", portable.DEFAULT_SEPOLIA_RPC,
        "--btc-esplora", portable.DEFAULT_BTC_ESPLORA,
        "--port", "0", "--open-browser",
    ]
    assert JsonRpc(portable.DEFAULT_SEPOLIA_RPC).display_endpoint == portable.DEFAULT_SEPOLIA_RPC


def test_custom_local_endpoints_and_no_browser(monkeypatch):
    received = []
    monkeypatch.setattr(portable, "web_main", lambda args: received.extend(args) or 0)
    assert portable.main([
        "--rpc-url", "http://127.0.0.1:8545",
        "--btc-esplora", "http://127.0.0.1:3002",
        "--no-browser", "--port", "8769",
    ]) == 0
    assert received == [
        "--rpc-url", "http://127.0.0.1:8545",
        "--btc-esplora", "http://127.0.0.1:3002",
        "--port", "8769",
    ]


@pytest.mark.parametrize("port", ["-1", "65536"])
def test_invalid_listening_ports_rejected(port):
    with pytest.raises(SystemExit) as exc:
        portable.main(["--port", port])
    assert exc.value.code == 2
