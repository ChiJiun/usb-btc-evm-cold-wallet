"""No-install Windows launcher for the watch-only Online Companion."""
from __future__ import annotations

import argparse

from .companion_web import main as web_main

DEFAULT_SEPOLIA_RPC = "https://ethereum-sepolia-rpc.publicnode.com"
DEFAULT_BTC_ESPLORA = "https://blockstream.info/testnet/api"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="USBColdCompanion",
        description="Portable BTC testnet / Sepolia watch-only Companion (no private keys).",
    )
    parser.add_argument("--rpc-url", default=DEFAULT_SEPOLIA_RPC)
    parser.add_argument("--btc-esplora", default=DEFAULT_BTC_ESPLORA)
    parser.add_argument("--port", type=int, default=0,
                        help="Loopback TCP port; 0 automatically chooses a free port")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("Invalid local port")
    forwarded = [
        "--rpc-url", args.rpc_url, "--btc-esplora", args.btc_esplora,
        "--port", str(args.port),
    ]
    if not args.no_browser:
        forwarded.append("--open-browser")
    return web_main(forwarded)


if __name__ == "__main__":
    raise SystemExit(main())
