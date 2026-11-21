"""Smoke the real packaged Windows executable, with no network RPC calls."""
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def denied(url: str, code: int, headers=None) -> None:
    try:
        with urlopen(Request(url, headers=headers or {}), timeout=4):
            raise AssertionError("Unexpected successful API call: " + url)
    except HTTPError as err:
        assert err.code == code, (err.code, code)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: smoke_windows_companion.py PATH_TO_EXE")
    exe = Path(sys.argv[1]).resolve(strict=True)
    assert exe.suffix.lower() == ".exe"
    help_result = subprocess.run([str(exe), "--help"], capture_output=True,
                                 text=True, timeout=50, check=True)
    assert "watch-only" in help_result.stdout.lower()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [str(exe), "--no-browser", "--port", str(port)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    try:
        markup = None
        until = time.monotonic() + 60
        while time.monotonic() < until:
            if proc.poll() is not None:
                error = proc.stderr.read(4096).decode("utf-8", errors="replace")
                raise AssertionError("Portable EXE exited before startup: " + error)
            try:
                with urlopen(origin + "/", timeout=2) as response:
                    markup = response.read().decode("utf-8")
                    assert response.headers["Content-Security-Policy"].startswith("default-src 'none'")
                break
            except (URLError, TimeoutError, ConnectionError):
                time.sleep(0.5)
        assert markup and "Online Companion" in markup, "Packed browser UI unavailable"
        match = re.search(r'<meta name="companion-token" content="([^"]+)"', markup)
        assert match is not None
        for path, marker in [
            ("/companion.css", b"body"), ("/companion.js", b"/api/wallet"),
        ]:
            with urlopen(origin + path, timeout=4) as response:
                assert marker in response.read(), path
        denied(origin + "/api/wallet", 404)
        denied(origin + "/", 403, headers={"Host": "evil.example"})
        with urlopen(Request(origin + "/api/wallet", headers={
            "X-Companion-Token": match.group(1),
        }), timeout=4) as response:
            state = json.load(response)
        assert state == {
            "loaded": False, "rpc": "https://ethereum-sepolia-rpc.publicnode.com",
            "chain": "Sepolia",
        }, state
        print("Packaged EXE: real localhost UI/CSP/static/auth smoke passed")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
