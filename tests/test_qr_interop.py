"""Python -> browser UR -> Python testnet QR vectors; public compromised seed only."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from usb_cold_wallet.keys import evm_account, root_from_mnemonic
from usb_cold_wallet.policy import default_profile
from usb_cold_wallet.qr_cli import main as qr_main
from usb_cold_wallet.qr_session import REQUEST_KEYS, RESPONSE_KEYS, _check
from usb_cold_wallet.qr_workflow import sign_offline, verify_evm_response

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "qr-transport/tests/interop_bridge.mjs"


def _browser_roundtrip(payload):
    node_modules = ROOT / "qr-transport/node_modules/@blockchaincommons/uniform-resources"
    if not node_modules.exists():
        if os.environ.get("QR_INTEROP") == "1":
            pytest.fail("QR interoperability test requires npm ci in qr-transport")
        pytest.skip("QR transport npm dependencies not installed")
    result = subprocess.run(
        ["node", str(BRIDGE)],
        input=json.dumps(payload, ensure_ascii=True, indent=2),
        text=True, capture_output=True, cwd=ROOT, timeout=30, check=True,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("wei", [
    9_007_199_254_740_993,  # First non-safe JavaScript integer
    10_000_000_000_000_000,  # 0.01 ETH
    1_000_000_000_000_000_000,  # 1 ETH
])
def test_python_cli_browser_ur_and_signed_response_are_lossless(wei, tmp_path):
    root = root_from_mnemonic("abandon " * 11 + "about")  # Known compromised test vector.
    sender = evm_account(root).address
    recipient = "0x000000000000000000000000000000000000dEaD"
    tx = {
        "type": 2, "chainId": 11155111, "nonce": 12, "to": recipient,
        "value": wei, "gas": 21000, "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000, "data": "0x",
    }
    tx_path = tmp_path / "tx.json"
    request_path = tmp_path / "request.json"
    tx_path.write_text(json.dumps(tx), encoding="utf-8")
    assert qr_main(["prepare-evm", "--tx", str(tx_path),
                    "--account", sender, "--to", recipient, "--wei", str(wei),
                    "--out", str(request_path)]) == 0
    request = json.loads(request_path.read_text(encoding="utf-8"))
    received_request = _browser_roundtrip(request)
    _check(received_request, REQUEST_KEYS, "unsigned")
    assert received_request == request
    assert received_request["payload"]["transaction"]["value"] == wei

    response = sign_offline(root, received_request, recipient=recipient, amount=wei,
                            profile=default_profile(root), extra_confirmation="UNVERIFIED RECIPIENT")
    received_response = _browser_roundtrip(response)
    _check(received_response, RESPONSE_KEYS, "signed")
    assert received_response == response
    assert received_response["payload"]["max_total_wei"] == response["payload"]["max_total_wei"]
    assert verify_evm_response(request, received_response)["transaction_hash"] == response["payload"]["transaction_hash"]
