import copy

import pytest

from usb_cold_wallet import cli
from usb_cold_wallet.exchange import package, read_envelope, verify, write
from usb_cold_wallet.keys import root_from_mnemonic


SEPOLIA = {
    "type": 2,
    "chainId": 11155111,
    "nonce": 0,
    "to": "0x000000000000000000000000000000000000dEaD",
    "value": 1000,
    "gas": 21000,
    "maxFeePerGas": 2_000_000_000,
    "maxPriorityFeePerGas": 1_000_000_000,
    "data": "0x",
}


def test_request_envelope_integrity_and_network():
    envelope = package("evm-request", SEPOLIA)
    assert verify(envelope, "evm-request") == SEPOLIA

    changed = copy.deepcopy(envelope)
    changed["payload"]["value"] += 1
    with pytest.raises(ValueError, match="integrity"):
        verify(changed, "evm-request")


def test_exchange_rejects_secret_fields():
    payload = dict(SEPOLIA)
    payload["private_key"] = "forbidden"
    with pytest.raises(ValueError, match="Secret field"):
        package("evm-request", payload)


def test_exchange_rejects_mainnet_evm_request():
    payload = dict(SEPOLIA)
    payload["chainId"] = 1
    with pytest.raises(ValueError, match="Sepolia"):
        package("evm-request", payload)


def test_cli_signs_issue5_evm_request_envelope(tmp_path, monkeypatch):
    request = tmp_path / "request.json"
    output = tmp_path / "signed.json"
    write(request, "evm-request", SEPOLIA)
    root = root_from_mnemonic("abandon " * 11 + "about")
    monkeypatch.setattr(cli, "_wallet_root", lambda args: root)
    monkeypatch.setattr(cli, "_approve", lambda phrase: None)

    result = cli.main([
        "--vault", str(tmp_path / "unused.vault"),
        "sign-evm",
        "--request", str(request),
        "--to", SEPOLIA["to"],
        "--wei", str(SEPOLIA["value"]),
        "--out", str(output),
    ])

    assert result == 0
    signed = read_envelope(output, "evm-signed")["payload"]
    assert signed["chain_id"] == 11155111
    assert signed["to"].lower() == SEPOLIA["to"].lower()


def test_cli_rejects_wrong_request_envelope_kind(tmp_path, monkeypatch):
    wrong_for_evm = tmp_path / "btc-request.json"
    wrong_for_btc = tmp_path / "evm-request.json"
    output = tmp_path / "must-not-exist.json"
    write(wrong_for_evm, "btc-request", "cHNidP8BAA==")
    write(wrong_for_btc, "evm-request", SEPOLIA)
    root = root_from_mnemonic("abandon " * 11 + "about")
    monkeypatch.setattr(cli, "_wallet_root", lambda args: root)
    monkeypatch.setattr(cli, "_approve", lambda phrase: None)

    evm_result = cli.main([
        "--vault", str(tmp_path / "unused.vault"),
        "sign-evm", "--request", str(wrong_for_evm),
        "--to", SEPOLIA["to"], "--wei", str(SEPOLIA["value"]),
        "--out", str(output),
    ])
    assert evm_result == 1
    assert not output.exists()

    btc_result = cli.main([
        "--vault", str(tmp_path / "unused.vault"),
        "sign-btc", "--request", str(wrong_for_btc),
        "--to", "tb1qexample", "--sats", "1000",
        "--max-fee-sats", "100", "--out", str(output),
    ])
    assert btc_result == 1
    assert not output.exists()
