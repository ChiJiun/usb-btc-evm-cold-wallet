"""Public test vectors only. No signing seeds required for QR binding tests."""
import copy

import pytest

from usb_cold_wallet.qr_session import QRSession, make_request, make_response


def fixture(network="sepolia", account="0x9858EfFD232B4033E47d90003D41EC34EcaEda94"):
    return make_request(network, account, {"transaction": {"nonce": 12, "value": 123}})


def verify_expected(request, response):
    # Stub ONLY for transport-level tests; actual signed tx validation belongs
    # to the chain-specific production verifier.
    return response["payload"] == {"signed": "public-test-only"}


def test_request_response_roundtrip_and_single_use():
    request = fixture()
    response = make_response(request, {"signed": "public-test-only"})
    session = QRSession(request, now=1000)
    assert session.check_response(response, now=1001, verify_signature=verify_expected) == {"signed": "public-test-only"}
    with pytest.raises(ValueError, match="already-consumed"):
        session.check_response(response, now=1002, verify_signature=verify_expected)


def test_independent_signature_verifier_is_required():
    request = fixture()
    response = make_response(request, {"signed": "public-test-only"})
    session = QRSession(request, now=1000)
    with pytest.raises(ValueError, match="verifier"):
        session.check_response(response, now=1001)
    with pytest.raises(ValueError, match="verification"):
        session.check_response(response, now=1001, verify_signature=lambda *_: False)


def test_reject_crosschain_wrong_account_and_wrong_request_id():
    request = fixture()
    response = make_response(request, {"signed": "public-test-only"})
    for field, bad in [
        ("network", "bitcoin-testnet"),
        ("account", "tb1q" + "a" * 48),
        ("request_id", "f" * 32),
        ("request_digest", "f" * 64),
    ]:
        altered = copy.deepcopy(response)
        altered[field] = bad
        with pytest.raises(ValueError):
            QRSession(request, now=0).check_response(altered, now=1, verify_signature=verify_expected)


def test_expiry_cancel_and_replay():
    request = fixture("bitcoin-testnet", "12345678")
    response = make_response(request, {"signed": "public-test-only"})
    session = QRSession(request, now=5, ttl=10)
    with pytest.raises(ValueError, match="expired"):
        session.check_response(response, now=16, verify_signature=verify_expected)
    session = QRSession(request, now=5)
    session.cancel()
    with pytest.raises(ValueError, match="Cancelled"):
        session.check_response(response, now=6, verify_signature=verify_expected)


def test_reject_modified_request_or_signed_payload():
    request = fixture()
    response = make_response(request, {"signed": "public-test-only"})
    altered = copy.deepcopy(response)
    altered["payload"] = {"signed": "tampered"}
    with pytest.raises(ValueError, match="digest"):
        QRSession(request, now=0).check_response(altered, now=1, verify_signature=verify_expected)
    altered_request = copy.deepcopy(request)
    altered_request["payload"]["transaction"]["nonce"] = 14
    with pytest.raises(ValueError, match="digest"):
        QRSession(altered_request)


@pytest.mark.parametrize("network", ["ethereum-mainnet", "bitcoin-mainnet", "arbitrum"])
def test_mainnet_and_other_networks_not_supported(network):
    with pytest.raises(ValueError):
        fixture(network=network)


@pytest.mark.parametrize("payload", [
    {"mnemonic": "public-test-word"},
    {"nested": {"private_key": "unsafe"}},
    {"value": [float("nan")]},
    {"unicode": "錢包"},
    {"nested": [[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]},
])
def test_malicious_qr_payload_is_rejected(payload):
    with pytest.raises(ValueError):
        make_request("sepolia", "12345678", payload)


def test_oversize_protocol_version_and_session_bounds():
    with pytest.raises(ValueError):
        make_request("sepolia", "12345678", {"data": "x" * 200000})
    with pytest.raises(ValueError):
        QRSession(fixture(), ttl=121)
    request = fixture()
    request["version"] = 2
    with pytest.raises(ValueError):
        QRSession(request)
