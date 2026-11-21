"""Issue #17 BTC testnet tests; public, deliberately compromised test mnemonic."""
import copy
import json
import math

import pytest
from embit import transaction, script, psbt
from eth_account import Account

from usb_cold_wallet.btc import sign_btc_psbt, review_btc_psbt
from usb_cold_wallet.companion_btc import (
    BitcoinCompanion, TestnetEsplora as EsploraClient, MAX_FEE_SATS, _parse_sats
)
from usb_cold_wallet.companion_core import canonical, pack_envelope, unpack_envelope, parse_watch_only
from usb_cold_wallet.keys import root_from_mnemonic, watch_only, btc_address, btc_key
from usb_cold_wallet.exchange import package as strict_exchange_package, verify as strict_exchange_verify

MNEMONIC = "abandon " * 11 + "about"  # PUBLIC known-compromised vector only
ROOT = root_from_mnemonic(MNEMONIC)
WATCH = watch_only(ROOT, 3)
RECEIVE = WATCH["bitcoin"]["receive_addresses"][0]
TARGET = btc_address(ROOT, 0, 1)


class FakeEsplora:
    display_endpoint = "https://fake-bitcoin-testnet.example/api"

    def __init__(self, sats=150_000):
        # Synthetic prev transaction, never user funds.
        tx = transaction.Transaction(version=2, vin=[
            transaction.TransactionInput(bytes.fromhex("ab" * 32), 0, sequence=0xFFFFFFFF)
        ], vout=[
            transaction.TransactionOutput(sats, script.address_to_scriptpubkey(RECEIVE))
        ], locktime=0)
        self.previous_transaction = tx
        self.txid = tx.txid().hex()
        self.balance = sats
        self.duplicate = False
        self.bad_value = False
        self.bad_status = False
        self.activity_used = set()
        self.send_error = False
        self.fake_hash = False
        self.sent = []
        self.status_data = {"confirmed": False}

    def utxos(self, address):
        if address != RECEIVE:
            return []
        record = {"txid": self.txid, "vout": 0, "value": self.balance,
                  "status": {"confirmed": True}}
        if self.bad_value:
            record["value"] += 1
        if self.bad_status:
            record["status"]["confirmed"] = 1
        return [record, dict(record)] if self.duplicate else [record]

    def activity(self, address):
        # Allow test to reserve an already-used change address.
        funded = 1 if address in self.activity_used else 0
        return {"chain_stats": {"funded_txo_count": funded},
                "mempool_stats": {"funded_txo_count": 0}}

    def previous(self, txid):
        assert txid == self.txid
        return self.previous_transaction

    def fee_rate(self):
        return 2

    def send(self, raw_hex):
        self.sent.append(raw_hex)
        if self.send_error:
            raise ValueError("timeout")
        result = transaction.Transaction.parse(bytes.fromhex(raw_hex)).txid().hex()
        return "00" * 32 if self.fake_hash else result

    def status(self, txid):
        return self.status_data


def companion(sats=150_000):
    rpc = FakeEsplora(sats)
    online = BitcoinCompanion(rpc)
    online.import_wallet(WATCH)
    return online, rpc


def test_master_fingerprint_export_and_old_watch_only_readonly():
    assert WATCH["bitcoin"]["master_fingerprint"] == ROOT.my_fingerprint.hex()
    assert parse_watch_only(canonical(WATCH))["bitcoin"]["master_fingerprint"] == ROOT.my_fingerprint.hex()
    old = copy.deepcopy(WATCH)
    old["bitcoin"].pop("master_fingerprint")
    assert parse_watch_only(canonical(old)) == old
    online, _ = companion()
    online.import_wallet(old)
    assert online.public_view()["spending_ready"] is False
    with pytest.raises(ValueError, match="fingerprint"):
        online.prepare(TARGET, "0.0005")
    bad = copy.deepcopy(WATCH)
    bad["bitcoin"]["master_fingerprint"] = "nothex"
    with pytest.raises(ValueError, match="fingerprint"):
        parse_watch_only(canonical(bad))


def test_btc_full_psbt_offline_sign_verify_broadcast_and_chain_status():
    online, rpc = companion()
    overview = online.overview()
    assert overview["confirmed_sats"] == 150_000
    assert overview["spending_ready"]
    result = online.prepare(TARGET, "0.0005")
    info = result["pending"]
    assert info["stage"] == "prepared" and info["input_count"] == 1
    assert info["change_sats"] >= 546 and info["change_index"] == 0
    assert result["envelope"] == online.request_envelope()
    encoded = unpack_envelope(result["envelope"], "btc-request")
    reviewed = review_btc_psbt(ROOT, encoded, TARGET, 50_000, MAX_FEE_SATS, 0)
    assert reviewed["amount_sats"] == 50_000 and reviewed["fee_sats"] == info["fee_sats"]

    # Existing legacy main signer returns signed PSBT, no finalized hex.
    signed = sign_btc_psbt(ROOT, encoded, TARGET, 50_000, MAX_FEE_SATS, 0)
    verified = online.accept_signed(canonical(pack_envelope("btc-signed", signed)))
    assert verified["stage"] == "verified"
    assert len(verified["txid"]) == 64
    assert online.broadcast()["stage"] == "broadcasted"
    assert len(rpc.sent) == 1
    with pytest.raises(ValueError, match="Only one"):
        online.broadcast()
    assert online.check_status()["result"] == "pending"
    rpc.status_data = {"confirmed": True, "block_hash": "11"*32, "block_height": 50}
    assert online.check_status()["result"] == "confirmed"
    rpc.status_data = {"confirmed": False}
    assert online.check_status()["result"] == "reorg_suspected"
    assert online.check_status()["reorg_warning"]


def test_main_exchange_btc_psbt_signed_result_and_broadcast_are_compatible():
    """Use the same #11 strict PSBT validator and #26 pending-transaction binding."""
    online, rpc = companion()
    request = online.prepare(TARGET, "0.0005")["envelope"]
    encoded = strict_exchange_verify(request, "btc-request")
    assert strict_exchange_package("btc-request", encoded) == request
    signed = sign_btc_psbt(ROOT, encoded, TARGET, 50_000, MAX_FEE_SATS, 0)
    response = strict_exchange_package("btc-signed", signed)
    assert strict_exchange_verify(response, "btc-signed") == signed
    assert online.accept_signed(canonical(response))["stage"] == "verified"
    assert online.broadcast()["stage"] == "broadcasted"
    assert len(rpc.sent) == 1



def test_companion_usb_cli_policy_btc_sign_broadcast_end_to_end(tmp_path, monkeypatch):
    """Companion -> PSBT USB-B -> policy-authorized offline CLI -> signed PSBT -> pre-broadcast check."""
    import hashlib
    from usb_cold_wallet import cli
    from usb_cold_wallet.exchange import write as write_exchange
    from usb_cold_wallet.policy import default_profile, save_profile
    from usb_cold_wallet.vault import encrypt_mnemonic, save_vault

    password = "public-test-vector-signing-password"
    online, rpc = companion()
    req = online.prepare(TARGET, "0.0005")
    decoded = strict_exchange_verify(req["envelope"], "btc-request")
    vault = tmp_path / "test.vault"
    save_vault(vault, encrypt_mnemonic(MNEMONIC, password))
    policy = vault.with_name(vault.name + ".policy")
    save_profile(policy, default_profile(ROOT), ROOT, password)
    anchor = hashlib.sha256(policy.read_bytes()).hexdigest()
    incoming, outgoing = tmp_path / "unsigned.json", tmp_path / "signed.json"
    write_exchange(incoming, "btc-request", decoded)
    monkeypatch.setattr(cli.getpass, "getpass",
                        lambda prompt: password if prompt.startswith("Vault") else "")
    monkeypatch.setattr("builtins.input",
                        lambda prompt: prompt.split("type '", 1)[1].split("'", 1)[0])
    assert cli.main([
        "--vault", str(vault), "sign-btc", "--request", str(incoming),
        "--to", TARGET, "--sats", "50000", "--max-fee-sats", str(MAX_FEE_SATS),
        "--change-index", str(req["pending"]["change_index"]),
        "--expected-policy-sha256", anchor, "--out", str(outgoing),
    ]) == 0
    assert strict_exchange_verify(json.loads(outgoing.read_bytes()), "btc-signed")["signature_count"] == 1
    assert online.accept_signed(outgoing.read_bytes())["stage"] == "verified"
    assert online.broadcast()["stage"] == "broadcasted"
    assert len(rpc.sent) == 1


def test_companion_qr_policy_btc_sign_broadcast_end_to_end():
    """Companion -> QR PSBT -> policy -> signed QR -> compare original unsigned tx -> broadcast."""
    from usb_cold_wallet.policy import default_profile
    from usb_cold_wallet.qr_workflow import (
        prepare_btc_qr, sign_offline, verify_btc_response,
    )
    online, rpc = companion()
    req = online.prepare(TARGET, "0.0005")
    encoded = strict_exchange_verify(req["envelope"], "btc-request")
    change = req["pending"]["change_index"]
    request = prepare_btc_qr(
        encoded, ROOT.my_fingerprint.hex(), TARGET, 50000, MAX_FEE_SATS, change)
    response = sign_offline(
        ROOT, request, recipient=TARGET, amount=50000,
        max_fee_sats=MAX_FEE_SATS, change_index=change,
        profile=default_profile(ROOT), extra_confirmation="UNVERIFIED RECIPIENT",
    )
    assert verify_btc_response(request, response)["signature_count"] == 1
    signed = strict_exchange_package("btc-signed", response["payload"])
    other, other_rpc = companion()
    other.prepare(TARGET, "0.0004")
    with pytest.raises(ValueError):
        other.accept_signed(canonical(signed))
    assert other_rpc.sent == []  # Reject mismatched original BTC outputs before broadcast.
    assert online.accept_signed(canonical(signed))["stage"] == "verified"
    assert online.broadcast()["stage"] == "broadcasted"
    assert len(rpc.sent) == 1


def test_companion_gui_policy_btc_sign_broadcast_end_to_end():
    """Companion -> GUI ReviewSession -> policy -> exact signed-v1 PSBT -> broadcast."""
    from usb_cold_wallet.policy import default_profile
    from usb_cold_wallet.review import ReviewSession, build_review_plan
    online, rpc = companion()
    req = online.prepare(TARGET, "0.0005")
    plan = build_review_plan(req["envelope"], ROOT, "btc-request")
    session = ReviewSession(plan)
    for index in range(len(plan.pages)):
        session.acknowledge(index, plan.review_digest)
    session.set_confirmation(plan.challenge, plan.review_digest)
    signed = session.sign(ROOT, default_profile(ROOT),
                          extra_confirmation="UNVERIFIED RECIPIENT")
    assert strict_exchange_verify(signed, "btc-signed") == signed["payload"]
    assert online.accept_signed(canonical(signed))["stage"] == "verified"
    assert online.broadcast()["stage"] == "broadcasted"
    assert len(rpc.sent) == 1


def test_hardened_signer_output_with_finalized_transaction_is_checked():
    online, _ = companion()
    encoded = unpack_envelope(online.prepare(TARGET, "0.0005")["envelope"], "btc-request")
    signed = sign_btc_psbt(ROOT, encoded, TARGET, 50_000, MAX_FEE_SATS, 0)
    p = psbt.PSBT.from_base64(signed["signed_psbt_base64"])
    finalized = transaction.Transaction.parse(p.tx.serialize())
    for i, inp in enumerate(p.inputs):
        pub, signature = next(iter(inp.partial_sigs.items()))
        finalized.vin[i].witness = transaction.Witness([signature, pub.sec()])
    signed["finalized_tx_hex"] = finalized.serialize().hex()
    assert online.accept_signed(canonical(signed))["stage"] == "verified"


@pytest.mark.parametrize("mutator", [
    lambda p: p.update(recipient=RECEIVE),
    lambda p: p.update(amount_sats=1),
    lambda p: p.update(fee_sats=0),
    lambda p: p.update(network="bitcoin-mainnet"),
    lambda p: p.update(signature_count=2),
    lambda p: p.update(finalized_tx_hex="00112233"),
    lambda p: p.update(private_key="secret"),
])
def test_rejects_invalid_btc_signed_metadata(mutator):
    online, rpc = companion()
    request = online.prepare(TARGET, "0.0005")
    signed = sign_btc_psbt(ROOT, unpack_envelope(request["envelope"], "btc-request"),
                           TARGET, 50_000, MAX_FEE_SATS, 0)
    mutator(signed)
    with pytest.raises(ValueError):
        online.accept_signed(canonical(signed))
    assert not rpc.sent and online.pending["stage"] == "prepared"


def test_signed_psbt_changed_outputs_rejected_even_if_metadata_claims_ok():
    online, _ = companion()
    request = online.prepare(TARGET, "0.0005")
    signed = sign_btc_psbt(ROOT, unpack_envelope(request["envelope"], "btc-request"),
                           TARGET, 50_000, MAX_FEE_SATS, 0)
    p = psbt.PSBT.from_base64(signed["signed_psbt_base64"])
    p.outputs[0].value += 1
    signed["signed_psbt_base64"] = p.to_base64()
    with pytest.raises(ValueError):
        online.accept_signed(canonical(signed))


def test_btc_request_rejects_bad_utxo_wrong_prevout_fee_cap_and_duplicate():
    online, rpc = companion()
    rpc.bad_value = True
    with pytest.raises(ValueError, match="mismatch"):
        online.prepare(TARGET, "0.0005")
    online, rpc = companion()
    rpc.duplicate = True
    with pytest.raises(ValueError, match="Duplicate UTXO"):
        online.prepare(TARGET, "0.0005")
    online, rpc = companion()
    rpc.bad_status = True
    with pytest.raises(ValueError, match="Malformed"):
        online.prepare(TARGET, "0.0005")
    online, rpc = companion()
    with pytest.raises(ValueError, match="fee"):
        online.prepare(TARGET, "0.0005", max_fee_sats=1)
    online, rpc = companion(1000)
    with pytest.raises(ValueError, match="Insufficient"):
        online.prepare(TARGET, "0.0005")


def test_used_change_address_skipped_and_invalid_settings_rejected():
    online, rpc = companion()
    from embit import bip32, networks
    pub = bip32.HDKey.from_base58(WATCH["bitcoin"]["account_tpub"])
    first_change = script.p2wpkh(pub.derive("1/0").key).address(networks.NETWORKS["test"])
    rpc.activity_used.add(first_change)
    info = online.prepare(TARGET, "0.0005")["pending"]
    assert info["change_index"] == 1
    online, _ = companion()
    with pytest.raises(ValueError, match="fee"):
        online.prepare(TARGET, "0.0005", fee_rate_sat_vb=999)
    with pytest.raises(ValueError, match="BTC value"):
        online.prepare(TARGET, "0.000000001")


def test_mismatched_btc_signed_payload_cannot_replay_on_new_request():
    online, _ = companion()
    request = online.prepare(TARGET, "0.0005")
    signed = sign_btc_psbt(ROOT, unpack_envelope(request["envelope"], "btc-request"),
                           TARGET, 50_000, MAX_FEE_SATS, 0)
    online.cancel()
    online.prepare(TARGET, "0.0004")
    with pytest.raises(ValueError):
        online.accept_signed(canonical(signed))


def test_esplora_network_config_rejects_remote_http_and_credentials():
    for url in ("http://evil.example/api", "ftp://localhost/testnet/api",
                "https://user:pw@host.example/api", "https://site.example/api?token=abc"):
        with pytest.raises(ValueError):
            EsploraClient(url)
    assert EsploraClient("http://127.0.0.1:3000/testnet/api").display_endpoint == "http://127.0.0.1:3000/testnet/api"


def test_btc_broadcast_timeout_or_wrong_hash_no_retries():
    online, rpc = companion()
    result = online.prepare(TARGET, "0.0005")
    signed = sign_btc_psbt(ROOT, unpack_envelope(result["envelope"], "btc-request"),
                           TARGET, 50_000, MAX_FEE_SATS, 0)
    online.accept_signed(canonical(signed))
    rpc.send_error = True
    with pytest.raises(ValueError, match="unknown"):
        online.broadcast()
    assert len(rpc.sent) == 1 and online.pending["stage"] == "broadcast_unknown"
    with pytest.raises(ValueError):
        online.broadcast()



def test_btc_loopback_browser_api_full_flow_and_cross_origin_rejection():
    import http.client
    import threading
    from usb_cold_wallet.companion_web import create_server

    class DummyRpc:
        display_endpoint = "https://mock-sepolia.example"

    fake = FakeEsplora()
    server, _, token = create_server(DummyRpc(), 0, esplora=fake)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    port = server.server_port

    def call(path, payload=None, *, origin=True, auth=True):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {"Host": f"127.0.0.1:{port}"}
        if auth:
            headers["X-Companion-Token"] = token
        if origin:
            headers["Origin"] = f"http://127.0.0.1:{port}"
        method = "GET" if payload is None else "POST"
        if payload is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=None if payload is None else canonical(payload),
                     headers=headers)
        res = conn.getresponse()
        status, body = res.status, res.read()
        conn.close()
        return status, json.loads(body)

    try:
        assert call("/api/import", {"raw": canonical(WATCH).decode()}, origin=False)[0] == 403
        assert call("/api/import", {"raw": canonical(WATCH).decode()})[0] == 200
        assert call("/api/btc/wallet")[1]["spending_ready"]
        assert call("/api/btc/overview")[1]["confirmed_sats"] == 150_000
        status, created = call("/api/btc/prepare", {
            "recipient": TARGET, "amount_btc": "0.0005",
            "max_fee_sats": MAX_FEE_SATS, "fee_rate_sat_vb": None
        })
        assert status == 200
        status, outbound = call("/api/btc/request")
        assert status == 200 and outbound["kind"] == "btc-request"
        unsigned = unpack_envelope(outbound, "btc-request")
        signed = sign_btc_psbt(ROOT, unsigned, TARGET, 50_000, MAX_FEE_SATS, 0)
        assert call("/api/btc/accept", {"raw": canonical(signed).decode()})[1]["stage"] == "verified"
        assert call("/api/btc/broadcast", {})[1]["stage"] == "broadcasted"
        assert len(fake.sent) == 1
        assert call("/api/btc/status", {})[1]["result"] == "pending"
        assert call("/api/btc/broadcast", {})[0] == 400
        assert len(fake.sent) == 1
    finally:
        server.shutdown()
        server.server_close()
        worker.join(5)
