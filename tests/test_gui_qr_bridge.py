"""Post-merge GUI/QR/USB integration: public compromised test vectors only.

These tests exercise OfflineReviewApp's actual entrypoint methods without a
Tk display or a physical camera. Hardware/optical acceptance remains separate.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from embit import bip32, psbt, script, transaction

from usb_cold_wallet import gui, vault
from usb_cold_wallet.exchange import package
from usb_cold_wallet.gui import OfflineReviewApp
from usb_cold_wallet.gui_qr_bridge import (
    parse_qr_input, bind_qr_to_review, signed_qr_text,
)
from usb_cold_wallet.keys import btc_address, btc_key, evm_account, root_from_mnemonic
from usb_cold_wallet.policy import default_profile
from usb_cold_wallet.qr_workflow import (
    prepare_evm_qr, prepare_btc_qr, verify_evm_response, verify_btc_response,
)
from usb_cold_wallet.qr_session import make_request
from usb_cold_wallet.review import ReviewSession, build_review_plan
from usb_cold_wallet.signer_session import SignerSession, State


ROOT = root_from_mnemonic("abandon " * 11 + "about")  # public, compromised BIP39 vector
RECIPIENT = "0x000000000000000000000000000000000000dEaD"
WEI = 10**16  # > JS Number.MAX_SAFE_INTEGER, must remain exact


def evm_transaction():
    return {
        "type": 2, "chainId": 11155111, "nonce": 7,
        "to": RECIPIENT, "value": WEI, "gas": 21000,
        "maxFeePerGas": 2_000_000_000, "maxPriorityFeePerGas": 1_000_000_000,
        "data": "0x",
    }


def btc_qr_request():
    key = btc_key(ROOT, 0, 0)
    destination = btc_address(ROOT, 0, 1)
    prev_tx = transaction.Transaction(
        vin=[transaction.TransactionInput(bytes.fromhex("11" * 32), 0)],
        vout=[transaction.TransactionOutput(120000, script.p2wpkh(key.key))],
    )
    tx = transaction.Transaction(
        vin=[transaction.TransactionInput(prev_tx.txid(), 0)],
        vout=[
            transaction.TransactionOutput(
                60000, script.address_to_scriptpubkey(destination)),
            transaction.TransactionOutput(
                58800, script.p2wpkh(btc_key(ROOT, 1, 0).key)),
        ],
    )
    signed = psbt.PSBT(tx)
    signed.inputs[0].witness_utxo = prev_tx.vout[0]
    signed.inputs[0].non_witness_utxo = prev_tx
    signed.inputs[0].bip32_derivations[key.key.get_public_key()] = psbt.DerivationPath(
        ROOT.my_fingerprint, bip32.parse_path("m/84h/1h/0h/0/0"))
    return prepare_btc_qr(
        signed.to_base64(), ROOT.my_fingerprint.hex(),
        destination, 60000, 1500, 0,
    )


def reviewed_session(envelope):
    plan = build_review_plan(envelope, ROOT)
    session = ReviewSession(plan)
    for index in range(len(plan.pages)):
        session.acknowledge(index, plan.review_digest)
    session.set_confirmation(plan.challenge, plan.review_digest)
    return session


def test_evm_qr_v1_to_gui_review_sign_and_correlated_online_response():
    request = prepare_evm_qr(evm_transaction(), evm_account(ROOT).address, RECIPIENT, WEI)
    envelope, original = parse_qr_input(json.dumps(request), "evm-request")
    bind_qr_to_review(original, reviewed_session(envelope).plan, ROOT)
    session = reviewed_session(envelope)
    signed = session.sign(ROOT, default_profile(ROOT), extra_confirmation="UNVERIFIED RECIPIENT")
    response = json.loads(signed_qr_text(original, signed, "evm-signed"))
    checked = verify_evm_response(request, response)
    assert checked["chain_id"] == 11155111
    assert checked["value_wei"] == WEI
    assert response["request_id"] == request["request_id"]
    assert response["request_digest"]
    assert "signed_raw_transaction" in checked


def test_btc_qr_v1_to_gui_review_sign_and_correlated_online_response():
    request = btc_qr_request()
    envelope, original = parse_qr_input(json.dumps(request), "btc-request")
    session = reviewed_session(envelope)
    bind_qr_to_review(original, session.plan, ROOT)
    signed = session.sign(ROOT, default_profile(ROOT), extra_confirmation="UNVERIFIED RECIPIENT")
    response = json.loads(signed_qr_text(original, signed, "btc-signed"))
    checked = verify_btc_response(request, response)
    assert checked["signature_count"] == 1
    assert response["request_id"] == request["request_id"]


def test_gui_qr_rejects_wrong_network_and_sender_and_metadata_without_unlock():
    request = prepare_evm_qr(evm_transaction(), evm_account(ROOT).address, RECIPIENT, WEI)
    with pytest.raises(ValueError):
        parse_qr_input(json.dumps(request), "btc-request")
    envelope, original = parse_qr_input(json.dumps(request), "evm-request")
    plan = build_review_plan(envelope, ROOT)
    bad_sender = make_request("sepolia", "0x0000000000000000000000000000000000000001", request["payload"])
    with pytest.raises(ValueError, match="account"):
        bind_qr_to_review(bad_sender, plan, ROOT)
    bad_payload = copy.deepcopy(request["payload"])
    bad_payload["amount_wei"] += 1
    bad_request = make_request("sepolia", request["account"], bad_payload)
    bad_env, bad_original = parse_qr_input(json.dumps(bad_request), "evm-request")
    with pytest.raises(ValueError, match="amount"):
        bind_qr_to_review(bad_original, build_review_plan(bad_env, ROOT), ROOT)
    malformed = json.dumps(request).replace('"version": 1', '"version": 1, "version": 1', 1)
    with pytest.raises(ValueError, match="Duplicate"):
        parse_qr_input(malformed, "evm-request")
    with pytest.raises(ValueError):
        parse_qr_input(json.dumps({"unexpected": True}), "evm-request")


class _Messages:
    def __init__(self):
        self.errors = []

    def showerror(self, *args, **kwargs):
        self.errors.append(args)

    def showwarning(self, *args, **kwargs):
        self.errors.append(args)


def make_gui(tmp_path):
    app = OfflineReviewApp.__new__(OfflineReviewApp)
    app.language = "zh-TW"
    app.transfer_dir = tmp_path
    app.development_mode = False
    app.wallet_root = None
    app.policy_profile = None
    app.session = None
    app.selected_kind = "evm-request"
    app._active_usb_file = None
    app._active_usb_identity = None
    app._active_usb_digest = None
    app._active_qr_request = None
    app._signed_qr_text = None
    app.page_index = 0
    app.status_message = ""
    app.root = object()
    app.messagebox = _Messages()
    app.simpledialog = SimpleNamespace(askstring=lambda *a, **kw: "UNVERIFIED RECIPIENT")
    app.rendered = []
    app._render_review = lambda: app.rendered.append("review")
    app._render_signed = lambda: app.rendered.append("signed")
    app._render_home = lambda: app.rendered.append("home")
    app.security = SignerSession(
        audit=lambda: True, on_lock=app._drop_wallet_references,
        clock=lambda: 100.0,
    )

    def unlock():
        assert app.wallet_root is None and app.security.state == State.LOCKED
        app.security.begin_unlock()
        app.security.unlock_succeeded()
        app.wallet_root = ROOT
        app.policy_profile = default_profile(ROOT)
        return True

    app._unlock = unlock
    return app


def test_actual_gui_import_qr_sign_present_and_correlate(tmp_path):
    app = make_gui(tmp_path)
    request = prepare_evm_qr(evm_transaction(), evm_account(ROOT).address, RECIPIENT, WEI)
    snapshots = []

    def scanned_text():
        snapshots.append((app.wallet_root, app.security.state))
        return json.dumps(request)

    app.qr_reader = scanned_text
    emitted = []
    app.qr_presenter = emitted.append
    app._import_qr()
    assert snapshots == [(None, State.LOCKED)]  # camera remains locked
    assert app.security.state == State.REVIEWING
    assert app.rendered == ["review"]
    assert app.session.plan.amount_atomic == WEI
    for index in range(len(app.session.plan.pages)):
        app.session.acknowledge(index, app.session.plan.review_digest)
    app.session.set_confirmation(app.session.plan.challenge, app.session.plan.review_digest)
    app._sign()
    assert app.rendered == ["review", "signed"]
    assert app.security.state == State.SIGNED
    app._present_signed_qr()
    response = json.loads(emitted[0])
    assert verify_evm_response(request, response)["value_wei"] == WEI
    assert response["request_digest"]
    app._done()
    assert app.wallet_root is None
    assert app._signed_qr_text is None


def test_real_gui_preunlock_rejects_bad_qr(tmp_path):
    app = make_gui(tmp_path)
    app.qr_reader = lambda: json.dumps({"version": 99, "direction": "unsigned"})
    app._unlock = lambda: (_ for _ in ()).throw(AssertionError("Must reject before unlock"))
    app._import_qr()
    assert app.wallet_root is None and app.security.state == State.LOCKED
    assert app.messagebox.errors


def test_real_gui_usb_path_guards_nested_symlinks_for_import_and_export(tmp_path):
    transfer = tmp_path / "transfer"
    outside = tmp_path / "outside"
    transfer.mkdir()
    outside.mkdir()
    (outside / "request.json").write_text('{"forbidden": true}')
    (transfer / "alias").symlink_to(outside, target_is_directory=True)
    app = make_gui(transfer)
    escaped = transfer / "alias" / "request.json"
    escaped_output = transfer / "alias" / "signed.json"
    assert not app._path_allowed(escaped)
    assert not app._path_allowed(escaped_output)
    with pytest.raises((OSError, ValueError)):
        app._read_transfer_snapshot(escaped)
    with pytest.raises((OSError, ValueError)):
        app._open_transfer_fd(escaped_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    assert not (outside / "signed.json").exists()

    # An entirely internal symlink is prohibited too (fail closed).
    (transfer / "nested").mkdir()
    (transfer / "internal").symlink_to(transfer / "nested", target_is_directory=True)
    assert not app._path_allowed(transfer / "internal" / "request.json")
    good = transfer / "request.json"
    good.write_bytes(b"safe")
    raw, (dev, inode) = app._read_transfer_snapshot(good)
    assert raw == b"safe"
    assert (dev, inode) == (good.stat().st_dev, good.stat().st_ino)


def test_usb_v1_envelope_remains_compatible_with_gui_qr_input():
    original = package("evm-request", evm_transaction())
    normalized, qr = parse_qr_input(json.dumps(original), "evm-request")
    assert normalized == original
    assert qr is None


def test_real_gui_qr_import_policy_sign_companion_verify_and_broadcast(tmp_path):
    """Companion → actual GUI QR import → policy/sign → strict Companion → send."""
    from eth_utils import keccak
    from usb_cold_wallet.companion_core import CompanionSession, canonical
    from usb_cold_wallet.keys import watch_only

    class FakeRpc:
        display_endpoint = "https://fake-sepolia.example"
        def __init__(self):
            self.sent = []
        def assert_sepolia(self):
            pass
        def account_state(self, address):
            assert address == evm_account(ROOT).address
            return 5 * 10**18, 7
        def fee_quote(self):
            return 2_000_000_000, 1_000_000_000
        def call(self, method, params):
            if method == "eth_getTransactionCount":
                return hex(7)
            if method == "eth_sendRawTransaction":
                self.sent.append(params[0])
                return "0x" + keccak(hexstr=params[0]).hex()
            raise AssertionError(method)

    rpc = FakeRpc()
    online = CompanionSession(rpc)
    online.import_wallet(canonical(watch_only(ROOT, count=2)))
    prepared = online.prepare(RECIPIENT, "0.01")
    tx = prepared["pending"]["tx"]
    native = prepare_evm_qr(
        tx, evm_account(ROOT).address, RECIPIENT, tx["value"],
        request_id=prepared["pending"]["request_id"],
    )

    app = make_gui(tmp_path)
    app.qr_reader = lambda: json.dumps(native)
    emitted = []
    app.qr_presenter = emitted.append
    app._import_qr()
    assert app.security.state == State.REVIEWING
    for index in range(len(app.session.plan.pages)):
        app.session.acknowledge(index, app.session.plan.review_digest)
    app.session.set_confirmation(app.session.plan.challenge, app.session.plan.review_digest)
    app._sign()
    assert app.security.state == State.SIGNED
    app._present_signed_qr()
    response = json.loads(emitted[0])
    signed = verify_evm_response(native, response)
    assert signed["value_wei"] == 10**16
    # Companion does its own pending-request, sender, raw transaction and fee validation.
    verified = online.accept_signed(canonical(package("evm-signed", signed)))
    assert verified["stage"] == "verified"
    online.broadcast()
    assert len(rpc.sent) == 1

    # A previously signed response must not authorize a different pending intent.
    another = CompanionSession(FakeRpc())
    another.import_wallet(canonical(watch_only(ROOT, count=2)))
    another.prepare(RECIPIENT, "0.02")
    with pytest.raises(ValueError):
        another.accept_signed(canonical(package("evm-signed", signed)))
    assert another.rpc.sent == []


def test_signed_usb_export_is_create_only_and_stays_under_transfer_dir(tmp_path):
    app = make_gui(tmp_path)
    req = prepare_evm_qr(evm_transaction(), evm_account(ROOT).address, RECIPIENT, WEI)
    app.qr_reader = lambda: json.dumps(req)
    app.qr_presenter = lambda value: None
    app._import_qr()
    for index in range(len(app.session.plan.pages)):
        app.session.acknowledge(index, app.session.plan.review_digest)
    app.session.set_confirmation(app.session.plan.challenge, app.session.plan.review_digest)
    app._sign()
    target = tmp_path / "signed-response.json"
    app._write_transfer_signed(target)
    assert json.loads(target.read_text())["kind"] == "evm-signed"
    with pytest.raises(FileExistsError):
        app._write_transfer_signed(target)


def test_actual_btc_gui_qr_import_review_policy_and_online_verification(tmp_path):
    app = make_gui(tmp_path)
    app.selected_kind = "btc-request"
    original = btc_qr_request()
    app.qr_reader = lambda: json.dumps(original)
    qr_output = []
    app.qr_presenter = qr_output.append
    app._import_qr()
    assert app.security.state == State.REVIEWING
    assert app.session.plan.kind == "btc"
    assert app.session.plan.amount_atomic == 60000
    for index in range(len(app.session.plan.pages)):
        app.session.acknowledge(index, app.session.plan.review_digest)
    app.session.set_confirmation(app.session.plan.challenge, app.session.plan.review_digest)
    app._sign()
    assert app.security.state == State.SIGNED
    app._present_signed_qr()
    result = json.loads(qr_output[0])
    assert verify_btc_response(original, result)["signature_count"] == 1
    app._done()
    assert app.wallet_root is None


@pytest.mark.parametrize("invalid_index", [False, True, -1, 2**31, "0"])
def test_btc_qr_change_index_rejects_non_integer_and_out_of_range(invalid_index):
    original = btc_qr_request()
    payload = copy.deepcopy(original["payload"])
    payload["change_index"] = invalid_index
    forged = make_request("bitcoin-testnet", ROOT.my_fingerprint.hex(), payload)
    envelope, parsed = parse_qr_input(json.dumps(forged), "btc-request")
    plan = build_review_plan(envelope, ROOT)
    with pytest.raises(ValueError, match="change index"):
        bind_qr_to_review(parsed, plan, ROOT)


def _signed_test_gui(tmp_path):
    app = make_gui(tmp_path)
    request = prepare_evm_qr(evm_transaction(), evm_account(ROOT).address, RECIPIENT, WEI)
    app.qr_reader = lambda: json.dumps(request)
    app._import_qr()
    for index in range(len(app.session.plan.pages)):
        app.session.acknowledge(index, app.session.plan.review_digest)
    app.session.set_confirmation(app.session.plan.challenge, app.session.plan.review_digest)
    app._sign()
    assert app.security.state == State.SIGNED
    return app


def test_signed_usb_export_fsync_error_cleans_only_its_own_file(monkeypatch, tmp_path):
    app = _signed_test_gui(tmp_path)
    target = tmp_path / "recoverable-signed.json"
    real_fsync = gui.os.fsync

    def failed_fsync(_fd):
        raise OSError(5, "simulated USB writeback failure")

    monkeypatch.setattr(gui.os, "fsync", failed_fsync)
    with pytest.raises(OSError, match="writeback failure"):
        app._write_transfer_signed(target)
    assert not target.exists(), "A failed write must not leave a blocking partial file"
    monkeypatch.setattr(gui.os, "fsync", real_fsync)
    app._write_transfer_signed(target)
    assert json.loads(target.read_text())["kind"] == "evm-signed"


def test_failed_export_cleanup_keeps_preexisting_or_replaced_files(tmp_path):
    app = make_gui(tmp_path)
    target = tmp_path / "preserve.json"
    target.write_bytes(b"unrelated existing content")
    info = target.stat()
    app._cleanup_failed_export(target, (info.st_dev, info.st_ino + 1))
    assert target.read_bytes() == b"unrelated existing content"
    (tmp_path / "alias").symlink_to(target)
    app._cleanup_failed_export(tmp_path / "alias", (info.st_dev, info.st_ino))
    assert target.read_bytes() == b"unrelated existing content"


def test_signed_export_not_visible_until_atomic_publish(monkeypatch, tmp_path):
    app = _signed_test_gui(tmp_path)
    target = tmp_path / "signed.json"
    original = vault._atomic_rename_noreplace
    seen = []

    def observe(parent, staging, final):
        assert not target.exists()
        assert staging.endswith(".partial")
        with os.fdopen(os.open(staging, os.O_RDONLY, dir_fd=parent), "rb") as f:
            assert json.load(f)["kind"] == "evm-signed"
        seen.append(staging)
        original(parent, staging, final)

    monkeypatch.setattr(vault, "_atomic_rename_noreplace", observe)
    app._write_transfer_signed(target)
    assert seen and json.loads(target.read_text())["kind"] == "evm-signed"
    assert not list(tmp_path.glob(".*.partial"))


def test_signed_export_short_write_is_retried(monkeypatch, tmp_path):
    app = _signed_test_gui(tmp_path)
    actual = gui.os.write
    calls = []

    def short_once(fd, data):
        calls.append(len(data))
        return actual(fd, data[:13] if len(calls) == 1 else data)

    with monkeypatch.context() as m:
        m.setattr(gui.os, "write", short_once)
        app._write_transfer_signed(tmp_path / "signed.json")
    assert len(calls) >= 2
    assert json.loads((tmp_path / "signed.json").read_text())["kind"] == "evm-signed"


def test_signed_export_enospc_cleans_stage_and_can_retry(monkeypatch, tmp_path):
    app = _signed_test_gui(tmp_path)
    actual = gui.os.write
    target = tmp_path / "signed.json"
    calls = []

    def fail_after_partial(fd, data):
        calls.append(len(data))
        if len(calls) == 1:
            actual(fd, data[:17])
        raise OSError(28, "simulated USB full during write")

    with monkeypatch.context() as m:
        m.setattr(gui.os, "write", fail_after_partial)
        with pytest.raises(OSError, match="USB full"):
            app._write_transfer_signed(target)
    assert not target.exists()
    assert not list(tmp_path.glob(".*.partial"))
    app._write_transfer_signed(target)
    assert json.loads(target.read_text())["kind"] == "evm-signed"


def test_signed_export_rename_collision_never_overwrites(monkeypatch, tmp_path):
    app = _signed_test_gui(tmp_path)
    target = tmp_path / "exists.json"
    target.write_bytes(b"keep existing data")
    with pytest.raises(FileExistsError):
        app._write_transfer_signed(target)
    assert target.read_bytes() == b"keep existing data"
    assert not list(tmp_path.glob(".*.partial"))


def test_signed_export_rename_unavailable_fails_closed(monkeypatch, tmp_path):
    app = _signed_test_gui(tmp_path)
    target = tmp_path / "no-atomic.json"

    def unavailable(*args):
        raise OSError(38, "renameat2 unavailable")

    monkeypatch.setattr(vault, "_atomic_rename_noreplace", unavailable)
    with pytest.raises(OSError, match="renameat2 unavailable"):
        app._write_transfer_signed(target)
    assert not target.exists()
    assert not list(tmp_path.glob(".*.partial"))


def test_signed_export_rejects_final_symlink(tmp_path):
    app = _signed_test_gui(tmp_path)
    outside = tmp_path.parent / (tmp_path.name + "-existing.txt")
    outside.write_bytes(b"untouched")
    target = tmp_path / "alias.json"
    target.symlink_to(outside)
    with pytest.raises((ValueError, FileExistsError, OSError)):
        app._write_transfer_signed(target)
    assert outside.read_bytes() == b"untouched"
    assert not list(tmp_path.glob(".*.partial"))


def test_usb_gui_rejects_hidden_partial_exchange_and_non_json_paths(tmp_path):
    app = make_gui(tmp_path)
    for name in (".usbwallet-incomplete.partial", ".hidden.json", "request.tmp"):
        path = tmp_path / name
        path.write_text("{}", encoding="utf-8")
        with pytest.raises(ValueError, match="completed .json"):
            app._read_transfer_snapshot(path)

    signed = _signed_test_gui(tmp_path)
    for name in (".hidden.json", "signed.partial", "signed.tmp"):
        with pytest.raises(ValueError, match="visible .json"):
            signed._write_transfer_signed(tmp_path / name)
    assert not list(tmp_path.glob(".*.partial"))
