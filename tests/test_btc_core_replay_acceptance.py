"""Independent Issue #21/#82 acceptance at the Core PSBT -> V2 -> policy -> journal boundary.

All wallet material is the publicly compromised BIP39 test vector. The Core
fixture was independently finalized on regtest; this is NOT a USB hardware test.
"""
import copy
import hashlib
import json
from pathlib import Path

import pytest
from embit import transaction

from usb_cold_wallet.btc import review_btc_psbt, sign_btc_psbt
from usb_cold_wallet.cross_boot import (
    package_v2_request, package_v2_response, verify_v2_response,
)
from usb_cold_wallet.keys import root_from_mnemonic
from usb_cold_wallet.policy import default_profile, enforce_review_policy, set_limit
from usb_cold_wallet.transaction_state import (
    PendingRequestStore, ReplayLedger, RollbackDetected, StateCorruptionError,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "bitcoin_core_bip84_regtest_e2e.json").read_text()
)
ROOT = root_from_mnemonic(FIXTURE["public_bip39_mnemonic"])
EXPIRY = {"mode": "trusted-time", "notAfter": 200}


def core_request(request_id="a1" * 16):
    return package_v2_request(
        "btc-request", FIXTURE["enriched_psbt_base64"],
        request_id=request_id, account=ROOT.my_fingerprint.hex(),
        recipient=FIXTURE["recipient_testnet"], amount=FIXTURE["recipient_sats"],
        expiry=EXPIRY,
    )


def _rewrite_journal_record(root, mutator):
    """Rehash and rename a malicious record so superficial digest checks pass."""
    old = next(root.glob("*.json"))
    record = json.loads(old.read_text(encoding="utf-8"))
    mutator(record)
    fields = {k: v for k, v in record.items() if k != "recordDigest"}
    record["recordDigest"] = hashlib.sha256(json.dumps(
        fields, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")).hexdigest()
    new = root / (
        old.name.split(".")[0] + "." + old.name.split(".")[1] +
        "." + record["recordDigest"] + ".json"
    )
    old.unlink()
    new.write_text(json.dumps(record), encoding="utf-8")


def test_core_oracle_through_policy_replay_and_online_import(tmp_path):
    request = core_request()
    reviewed = review_btc_psbt(
        ROOT, request["payload"], FIXTURE["recipient_testnet"],
        FIXTURE["recipient_sats"], FIXTURE["fee_sats"], 0,
    )
    assert request["intent"]["fee"] == FIXTURE["fee_sats"]
    _, decision = enforce_review_policy(default_profile(ROOT), ROOT, reviewed, kind="btc")
    assert decision.status == "REQUIRE_EXTRA_CONFIRMATION"

    # An independently verified public PSBT can still be rejected by the
    # stricter local policy. Online metadata cannot override this decision.
    limited = set_limit(default_profile(ROOT), ROOT, "btc_max_fee_sats", 500)
    with pytest.raises(ValueError, match="Offline policy denied"):
        enforce_review_policy(limited, ROOT, reviewed, kind="btc")

    cold = ReplayLedger(tmp_path / "cold")
    cold.review_once(request, expected_account=ROOT.my_fingerprint.hex(), trusted_time=100)
    signed = sign_btc_psbt(
        ROOT, request["payload"], FIXTURE["recipient_testnet"],
        FIXTURE["recipient_sats"], FIXTURE["fee_sats"], 0,
    )
    response = package_v2_response(request, signed, trusted_time=100)
    assert verify_v2_response(request, response, trusted_time=100) == signed
    assert transaction.Transaction.parse(
        bytes.fromhex(signed["finalized_tx_hex"])
    ).txid().hex() == FIXTURE["core_txid"]
    assert cold.mark_signed(request, response, trusted_time=100).state == "SIGNED"

    # Cross-process recovery permits verified import, never implicit broadcast.
    online_path = tmp_path / "online"
    online = PendingRequestStore(online_path)
    online.create(request)
    online.exported(request)
    assert PendingRequestStore(online_path).import_verified(
        request, response, trusted_time=100
    ).state == "IMPORTED_VERIFIED"
    assert PendingRequestStore(online_path).get(request["requestId"]).state != "BROADCASTED"

    with pytest.raises(ValueError, match="Duplicate requestId"):
        ReplayLedger(tmp_path / "cold").review_once(
            request, expected_account=ROOT.my_fingerprint.hex(), trusted_time=100
        )


def test_core_signed_response_replacement_fails_before_import(tmp_path):
    request = core_request()
    signed = sign_btc_psbt(
        ROOT, request["payload"], FIXTURE["recipient_testnet"],
        FIXTURE["recipient_sats"], FIXTURE["fee_sats"], 0,
    )
    response = package_v2_response(request, signed, trusted_time=100)
    tampered = copy.deepcopy(response)
    tampered["requestId"] = "bb" * 16
    # An attacker can recompute a checksum, but not change the bound request.
    with pytest.raises(ValueError, match="does not match pending request"):
        verify_v2_response(request, tampered, trusted_time=100)
    store = PendingRequestStore(tmp_path / "online")
    store.create(request)
    store.exported(request)
    with pytest.raises(ValueError):
        store.import_verified(request, tampered, trusted_time=100)
    assert store.get(request["requestId"]).state == "EXPORTED"


@pytest.mark.parametrize("mutation", ["boolean_version", "numeric_request_id"])
def test_hostile_journal_rejects_rehashed_ambiguous_metadata(tmp_path, mutation):
    request = core_request()
    root = tmp_path / "online"
    PendingRequestStore(root).create(request)
    if mutation == "boolean_version":
        _rewrite_journal_record(root, lambda record: record.__setitem__("version", True))
    else:
        _rewrite_journal_record(root, lambda record: record.__setitem__("requestId", 42))
    with pytest.raises(StateCorruptionError):
        PendingRequestStore(root)


def test_cold_whole_store_rollback_negative_control_requires_external_tip(tmp_path):
    # This is an EXPECTED vulnerability demonstration, NOT a pass for USB
    # rollback resistance. Replacing the journal and its USB-local hash is easy.
    root = tmp_path / "cold"
    first = core_request("c1" * 16)
    second = core_request("c2" * 16)
    ledger = ReplayLedger(root)
    ledger.review_once(first, expected_account=ROOT.my_fingerprint.hex(), trusted_time=100)
    first_tip = ledger.tip_anchor()
    # Same unsigned transaction under another request ID is rejected even
    # after reopening. Replacing that request with another valid transaction
    # would be needed to create a new record; use a terminal mark_signed.
    signed = sign_btc_psbt(
        ROOT, first["payload"], FIXTURE["recipient_testnet"],
        FIXTURE["recipient_sats"], FIXTURE["fee_sats"], 0,
    )
    response = package_v2_response(first, signed, trusted_time=100)
    ledger.mark_signed(first, response, trusted_time=100)
    latest_tip = ledger.tip_anchor()
    assert latest_tip != first_tip
    # Removing the last record rolls the journal back to the valid old state.
    last = next(p for p in root.glob("*.json") if ".00000002." in p.name)
    last.unlink()
    with pytest.raises(RollbackDetected):
        ReplayLedger(root, expected_tip=latest_tip)
    reloaded = ReplayLedger(root)
    assert reloaded.rollback_resistant is False
    assert reloaded.tip_anchor() == first_tip
    # A USB-local copy of first_tip can be reverted together with the history.
    # Thus this reopened journal has no authenticated knowledge of its past SIGNED state.
    assert reloaded.get(first["requestId"]).state == "COLD_REVIEWED"
