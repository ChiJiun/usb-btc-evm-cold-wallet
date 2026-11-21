"""Issue #21 attack tests: policy file replacement, rollback anchor, Unicode and malformed intents."""
import hashlib
import json
import math
from dataclasses import replace

import pytest
from embit import networks, script

from usb_cold_wallet import cli
from usb_cold_wallet.keys import root_from_mnemonic, btc_address
from usb_cold_wallet.policy import (
    TransactionIntent, default_profile, decide, load_profile, normalize_address,
    register_verified_address, save_profile, set_limit, validate_profile,
    wallet_binding,
)

# Publicly compromised BIP39 reference only. Never use it with funds.
ROOT = root_from_mnemonic("abandon " * 11 + "about")
PASSWORD = "known-test-policy-password-123456"
RECIPIENT = "0x000000000000000000000000000000000000dEaD"
TX = {
    "type": 2, "chainId": 11155111, "nonce": 3, "to": RECIPIENT,
    "value": 10**12, "gas": 21000, "maxFeePerGas": 2 * 10**9,
    "maxPriorityFeePerGas": 10**9, "data": "0x",
}


def test_encrypted_policy_rollback_requires_independent_anchor(tmp_path):
    policy = tmp_path / "wallet.vault.policy"
    old = default_profile(ROOT)
    save_profile(policy, old, ROOT, PASSWORD)
    original = policy.read_bytes()
    original_digest = hashlib.sha256(original).hexdigest()
    assert load_profile(policy, ROOT, PASSWORD, expected_sha256=original_digest) == old

    newer = set_limit(old, ROOT, "evm_max_value_wei", 1)
    save_profile(policy, newer, ROOT, PASSWORD, replace=True)
    latest_digest = hashlib.sha256(policy.read_bytes()).hexdigest()
    assert latest_digest != original_digest
    with pytest.raises(ValueError, match="corrupted or mismatched"):
        load_profile(policy, ROOT, PASSWORD, expected_sha256=original_digest)

    # Replacing the whole encrypted file with a valid older copy is NOT
    # detectable by AES-GCM alone. An independent current digest detects it.
    policy.write_bytes(original)
    assert load_profile(policy, ROOT, PASSWORD) == old
    with pytest.raises(ValueError, match="corrupted or mismatched"):
        load_profile(policy, ROOT, PASSWORD, expected_sha256=latest_digest)
    with pytest.raises(ValueError):
        load_profile(policy, ROOT, PASSWORD, expected_sha256="X" * 64)


def test_reject_large_nonregular_duplicate_json_and_symlinks(tmp_path):
    policy = tmp_path / "wallet.vault.policy"
    save_profile(policy, default_profile(ROOT), ROOT, PASSWORD)
    link = tmp_path / "link.policy"
    link.symlink_to(policy)
    with pytest.raises(ValueError):
        load_profile(link, ROOT, PASSWORD)

    for raw in [
        b"A" * 20000,
        b'{"format":"test","format":"test"}',
        b'{"format":NaN}',
        b'{"version":1,"version":2}',
    ]:
        policy.write_bytes(raw)
        with pytest.raises(ValueError):
            load_profile(policy, ROOT, PASSWORD)
    with pytest.raises(ValueError):
        load_profile(tmp_path, ROOT, PASSWORD)


@pytest.mark.parametrize("label", [
    "Known\u202eDeceiver",  # Unicode bidirectional display override
    "Wallet\u200bSafe",     # Invisible format mark
    "Full\nName",
    "Ｆｕｌｌｗｉｄｔｈ",  # Visually confusable normalization
])
def test_reject_unicode_label_spoofing(label):
    with pytest.raises(ValueError, match="label"):
        register_verified_address(default_profile(ROOT), ROOT, "sepolia", RECIPIENT, label)


def test_reject_btc_witness_script_hash_as_verified_bip84():
    p2wsh = script.Script(b"\x00\x20" + b"\x01" * 32).address(networks.NETWORKS["test"])
    assert p2wsh.startswith("tb1q")
    with pytest.raises(ValueError):
        normalize_address("bitcoin-testnet", p2wsh)


def test_policy_fails_closed_on_nan_fee_rate_and_inconsistent_intent():
    base = TransactionIntent(
        version=1, network="bitcoin-testnet", account=wallet_binding(ROOT),
        recipient=btc_address(ROOT, 0, 1), amount=1000, maximum_fee=100,
        maximum_total=1100, signature_type="PSBT P2WPKH SIGHASH_ALL",
        fee_rate=10.0,
    )
    policy = default_profile(ROOT)
    assert decide(policy, ROOT, base).status == "REQUIRE_EXTRA_CONFIRMATION"
    for tampered in [
        replace(base, fee_rate=float("nan")),
        replace(base, fee_rate=float("inf")),
        replace(base, maximum_total=1110),
        replace(base, maximum_fee=bool(1)),
    ]:
        assert decide(policy, ROOT, tampered).status == "DENY"

    from usb_cold_wallet.evm import review_evm_transaction
    from usb_cold_wallet.policy import evm_intent
    evm = evm_intent(ROOT, review_evm_transaction(TX, RECIPIENT, TX["value"]))
    for tampered in [
        replace(evm, max_priority_fee_per_gas=2 * 10**9 + 1),
        replace(evm, maximum_total=5),
        replace(evm, maximum_fee=0),
        replace(evm, nonce=-1),
        replace(evm, gas=30000),
    ]:
        assert decide(policy, ROOT, tampered).status == "DENY"


def test_cli_rejects_wrong_policy_anchor_before_signing(tmp_path, monkeypatch):
    policy = tmp_path / "wallet.vault.policy"
    save_profile(policy, default_profile(ROOT), ROOT, PASSWORD)
    tx = tmp_path / "sepolia.json"
    tx.write_text(json.dumps(TX))
    out = tmp_path / "not-signed.json"
    monkeypatch.setattr(cli, "_wallet_root", lambda _args: ROOT)
    monkeypatch.setattr(cli, "_password", lambda: PASSWORD)
    monkeypatch.setattr(cli, "_approve", lambda _: pytest.fail("No approval before matching policy anchor"))
    monkeypatch.setattr(cli, "sign_evm", lambda *_a, **_kw: pytest.fail("Never sign with wrong policy anchor"))
    args = [
        "--vault", str(tmp_path / "wallet.vault"),
        "sign-evm", "--tx", str(tx), "--to", RECIPIENT,
        "--wei", str(TX["value"]), "--out", str(out),
        "--expected-policy-sha256", "0" * 64,
    ]
    assert cli.main(args) == 1
    assert not out.exists()


@pytest.mark.parametrize("case", ["oversize", "symlink", "duplicate", "nan", "directory", "fifo"])
def test_unsigned_evm_usb_rejected_before_vault_unlock(tmp_path, monkeypatch, case):
    import os
    inbound = tmp_path / "untrusted.json"
    if case == "oversize":
        inbound.write_bytes(b"x" * 200_001)
    elif case == "duplicate":
        inbound.write_text('{"type":2,"type":2}', encoding="ascii")
    elif case == "nan":
        inbound.write_text('{"value":NaN}', encoding="ascii")
    elif case == "symlink":
        original = tmp_path / "original"
        original.write_text(json.dumps(TX), encoding="ascii")
        inbound.symlink_to(original)
    elif case == "directory":
        inbound.mkdir()
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("POSIX-only FIFO")
        os.mkfifo(inbound)
    monkeypatch.setattr(cli, "_wallet_root", lambda _args: pytest.fail("USB must be rejected before vault unlock"))
    argv = ["--vault", str(tmp_path / "wallet.vault"), "sign-evm",
            "--tx", str(inbound), "--to", RECIPIENT, "--wei", str(TX["value"]),
            "--out", str(tmp_path / "signed.json"), "--expected-policy-sha256", "0" * 64]
    assert cli.main(argv) == 1
    assert not (tmp_path / "signed.json").exists()


def test_btc_bad_usb_rejected_before_unlock(tmp_path, monkeypatch):
    inbound = tmp_path / "psbt.txt"
    inbound.write_text("not a psbt", encoding="ascii")
    monkeypatch.setattr(cli, "_wallet_root", lambda _args: pytest.fail("Bad PSBT must fail before unlock"))
    argv = ["--vault", str(tmp_path / "wallet.vault"), "sign-btc", "--psbt", str(inbound),
            "--to", btc_address(ROOT, 0, 1), "--sats", "1000",
            "--max-fee-sats", "1000", "--out", str(tmp_path / "signed.json"),
            "--expected-policy-sha256", "0" * 64]
    assert cli.main(argv) == 1


def test_missing_independent_anchor_rejected_before_unlock(tmp_path, monkeypatch):
    path = tmp_path / "unsigned.json"
    path.write_text(json.dumps(TX), encoding="utf-8")
    monkeypatch.setattr(cli, "_wallet_root",
                        lambda _args: pytest.fail("Missing anchor must fail before wallet unlock"))
    argv = ["--vault", str(tmp_path / "wallet.vault"), "sign-evm",
            "--tx", str(path), "--to", RECIPIENT, "--wei", str(TX["value"]),
            "--out", str(tmp_path / "signed.json")]
    assert cli.main(argv) == 1
    assert not (tmp_path / "signed.json").exists()


def test_policy_cli_prints_exact_current_digest_for_independent_record(tmp_path, capsys):
    policy = tmp_path / "wallet.vault.policy"
    save_profile(policy, default_profile(ROOT), ROOT, PASSWORD)
    cli._print_anchor_for_independent_record(policy)
    printed = capsys.readouterr().out
    assert hashlib.sha256(policy.read_bytes()).hexdigest() in printed
    assert "record independently" in printed
