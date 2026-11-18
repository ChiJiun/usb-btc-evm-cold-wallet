"""Policy tests use a publicly compromised mnemonic; never use for funds."""
from dataclasses import replace
import json

import pytest

from usb_cold_wallet.keys import root_from_mnemonic, evm_account, btc_address
from usb_cold_wallet.evm import review_evm_transaction
from usb_cold_wallet.policy import (
    default_profile, validate_profile, normalize_address, wallet_binding,
    register_verified_address, set_limit, save_profile, load_profile,
    evm_intent, decide, TransactionIntent, btc_intent,
)

MNEMONIC = "abandon " * 11 + "about"
PASSWORD = "testing-policy-password-long"
RECIPIENT = "0x000000000000000000000000000000000000dEaD"


@pytest.fixture(scope="module")
def root():
    return root_from_mnemonic(MNEMONIC)


def sample_evm_intent(root):
    tx = {"type": 2, "chainId": 11155111, "nonce": 7, "to": RECIPIENT,
          "value": 10**12, "gas": 21000, "maxFeePerGas": 2 * 10**9,
          "maxPriorityFeePerGas": 10**9, "data": "0x"}
    return evm_intent(root, review_evm_transaction(tx, RECIPIENT, 10**12))


def test_default_policy_requires_extra_confirmation_for_unknown_address(root):
    intent = sample_evm_intent(root)
    result = decide(default_profile(root), root, intent)
    assert result.status == "REQUIRE_EXTRA_CONFIRMATION"
    assert result.verified_label is None
    assert intent.nonce == 7 and intent.gas == 21000


def test_verified_label_never_hides_full_address(root):
    p = register_verified_address(default_profile(root), root, "sepolia", RECIPIENT, "Family")
    result = decide(p, root, sample_evm_intent(root))
    assert result.status == "ALLOW_FOR_REVIEW" and result.verified_label == "Family"
    assert sample_evm_intent(root).recipient == RECIPIENT


def test_fee_cap_and_wrong_account_fail_closed(root):
    intent = sample_evm_intent(root)
    p = set_limit(default_profile(root), root, "evm_max_fee_wei", 1)
    assert decide(p, root, intent).status == "DENY"
    assert decide(default_profile(root), root, replace(intent, account=RECIPIENT)).status == "DENY"
    assert decide(default_profile(root), root, replace(intent, network="bitcoin-testnet")).status == "DENY"
    assert decide(default_profile(root), root, replace(intent, signature_type="ERC20 approve")).status == "DENY"


def test_encrypted_roundtrip_and_tamper_fail_closed(root, tmp_path):
    p = register_verified_address(default_profile(root), root, "sepolia", RECIPIENT, "Known")
    path = tmp_path / "wallet.vault.policy"
    save_profile(path, p, root, PASSWORD)
    assert load_profile(path, root, PASSWORD) == p
    assert b"Known" not in path.read_bytes()
    with pytest.raises(ValueError):
        save_profile(path, p, root, PASSWORD)
    with pytest.raises(ValueError):
        load_profile(path, root, "another-password-123")
    blob = json.loads(path.read_text())
    blob["ciphertext"] = "AA=="
    path.write_text(json.dumps(blob))
    with pytest.raises(ValueError):
        load_profile(path, root, PASSWORD)


def test_incompatible_version_and_wrong_wallet(root):
    p = default_profile(root)
    with pytest.raises(ValueError, match="version"):
        validate_profile({**p, "version": 2}, root)
    with pytest.raises(ValueError, match="different wallet"):
        validate_profile(p, root_from_mnemonic("legal winner thank year wave sausage worth useful legal winner thank yellow"))


def test_address_book_rejects_duplicate_injection_and_fake_names(root):
    p = register_verified_address(default_profile(root), root, "sepolia", RECIPIENT, "Known")
    p["verified_addresses"].append(dict(p["verified_addresses"][0]))
    with pytest.raises(ValueError, match="Duplicate"):
        validate_profile(p, root)
    with pytest.raises(ValueError):
        register_verified_address(default_profile(root), root, "sepolia", RECIPIENT, "Fake\nPrompt")
    with pytest.raises(ValueError):
        normalize_address("bitcoin-testnet", RECIPIENT)


def test_bitcoin_account_binding_and_fee_rate(root):
    recipient = btc_address(root, 0, 1)
    reviewed = {"network": "bitcoin-testnet", "recipient": recipient,
                "amount_sats": 60000, "fee_sats": 2000,
                "psbt": type("StubPSBT", (), {"tx": type("TX", (), {"serialize": lambda self: b"a" * 120})()})()}
    intent = btc_intent(root, reviewed)
    assert intent.account == wallet_binding(root)
    assert 16 < intent.fee_rate < 17
    p = set_limit(default_profile(root), root, "btc_max_fee_rate_sat_vb", 10)
    assert decide(p, root, intent).status == "DENY"
    verified = register_verified_address(default_profile(root), root, "bitcoin-testnet", recipient, "Backup")
    assert decide(verified, root, intent).status == "ALLOW_FOR_REVIEW"


def test_policy_integrity_rejects_invalid_shape_bool_and_missing(root, tmp_path):
    p = default_profile(root)
    p["limits"]["btc_max_fee_sats"] = True
    with pytest.raises(ValueError):
        validate_profile(p, root)
    with pytest.raises(ValueError):
        load_profile(tmp_path / "missing", root, PASSWORD)
    p = default_profile(root)
    with pytest.raises(ValueError):
        set_limit(p, root, "unknown", 4)


def test_cli_never_signs_without_profile(root, tmp_path, monkeypatch):
    from usb_cold_wallet import cli
    vault = tmp_path / "wallet.vault"
    vault.write_text("placeholder")
    tx = tmp_path / "unsigned.json"
    tx.write_text(json.dumps({
        "type": 2, "chainId": 11155111, "nonce": 7, "to": RECIPIENT,
        "value": 10**12, "gas": 21000, "maxFeePerGas": 2 * 10**9,
        "maxPriorityFeePerGas": 10**9, "data": "0x",
    }))
    monkeypatch.setattr(cli, "_wallet_root", lambda args: root)
    monkeypatch.setattr(cli, "sign_evm", lambda *a, **kw: pytest.fail("signing bypassed policy"))
    monkeypatch.setattr(cli, "_approve", lambda phrase: pytest.fail("approval offered without policy"))
    args = ["--vault", str(vault), "sign-evm", "--tx", str(tx),
            "--to", RECIPIENT, "--wei", str(10**12), "--out", str(tmp_path / "signed.json")]
    assert cli.main(args) == 1
    assert not (tmp_path / "signed.json").exists()


def test_cli_policy_cap_denial_precedes_approval(root, tmp_path, monkeypatch):
    from usb_cold_wallet import cli
    vault = tmp_path / "wallet.vault"
    vault.write_text("placeholder")
    tx = tmp_path / "unsigned.json"
    tx.write_text(json.dumps({
        "type": 2, "chainId": 11155111, "nonce": 7, "to": RECIPIENT,
        "value": 10**12, "gas": 21000, "maxFeePerGas": 2 * 10**9,
        "maxPriorityFeePerGas": 10**9, "data": "0x",
    }))
    p = set_limit(default_profile(root), root, "evm_max_fee_wei", 1)
    save_profile(tmp_path / "wallet.vault.policy", p, root, PASSWORD)
    monkeypatch.setattr(cli, "_wallet_root", lambda args: root)
    monkeypatch.setattr(cli, "_password", lambda: PASSWORD)
    monkeypatch.setattr(cli, "sign_evm", lambda *a, **kw: pytest.fail("signing bypassed policy"))
    monkeypatch.setattr(cli, "_approve", lambda phrase: pytest.fail("approval offered on DENY"))
    args = ["--vault", str(vault), "sign-evm", "--tx", str(tx),
            "--to", RECIPIENT, "--wei", str(10**12), "--out", str(tmp_path / "signed.json")]
    assert cli.main(args) == 1
    assert not (tmp_path / "signed.json").exists()


def test_symlink_policy_refused(root, tmp_path):
    path = tmp_path / "policy"
    target = tmp_path / "other"
    target.write_text("anything")
    path.symlink_to(target)
    with pytest.raises(ValueError):
        save_profile(path, default_profile(root), root, PASSWORD, replace=True)
    with pytest.raises(ValueError):
        load_profile(path, root, PASSWORD)
