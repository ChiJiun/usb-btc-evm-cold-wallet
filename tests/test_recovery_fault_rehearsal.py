"""Issue #5 isolated recovery/fault-injection checks. PUBLIC compromised vectors only.

Never point these tests at a removable disk or user-supplied vault path.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest
from embit import bip39, networks, script

from usb_cold_wallet.keys import btc_address, root_from_mnemonic, watch_only
from usb_cold_wallet.policy import default_profile, load_profile, save_profile, wallet_binding
from usb_cold_wallet.recovery import (
    PUBLIC_TEST_MNEMONIC, restore_paper_wallet, verify_paper_recovery,
)
from usb_cold_wallet import vault

PASSWORD = "PUBLIC-TEST-only-strong-container-passphrase"
MNEMONIC = PUBLIC_TEST_MNEMONIC
# Trezor BIP39 test vector: 128-bit zero entropy, passphrase TREZOR.
# Trezor python-mnemonic vectors.json, English vector 0, commit
# b57a5ad77a981e743f4167ab2f7927a55c1e82a8. Published and compromised.
EXPECTED_SEED = (
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e534955"
    "31f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)
# SHA-256 of the *published* BIP32 master xprv in the same upstream vector.
# Keep the public compromised xprv itself out of fixtures and CI artifacts.
EXPECTED_MASTER_XPRV_SHA256 = "ce0e5e2d20c072573ebbd11097f811c970974484431102b9501e6af36b3c6d7e"


@pytest.fixture
def private_dir(tmp_path):
    # Kernel renameat2 and directory fsync are Linux-only in the current project.
    if os.name != "posix" or not hasattr(os, "geteuid"):
        pytest.skip("Linux-only atomic vault implementation")
    folder = tmp_path / "fixture-only"
    folder.mkdir(mode=0o700)
    folder.chmod(0o700)
    return folder


def _identity(mnemonic=MNEMONIC, passphrase="", count=3):
    root = root_from_mnemonic(mnemonic, passphrase)
    return root, watch_only(root, count=count)


def _restore(path, mnemonic=MNEMONIC, phrase="", reference=None):
    if reference is None:
        reference = _identity()[1]
    return restore_paper_wallet(
        path, mnemonic, phrase,
        reference["bitcoin"]["receive_addresses"][0],
        reference["evm"]["address"], PASSWORD,
    )


def test_public_bip39_vector_backup_and_full_watch_only_identity(private_dir):
    assert bip39.mnemonic_to_bytes(MNEMONIC) == bytes(16)
    seed = bip39.mnemonic_to_seed(MNEMONIC, password="TREZOR")
    assert seed.hex() == EXPECTED_SEED
    assert hashlib.pbkdf2_hmac(
        "sha512", MNEMONIC.encode("utf-8"), b"mnemonicTREZOR", 2048, 64
    ) == bytes.fromhex(EXPECTED_SEED)
    root, before = _identity(MNEMONIC, "TREZOR")
    assert hashlib.sha256(root.to_base58().encode("ascii")).hexdigest() == EXPECTED_MASTER_XPRV_SHA256
    target = private_dir / "test-only-restored.vault"
    returned = _restore(target, MNEMONIC, "TREZOR", before)
    after_root, after = _identity(vault.load_vault(target, PASSWORD), "TREZOR")
    assert returned["bitcoin"]["receive_addresses"][0] == before["bitcoin"]["receive_addresses"][0]
    assert returned["evm"] == before["evm"]
    assert after == before
    assert root.my_fingerprint == after_root.my_fingerprint
    assert wallet_binding(root) == wallet_binding(after_root)
    assert before["bitcoin"]["network"] == "testnet"
    assert before["evm"]["chain_id"] == 11155111
    assert len(before["bitcoin"]["receive_addresses"]) == 3
    assert before["bitcoin"]["account_tpub"] == after["bitcoin"]["account_tpub"]
    assert before["bitcoin"]["master_fingerprint"] == after["bitcoin"]["master_fingerprint"]


@pytest.mark.parametrize("bad_phrase", [
    "abandon " * 12,
    "abandon " * 11 + "ability",
    "not a valid mnemonic",
])
def test_invalid_paper_is_rejected_before_creating_vault(private_dir, bad_phrase):
    destination = private_dir / "must-not-create.vault"
    with pytest.raises(ValueError):
        _restore(destination, bad_phrase)
    assert not destination.exists()


def test_wrong_bip39_passphrase_and_wrong_external_wallet_identity(private_dir):
    expected = _identity(MNEMONIC, "TREZOR")[1]
    target = private_dir / "must-not-create.vault"
    with pytest.raises(ValueError, match="disagree"):
        _restore(target, MNEMONIC, "WRONG", expected)
    assert not target.exists()
    # Different valid mnemonic, yet the *same independently recorded identity*.
    alternate = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    with pytest.raises(ValueError):
        _restore(target, alternate, "", expected)
    assert not target.exists()
    with pytest.raises(ValueError, match="disagree"):
        verify_paper_recovery(MNEMONIC, "TREZOR",
                              expected["bitcoin"]["receive_addresses"][0],
                              _identity()[1]["evm"]["address"])


def test_wrong_bitcoin_network_or_account_is_rejected(private_dir):
    root, recorded = _identity()
    first = recorded["bitcoin"]["receive_addresses"][0]
    mainnet = script.address_to_scriptpubkey(first).address(networks.NETWORKS["main"])
    assert mainnet != first and not mainnet.startswith("tb1")
    # A mainnet receive address must never be accepted as a testnet reference.
    with pytest.raises(ValueError, match="testnet"):
        verify_paper_recovery(MNEMONIC, "", mainnet, recorded["evm"]["address"])
    target = private_dir / "wrong-account.vault"
    # Both the next address and an address from account 1 are valid testnet
    # addresses, but neither matches the recorded account-0 first address.
    other_index = btc_address(root, 0, 1)
    other_account = script.p2wpkh(root.derive("m/84h/1h/1h/0/0").key).address(
        networks.NETWORKS["test"])
    assert len({first, other_index, other_account}) == 3
    for unexpected in (other_index, other_account):
        with pytest.raises(ValueError, match="disagree"):
            restore_paper_wallet(target, MNEMONIC, "", unexpected,
                                 recorded["evm"]["address"], PASSWORD)
        assert not target.exists()


def test_missing_vault_is_rejected_without_writing(private_dir):
    missing = private_dir / "never-created.vault"
    with pytest.raises(ValueError, match="not found"):
        vault.load_vault(missing, PASSWORD)
    assert not missing.exists()


def test_nonprivate_vault_directory_rejected_before_staging(private_dir):
    unsafe = private_dir / "unsafe"
    unsafe.mkdir(mode=0o755)
    unsafe.chmod(0o755)
    target = unsafe / "unpublished.vault"
    with pytest.raises(PermissionError, match="signer-private"):
        _restore(target)
    assert not target.exists()
    assert not list(unsafe.glob(".usbwallet-*.partial"))


def test_missing_vault_restore_is_create_only_and_never_overwrites(private_dir):
    path = private_dir / "test-only.vault"
    reference = _identity()[1]
    _restore(path, reference=reference)
    old_bytes = path.read_bytes()
    path.unlink()  # disposable fixture only, never a real wallet
    assert not path.exists()
    _restore(path, reference=reference)
    assert _restore_result_matches(path, reference)
    # This second attempt must not disturb the restored vault.
    restored_bytes = path.read_bytes()
    with pytest.raises(FileExistsError):
        _restore(path, reference=reference)
    assert path.read_bytes() == restored_bytes
    assert vault.load_vault(path, PASSWORD) == MNEMONIC
    assert old_bytes != restored_bytes  # fresh authenticated encryption


def _restore_result_matches(path, reference):
    """The expected first address and EVM identity survive the test-only deletion."""
    recovered = vault.load_vault(path, PASSWORD)
    current = _identity(recovered)[1]
    return current == reference


@pytest.mark.parametrize("mutation", ["ciphertext", "truncate", "format", "version", "salt", "nonce"])
def test_corrupt_or_unsupported_vault_never_decrypts(private_dir, mutation):
    path = private_dir / "corrupted.vault"
    _restore(path)
    obj = json.loads(path.read_text())
    if mutation == "ciphertext":
        # Valid base64 but invalid AEAD tag.
        ciphertext = base64.b64decode(obj["ciphertext"], validate=True)
        obj["ciphertext"] = base64.b64encode(
            ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        ).decode("ascii")
        path.write_text(json.dumps(obj))
    elif mutation == "truncate":
        path.write_bytes(path.read_bytes()[:40])
    elif mutation == "format":
        obj["format"] = "other-wallet"
        path.write_text(json.dumps(obj))
    elif mutation == "version":
        obj["version"] = 999
        path.write_text(json.dumps(obj))
    else:
        field = "salt" if mutation == "salt" else "nonce"
        container = obj["kdf"] if mutation == "salt" else obj
        encoded = base64.b64decode(container[field], validate=True)
        # Preserve valid base64, size and JSON; alter exactly one bit so
        # rejection must come from authenticated decryption, not parsing.
        container[field] = base64.b64encode(
            bytes([encoded[0] ^ 1]) + encoded[1:]
        ).decode("ascii")
        path.write_text(json.dumps(obj))
    with pytest.raises((ValueError, KeyError, json.JSONDecodeError)):
        vault.load_vault(path, PASSWORD)


def test_wrong_encryption_password_does_not_modify_vault(private_dir):
    path = private_dir / "vault.vault"
    _restore(path)
    before = path.read_bytes()
    with pytest.raises(ValueError):
        vault.load_vault(path, "WRONG-encryption-password")
    assert path.read_bytes() == before


def test_power_cut_before_publish_and_stage_swap_fail_closed(private_dir, monkeypatch):
    path = private_dir / "cut.vault"
    actual = vault.os.fsync

    def cut_on_stage(fd):
        if os.fstat(fd).st_mode & 0o170000 == 0o100000:
            raise OSError(5, "injected power loss before publication")
        return actual(fd)

    with monkeypatch.context() as m:
        m.setattr(vault.os, "fsync", cut_on_stage)
        with pytest.raises(OSError, match="power loss"):
            _restore(path)
    assert not path.exists()
    assert not list(private_dir.glob(".usbwallet-*.partial"))
    _restore(path)
    assert vault.load_vault(path, PASSWORD) == MNEMONIC


def test_staged_vault_filename_substitution_detected(private_dir, monkeypatch):
    path = private_dir / "swapped.vault"
    foreign = private_dir / "foreign"
    foreign.write_bytes(b"public-test-attacker-file")
    actual = vault._atomic_rename_noreplace

    injected = []
    def swap_before_publish(parent_fd, stage, final):
        # Attacker with same UID moves a different inode into staging slot.
        injected.append(stage)
        os.replace(foreign, private_dir / stage)
        return actual(parent_fd, stage, final)

    with monkeypatch.context() as m:
        m.setattr(vault, "_atomic_rename_noreplace", swap_before_publish)
        with pytest.raises(OSError, match="does not match|changed"):
            _restore(path)
    # Prove the injected swap actually reached publication, then verify that
    # the resulting attacker-owned final entry is not accepted as a Vault.
    assert len(injected) == 1
    assert path.exists()
    assert path.read_bytes() == b"public-test-attacker-file"
    with pytest.raises((ValueError, json.JSONDecodeError, UnicodeDecodeError)):
        vault.load_vault(path, PASSWORD)


def test_historical_valid_vault_replay_is_not_detectable_without_anchor(private_dir):
    path = private_dir / "historical.vault"
    _restore(path)
    earlier = path.read_bytes()
    path.unlink()  # fixture-only simulation of an offline file replacement
    _restore(path)
    assert path.read_bytes() != earlier
    path.write_bytes(earlier)
    # Explicit documented limitation: AEAD confirms authenticity to the
    # encryption key, NOT freshness or monotonic counter.
    assert vault.load_vault(path, PASSWORD) == MNEMONIC


def test_policy_rollback_needs_independent_digest_anchor(private_dir):
    root = _identity()[0]
    path = private_dir / "fixture.policy"
    original = default_profile(root)
    save_profile(path, original, root, PASSWORD)
    old_bytes = path.read_bytes()
    old_digest = hashlib.sha256(old_bytes).hexdigest()
    changed = dict(original)
    changed["limits"] = {**original["limits"], "btc_max_fee_sats": 42}
    save_profile(path, changed, root, PASSWORD, replace=True,
                 expected_sha256=old_digest)
    newest_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert newest_digest != old_digest
    path.write_bytes(old_bytes)  # adversarial rollback outside writer API
    assert load_profile(path, root, PASSWORD) == original
    with pytest.raises(ValueError):
        load_profile(path, root, PASSWORD, expected_sha256=newest_digest)
    assert load_profile(path, root, PASSWORD, expected_sha256=old_digest) == original


def test_policy_cannot_be_loaded_as_another_wallet(private_dir):
    root = _identity()[0]
    another = _identity(MNEMONIC, "TREZOR")[0]
    path = private_dir / "fixture.policy"
    save_profile(path, default_profile(root), root, PASSWORD)
    with pytest.raises(ValueError):
        load_profile(path, another, PASSWORD)


def test_no_test_fixture_secrets_in_exception_or_captured_output(private_dir, capsys):
    target = private_dir / "bad-identity.vault"
    incorrect = _identity(MNEMONIC, "TREZOR")[1]
    with pytest.raises(ValueError) as failure:
        _restore(target, reference=incorrect)
    captured = capsys.readouterr()
    text = str(failure.value) + captured.out + captured.err
    assert MNEMONIC not in text
    assert PASSWORD not in text
    assert not target.exists()
