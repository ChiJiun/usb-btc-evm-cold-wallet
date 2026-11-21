"""Offline paper recovery with independently verified public address fingerprints."""
from pathlib import Path
from tempfile import TemporaryDirectory

from .keys import root_from_mnemonic, watch_only
from .vault import encrypt_mnemonic, load_vault, save_vault, validate_mnemonic

# This mnemonic is a published, COMPROMISED test vector. NEVER fund it.
PUBLIC_TEST_MNEMONIC = "abandon " * 11 + "about"


def verify_paper_recovery(mnemonic: str, bip39_passphrase: str,
                          expected_btc: str, expected_evm: str):
    if not isinstance(expected_btc, str) or not expected_btc.startswith("tb1"):
        raise ValueError("Independent Bitcoin testnet address required")
    if not isinstance(expected_evm, str) or not expected_evm.startswith("0x"):
        raise ValueError("Independent Sepolia EVM address required")
    words = validate_mnemonic(mnemonic)
    public = watch_only(root_from_mnemonic(words, bip39_passphrase), count=1)
    if (public["bitcoin"]["receive_addresses"][0] != expected_btc or
            public["evm"]["address"].lower() != expected_evm.lower()):
        raise ValueError("Recovery addresses disagree with paper records; no vault written")
    return public


def restore_paper_wallet(path: Path, mnemonic: str, bip39_passphrase: str,
                         expected_btc: str, expected_evm: str, password: str):
    """Check BOTH external reference addresses before any vault write, never overwrite."""
    public = verify_paper_recovery(mnemonic, bip39_passphrase, expected_btc, expected_evm)
    save_vault(path, encrypt_mnemonic(mnemonic, password))
    return public


def rehearsal(password: str):
    """Destructive test-only restore in a temporary directory using public BIP39 vector."""
    public = watch_only(root_from_mnemonic(PUBLIC_TEST_MNEMONIC), count=1)
    btc = public["bitcoin"]["receive_addresses"][0]
    evm = public["evm"]["address"]
    with TemporaryDirectory(prefix="usb-wallet-test-recovery-") as name:
        path = Path(name) / "throwaway-test-only.vault"
        save_vault(path, encrypt_mnemonic(PUBLIC_TEST_MNEMONIC, password))
        if load_vault(path, password) != PUBLIC_TEST_MNEMONIC:
            raise ValueError("Test-only vault roundtrip failed")
        path.unlink()  # Only the known disposable fixture, NEVER a user vault.
        restore_paper_wallet(path, PUBLIC_TEST_MNEMONIC, "", btc, evm, password)
        if load_vault(path, password) != PUBLIC_TEST_MNEMONIC:
            raise ValueError("Recovery rehearsal failed")
    return {"network": "testnet-and-sepolia", "btc_address": btc,
            "evm_address": evm, "result": "test-only recovery rehearsal passed"}
