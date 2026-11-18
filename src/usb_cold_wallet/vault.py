"""Scrypt + AES-256-GCM encrypted mnemonic container. No network functions."""
import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from embit import bip39

_AAD = b"usb-btc-evm-cold-wallet-v1"
_N = 1 << 17
_R = 8
_P = 1


def new_mnemonic() -> str:
    """Generate 256 bits using the operating system CSPRNG. Call only on a trusted offline OS."""
    return bip39.mnemonic_from_bytes(os.urandom(32))


def validate_mnemonic(mnemonic: str) -> str:
    words = " ".join(mnemonic.strip().split())
    if len(words.split()) not in (12, 15, 18, 21, 24):
        raise ValueError("BIP39 mnemonic must have 12/15/18/21/24 words")
    # Reject malformed mnemonics / invalid BIP39 checksums.
    bip39.mnemonic_to_bytes(words)
    return words


def _derive(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12:
        raise ValueError("Wallet encryption passphrase needs at least 12 characters")
    return Scrypt(salt=salt, length=32, n=_N, r=_R, p=_P).derive(passphrase.encode("utf-8"))


def encrypt_mnemonic(mnemonic: str, passphrase: str) -> dict:
    mnemonic = validate_mnemonic(mnemonic)
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _derive(passphrase, salt)
    encrypted = AESGCM(key).encrypt(nonce, mnemonic.encode("utf-8"), _AAD)
    return {
        "format": "usb-btc-evm-cold-wallet",
        "version": 1,
        "kdf": {"name": "scrypt", "n": _N, "r": _R, "p": _P, "salt": base64.b64encode(salt).decode()},
        "cipher": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(encrypted).decode(),
    }


def decrypt_mnemonic(data: dict, passphrase: str) -> str:
    if data.get("format") != "usb-btc-evm-cold-wallet" or data.get("version") != 1:
        raise ValueError("Unknown wallet format")
    kdf = data.get("kdf", {})
    if (kdf.get("name"), kdf.get("n"), kdf.get("r"), kdf.get("p")) != ("scrypt", _N, _R, _P):
        raise ValueError("Unexpected KDF parameters")
    if data.get("cipher") != "AES-256-GCM":
        raise ValueError("Unexpected cipher")
    salt = base64.b64decode(kdf["salt"], validate=True)
    nonce = base64.b64decode(data["nonce"], validate=True)
    ciphertext = base64.b64decode(data["ciphertext"], validate=True)
    if len(salt) != 16 or len(nonce) != 12 or len(ciphertext) > 2048:
        raise ValueError("Malformed wallet")
    try:
        return validate_mnemonic(AESGCM(_derive(passphrase, salt)).decrypt(nonce, ciphertext, _AAD).decode())
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise ValueError("Incorrect passphrase or corrupted wallet") from exc


def save_vault(path: Path, data: dict) -> None:
    """Create-only and mode 0600, avoiding silent replacement of an existing wallet."""
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")


def load_vault(path: Path, passphrase: str) -> str:
    path = Path(path)
    if not path.is_file():
        raise ValueError("Vault file not found")
    if path.stat().st_size > 4096:
        raise ValueError("Vault file unexpectedly large")
    return decrypt_mnemonic(json.loads(path.read_text(encoding="utf-8")), passphrase)
