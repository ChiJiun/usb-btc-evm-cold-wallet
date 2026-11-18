"""Offline-only, fail-closed testnet policy profiles and verified address book.

The policy is an additional restriction, NEVER an authorization to sign. The
existing BTC/EVM review routines and separate human SIGN prompt remain mandatory.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from eth_utils import to_checksum_address
from embit import networks, script

from .keys import evm_account

VERSION = 1
AAD = b"usb-cold-wallet-offline-policy-v1"
MAX_FILE_BYTES = 16384
MAX_ENTRIES = 64
DEFAULT_EVM_MAX_FEE_WEI = 10**17
DEFAULT_EVM_MAX_VALUE_WEI = 10**19
DEFAULT_BTC_MAX_FEE_SATS = 100000
DEFAULT_BTC_MAX_FEE_RATE = 100  # sat/vbyte


@dataclass(frozen=True)
class TransactionIntent:
    version: int
    network: Literal["sepolia", "bitcoin-testnet"]
    account: str
    recipient: str
    amount: int
    maximum_fee: int
    maximum_total: int
    signature_type: str
    nonce: int | None = None
    gas: int | None = None
    max_fee_per_gas: int | None = None
    max_priority_fee_per_gas: int | None = None
    fee_rate: float | None = None


@dataclass(frozen=True)
class PolicyDecision:
    status: Literal["ALLOW_FOR_REVIEW", "REQUIRE_EXTRA_CONFIRMATION", "DENY"]
    reasons: tuple[str, ...]
    verified_label: str | None


def wallet_binding(root) -> str:
    """Stable public-only binding: not a derivation of or substitute for encryption."""
    public = root.to_public().to_base58()
    return hashlib.sha256(b"offline-policy-wallet-v1\0" + public.encode("ascii")).hexdigest()


def default_profile(root) -> dict:
    return {
        "version": VERSION,
        "wallet_binding": wallet_binding(root),
        "limits": {
            "evm_max_value_wei": DEFAULT_EVM_MAX_VALUE_WEI,
            "evm_max_fee_wei": DEFAULT_EVM_MAX_FEE_WEI,
            "btc_max_fee_sats": DEFAULT_BTC_MAX_FEE_SATS,
            "btc_max_fee_rate_sat_vb": DEFAULT_BTC_MAX_FEE_RATE,
        },
        "verified_addresses": [],
    }


def normalize_address(network: str, address: str) -> str:
    if not isinstance(address, str) or len(address) > 100:
        raise ValueError("Invalid address")
    if network == "sepolia":
        try:
            if not address.startswith("0x") or len(address) != 42:
                raise ValueError("Bad EVM address")
            return to_checksum_address(address)
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid EVM address") from exc
    if network == "bitcoin-testnet":
        try:
            parsed = script.address_to_scriptpubkey(address)
            normalized = parsed.address(networks.NETWORKS["test"])
        except Exception as exc:
            raise ValueError("Invalid Bitcoin testnet address") from exc
        if normalized != address or not address.startswith("tb1q"):
            raise ValueError("Only canonical Bitcoin testnet bech32 addresses supported")
        return normalized
    raise ValueError("Unsupported address network")


def _bounded_integer(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def validate_profile(profile: object, root) -> dict:
    if not isinstance(profile, dict) or set(profile) != {"version", "wallet_binding", "limits", "verified_addresses"}:
        raise ValueError("Invalid policy profile shape")
    if type(profile["version"]) is not int or profile["version"] != VERSION:
        raise ValueError("Unsupported policy version")
    if profile["wallet_binding"] != wallet_binding(root):
        raise ValueError("Policy belongs to a different wallet")
    limits = profile["limits"]
    maxima = {"evm_max_value_wei": 10**22, "evm_max_fee_wei": 10**20,
              "btc_max_fee_sats": 10**8, "btc_max_fee_rate_sat_vb": 1000}
    if not isinstance(limits, dict) or set(limits) != set(maxima):
        raise ValueError("Invalid policy limits")
    for field, maximum in maxima.items():
        if not _bounded_integer(limits[field], maximum):
            raise ValueError(f"Invalid policy limit: {field}")
    addresses = profile["verified_addresses"]
    if not isinstance(addresses, list) or len(addresses) > MAX_ENTRIES:
        raise ValueError("Invalid address book size")
    seen = set()
    for item in addresses:
        if not isinstance(item, dict) or set(item) != {"network", "account", "address", "label"}:
            raise ValueError("Invalid verified address entry")
        network, account, address, label = (item[k] for k in ("network", "account", "address", "label"))
        if network not in ("sepolia", "bitcoin-testnet") or not isinstance(account, str):
            raise ValueError("Invalid address book network/account")
        expected_account = evm_account(root).address if network == "sepolia" else wallet_binding(root)
        if account != expected_account or normalize_address(network, address) != address:
            raise ValueError("Address book account binding or address mismatch")
        if not isinstance(label, str) or not (1 <= len(label) <= 48) or any(ord(c) < 32 for c in label):
            raise ValueError("Invalid address book label")
        key = (network, account, address)
        if key in seen:
            raise ValueError("Duplicate verified address")
        seen.add(key)
    return profile


def register_verified_address(profile: dict, root, network: str, address: str, label: str) -> dict:
    """Caller MUST unlock the wallet and independently confirm complete address offline."""
    validate_profile(profile, root)
    canonical = normalize_address(network, address)
    new_profile = json.loads(json.dumps(profile))
    account = evm_account(root).address if network == "sepolia" else wallet_binding(root)
    new_profile["verified_addresses"] = [
        x for x in new_profile["verified_addresses"]
        if (x["network"], x["account"], x["address"]) != (network, account, canonical)
    ]
    new_profile["verified_addresses"].append({
        "network": network, "account": account, "address": canonical, "label": label,
    })
    return validate_profile(new_profile, root)


def set_limit(profile: dict, root, field: str, value: int) -> dict:
    validate_profile(profile, root)
    if field not in profile["limits"]:
        raise ValueError("Unknown policy limit")
    changed = json.loads(json.dumps(profile))
    changed["limits"][field] = value
    return validate_profile(changed, root)


def _key(password: str, salt: bytes) -> bytes:
    if len(password) < 12:
        raise ValueError("Policy encryption passphrase needs at least 12 characters")
    return Scrypt(salt=salt, length=32, n=1 << 17, r=8, p=1).derive(password.encode("utf-8"))


def save_profile(path: Path, profile: dict, root, password: str, *, replace: bool = False) -> None:
    validate_profile(profile, root)
    path = Path(path)
    if path.is_symlink() or (path.exists() and not replace):
        raise ValueError("Policy file already exists or is a symlink")
    salt, nonce = os.urandom(16), os.urandom(12)
    raw = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
    ciphertext = AESGCM(_key(password, salt)).encrypt(nonce, raw, AAD)
    obj = {"format": "usb-cold-wallet-policy", "version": VERSION,
           "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
           "ciphertext": base64.b64encode(ciphertext).decode()}
    content = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
    if len(content) > MAX_FILE_BYTES:
        raise ValueError("Policy file too large")
    # Same-directory atomic replacement, never write a plaintext policy file.
    tmp = path.with_name(path.name + ".new-" + os.urandom(8).hex())
    try:
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if path.is_symlink() or (path.exists() and not replace):
            raise ValueError("Policy path changed during write")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def load_profile(path: Path, root, password: str) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Policy file missing, too large or symlink")
    try:
        container = json.loads(path.read_bytes())
        if set(container) != {"format", "version", "salt", "nonce", "ciphertext"}:
            raise ValueError("Unsupported policy container")
        if container["format"] != "usb-cold-wallet-policy" or type(container["version"]) is not int or container["version"] != VERSION:
            raise ValueError("Unsupported policy container version")
        salt = base64.b64decode(container["salt"], validate=True)
        nonce = base64.b64decode(container["nonce"], validate=True)
        ciphertext = base64.b64decode(container["ciphertext"], validate=True)
        if len(salt) != 16 or len(nonce) != 12 or len(ciphertext) > MAX_FILE_BYTES:
            raise ValueError("Malformed policy ciphertext")
        raw = AESGCM(_key(password, salt)).decrypt(nonce, ciphertext, AAD)
        return validate_profile(json.loads(raw), root)
    except (KeyError, TypeError, UnicodeError, ValueError) as exc:
        raise ValueError("Invalid, corrupted or mismatched policy") from exc
    except Exception as exc:
        # InvalidTag and invalid crypto containers must fail closed.
        raise ValueError("Invalid, corrupted or mismatched policy") from exc


def evm_intent(root, review: dict) -> TransactionIntent:
    tx = review["transaction"]
    return TransactionIntent(VERSION, "sepolia", evm_account(root).address,
                             review["recipient"], review["value_wei"],
                             review["max_fee_wei"], review["max_total_wei"], "EIP-1559 native transfer",
                             nonce=tx["nonce"], gas=tx["gas"],
                             max_fee_per_gas=tx["maxFeePerGas"],
                             max_priority_fee_per_gas=tx["maxPriorityFeePerGas"])


def btc_intent(root, review: dict) -> TransactionIntent:
    if review["network"] != "bitcoin-testnet":
        raise ValueError("Unexpected Bitcoin network")
    # Stripped transaction bytes are a conservative LOWER bound on vbytes,
    # giving an upper bound for fee rate. No unsigned-witness estimate is trusted.
    stripped_size = len(review["psbt"].tx.serialize())
    if stripped_size <= 0:
        raise ValueError("Invalid PSBT transaction size")
    return TransactionIntent(VERSION, "bitcoin-testnet", wallet_binding(root),
                             review["recipient"], review["amount_sats"],
                             review["fee_sats"], review["amount_sats"] + review["fee_sats"],
                             "PSBT P2WPKH SIGHASH_ALL",
                             fee_rate=review["fee_sats"] / stripped_size)


def decide(profile: dict, root, intent: TransactionIntent) -> PolicyDecision:
    validate_profile(profile, root)
    expected_account = evm_account(root).address if intent.network == "sepolia" else wallet_binding(root)
    if intent.version != VERSION or intent.network not in ("sepolia", "bitcoin-testnet") or intent.account != expected_account:
        return PolicyDecision("DENY", ("Unsupported intent version/network/account",), None)
    try:
        address = normalize_address(intent.network, intent.recipient)
    except ValueError:
        return PolicyDecision("DENY", ("Invalid network recipient",), None)
    if type(intent.amount) is not int or intent.amount <= 0 or type(intent.maximum_fee) is not int or intent.maximum_fee < 0:
        return PolicyDecision("DENY", ("Invalid transaction amount/fee",), None)
    limits = profile["limits"]
    if intent.network == "sepolia":
        if intent.signature_type != "EIP-1559 native transfer" or intent.gas != 21000 or intent.max_fee_per_gas is None:
            return PolicyDecision("DENY", ("Unsupported EVM signing method",), None)
        if intent.amount > limits["evm_max_value_wei"] or intent.maximum_fee > limits["evm_max_fee_wei"]:
            return PolicyDecision("DENY", ("Sepolia value/fee exceeds policy cap",), None)
    else:
        if intent.signature_type != "PSBT P2WPKH SIGHASH_ALL":
            return PolicyDecision("DENY", ("Unsupported Bitcoin signing method",), None)
        if intent.maximum_fee > limits["btc_max_fee_sats"]:
            return PolicyDecision("DENY", ("Bitcoin fee exceeds policy cap",), None)
        if intent.fee_rate is None or intent.fee_rate < 0 or intent.fee_rate > limits["btc_max_fee_rate_sat_vb"]:
            return PolicyDecision("DENY", ("Bitcoin fee rate exceeds policy cap",), None)
    label = next((entry["label"] for entry in profile["verified_addresses"]
                  if (entry["network"], entry["account"], entry["address"]) ==
                  (intent.network, intent.account, address)), None)
    if label is None:
        return PolicyDecision("REQUIRE_EXTRA_CONFIRMATION", ("Unverified recipient; compare full address offline",), None)
    return PolicyDecision("ALLOW_FOR_REVIEW", ("Verified address label; compare full address anyway",), label)
