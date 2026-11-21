"""Offline-only, fail-closed testnet policy profiles and verified address book.

The policy is an additional restriction, NEVER an authorization to sign. The
existing BTC/EVM review routines and separate human SIGN prompt remain mandatory.
"""
from __future__ import annotations

import base64
import fcntl
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import re
import math
import stat
import unicodedata
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
    contract: str | None = None
    method: str | None = None
    deadline: int | None = None


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
        "contract_rules": [],
        "typed_rules": [],
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
        if (normalized != address or not address.startswith("tb1q") or
                len(address) != 42 or len(parsed.data) != 22 or
                not parsed.data.startswith(b"\x00\x14")):
            raise ValueError("Only canonical Bitcoin testnet BIP84 P2WPKH addresses supported")
        return normalized
    raise ValueError("Unsupported address network")


def _bounded_integer(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def validate_profile(profile: object, root) -> dict:
    if not isinstance(profile, dict) or not {"version", "wallet_binding", "limits", "verified_addresses"} <= set(profile) or set(profile) - {"version", "wallet_binding", "limits", "verified_addresses", "contract_rules", "typed_rules"}:
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
        if (type(label) is not str or not (1 <= len(label) <= 48) or
                unicodedata.normalize("NFKC", label) != label or
                any(not c.isprintable() or unicodedata.category(c) in
                    ("Cf", "Cc", "Cs", "Zl", "Zp") for c in label)):
            raise ValueError("Invalid address book label (unsafe control/bidi formatting)")
        key = (network, account, address)
        if key in seen:
            raise ValueError("Duplicate verified address")
        seen.add(key)
    # Contract permissions are wallet-bound, encrypted profile data, never RPC metadata.
    from .evm_erc20 import checked_address, checked_uint
    rules = profile.get("contract_rules", [])
    if type(rules) is not list or len(rules) > 32:
        raise ValueError("Invalid offline contract rules")
    rule_ids = set()
    for rule in rules:
        if type(rule) is not dict or set(rule) != {"contract", "method", "counterparty", "max_amount", "expected_nonce"}:
            raise ValueError("Invalid contract rule shape")
        contract = checked_address(rule["contract"], "approved contract")
        counterparty = checked_address(rule["counterparty"], "approved counterparty")
        if contract != rule["contract"] or counterparty != rule["counterparty"]:
            raise ValueError("Contract rule addresses must use checksum form")
        if rule["method"] not in ("transfer", "approve"):
            raise ValueError("Unsupported contract method")
        checked_uint(rule["max_amount"], "contract maximum amount")
        checked_uint(rule["expected_nonce"], "contract expected nonce")
        identity = (contract, rule["method"], counterparty)
        if identity in rule_ids:
            raise ValueError("Duplicate contract rule")
        rule_ids.add(identity)
    typed_rules = profile.get("typed_rules", [])
    if type(typed_rules) is not list or len(typed_rules) > 32:
        raise ValueError("Invalid offline EIP-712 rules")
    typed_ids = set()
    for rule in typed_rules:
        if type(rule) is not dict or set(rule) != {"contract", "schema", "counterparty", "max_amount", "expected_nonce", "deadline"}:
            raise ValueError("Invalid EIP-712 rule shape")
        contract = checked_address(rule["contract"], "typed verifying contract")
        party = checked_address(rule["counterparty"], "typed counterparty")
        if contract != rule["contract"] or party != rule["counterparty"]:
            raise ValueError("EIP-712 policy addresses must be checksummed")
        if rule["schema"] not in ("WalletTransferIntent", "WalletApprovalIntent"):
            raise ValueError("Unsupported EIP-712 policy schema")
        checked_uint(rule["max_amount"], "typed maximum amount")
        checked_uint(rule["expected_nonce"], "typed expected nonce")
        checked_uint(rule["deadline"], "typed policy deadline", minimum=1)
        identity = (contract, rule["schema"], party)
        if identity in typed_ids:
            raise ValueError("Duplicate EIP-712 rule")
        typed_ids.add(identity)
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


def save_profile(path: Path, profile: dict, root, password: str, *, replace: bool = False,
                 expected_sha256: str | None = None) -> None:
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
    # Pin the parent directory: a symlink swap of its path must not redirect
    # the write to another directory. Never stage policy plaintext.
    from .vault import _atomic_rename_noreplace

    if not path.name or path.name in (".", ".."):
        raise ValueError("Invalid policy filename")
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                        getattr(os, "O_NOFOLLOW", 0))
    stage = ".policy-" + os.urandom(16).hex() + ".partial"
    stage_identity = None
    fd = None
    guard_fd = None
    try:
        parent = os.fstat(parent_fd)
        # The Vault/Policy mount contains sensitive wallet metadata. Require
        # owner-exclusive access (0700), matching the atomic Vault writer and
        # VFAT dmask=0077. Same-UID/root malicious writers remain out of scope.
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or
                (stat.S_IMODE(parent.st_mode) & 0o077)):
            raise ValueError("Policy directory must be signer-private (mode 0700)")
        # Advisory lock serializes all cooperating Policy publishers; the
        # expected SHA provides compare-and-swap against stale edits.
        fcntl.flock(parent_fd, fcntl.LOCK_EX)
        fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent_fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Policy staging file is not regular")
        stage_identity = (info.st_dev, info.st_ino)
        # Pin original staging inode across the name-based rename. A same-UID
        # writer is outside the trust model, but must never be silently trusted.
        guard_fd = os.dup(fd)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        staged = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(staged.st_mode) or (staged.st_dev, staged.st_ino) != stage_identity:
            raise ValueError("Policy staging file changed")
        try:
            target = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            target = None
        if target is not None and not stat.S_ISREG(target.st_mode):
            raise ValueError("Policy destination is not a regular file")
        if replace:
            if type(expected_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
                raise ValueError("A known current policy SHA-256 is required for replacement")
            if target is None:
                raise ValueError("Cannot replace missing policy")
            # Compare the current target via a single fd, under the directory
            # lock. A stale editor must never overwrite another policy update.
            target_fd = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                                getattr(os, "O_NONBLOCK", 0), dir_fd=parent_fd)
            try:
                current = os.fstat(target_fd)
                if not stat.S_ISREG(current.st_mode) or (
                        current.st_dev, current.st_ino) != (target.st_dev, target.st_ino):
                    raise ValueError("Policy destination changed during update")
                old_bytes = os.read(target_fd, MAX_FILE_BYTES + 1)
                if len(old_bytes) > MAX_FILE_BYTES:
                    raise ValueError("Current policy is unexpectedly large")
                if not hmac.compare_digest(hashlib.sha256(old_bytes).hexdigest(), expected_sha256):
                    raise ValueError("Stale policy SHA-256; reload and reconfirm offline")
            finally:
                os.close(target_fd)
            # The operator must independently record the new trusted hash
            # after this successful durable publication. This is NOT a
            # hardware-backed monotonic rollback counter.
            os.replace(stage, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        else:
            if expected_sha256 is not None:
                raise ValueError("Expected SHA-256 is only valid for replacement")
            _atomic_rename_noreplace(parent_fd, stage, path.name)
        # Name-based rename is susceptible to a compromised same-UID writer.
        # Verify the published entry STILL refers to the inode we encrypted
        # and fsynced; reject a substituted final entry before reporting success.
        published = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        original = os.fstat(guard_fd)
        if (not stat.S_ISREG(published.st_mode)
                or (published.st_dev, published.st_ino) != (original.st_dev, original.st_ino)
                or published.st_size != len(content)):
            raise OSError("Policy published file differs from staged ciphertext")
        # File fsync alone does not make the directory rename durable.
        os.fsync(parent_fd)
    finally:
        if fd is not None:
            os.close(fd)
        if guard_fd is not None:
            os.close(guard_fd)
        if stage_identity is not None:
            try:
                staged = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISREG(staged.st_mode) and (
                        staged.st_dev, staged.st_ino) == stage_identity:
                    os.unlink(stage, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError:
                # Removed media can prevent cleanup; partial names are never
                # treated as approved policy files.
                pass
        os.close(parent_fd)


def _strict_json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate policy JSON property")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"Invalid JSON number {x}")))


def _bounded_policy_read(path: Path):
    """Atomic fd-based read of an untrusted regular policy file; no symlinks/FIFO."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("Policy must be a regular file")
            raw = os.read(fd, MAX_FILE_BYTES + 1)
            if len(raw) > MAX_FILE_BYTES:
                raise ValueError("Policy file unexpectedly large")
            return raw
        finally:
            os.close(fd)
    except OSError as exc:
        raise ValueError("Invalid, missing or inaccessible policy file") from exc


def read_policy_snapshot(path: Path, expected_sha256: str) -> bytes:
    """Read and verify the independently recorded ciphertext anchor BEFORE unlocking.

    Return the exact authenticated file bytes. Consumers decrypt this snapshot,
    never a second read from possibly swapped removable media.
    """
    if (type(expected_sha256) is not str or
            not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
        raise ValueError("A current independent policy SHA-256 anchor is required")
    raw = _bounded_policy_read(path)
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
        raise ValueError("Invalid, corrupted or mismatched policy anchor")
    return raw


def load_policy_snapshot(raw_file: bytes, root, password: str) -> dict:
    """Decrypt and bind a previously validated single-read ciphertext snapshot."""
    try:
        if type(raw_file) is not bytes or len(raw_file) > MAX_FILE_BYTES:
            raise ValueError("Invalid policy snapshot")
        container = _strict_json(raw_file)
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
        return validate_profile(_strict_json(raw), root)
    except Exception as exc:
        # InvalidTag and hostile JSON/crypto containers must fail closed.
        raise ValueError("Invalid, corrupted or mismatched policy") from exc


def load_profile(path: Path, root, password: str, *, expected_sha256: str | None = None) -> dict:
    # Policy maintenance can read without an independent anchor; signing
    # must always use read_policy_snapshot(), before wallet key material enters RAM.
    raw_file = (read_policy_snapshot(path, expected_sha256)
                if expected_sha256 is not None else _bounded_policy_read(path))
    return load_policy_snapshot(raw_file, root, password)


def enforce_review_policy(profile: dict, root, review: dict, *, kind: str) -> tuple[TransactionIntent, PolicyDecision]:
    """Common fail-closed policy boundary for CLI and future GUI/QR signers.

    Pass only a chain-specific validated review, never an online supplied
    'decision' or intent. Caller MUST separately enforce any additional
    confirmation and final sign approval.
    """
    if kind == "evm":
        intent = evm_intent(root, review)
    elif kind == "btc":
        intent = btc_intent(root, review)
    else:
        raise ValueError("Unsupported policy signing kind")
    decision = decide(profile, root, intent)
    if decision.status == "DENY":
        raise ValueError(f"Offline policy denied {kind} transaction: {'; '.join(decision.reasons)}")
    return intent, decision

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
    if (type(intent.amount) is not int or intent.amount <= 0 or
            type(intent.maximum_fee) is not int or intent.maximum_fee < 0 or
            type(intent.maximum_total) is not int or intent.maximum_total != intent.amount + intent.maximum_fee):
        return PolicyDecision("DENY", ("Invalid transaction amount/fee/total",), None)
    limits = profile["limits"]
    if intent.network == "sepolia":
        if (intent.signature_type != "EIP-1559 native transfer" or type(intent.gas) is not int or
                intent.gas != 21000 or type(intent.nonce) is not int or not 0 <= intent.nonce < (1 << 64) or
                type(intent.max_fee_per_gas) is not int or not 0 < intent.max_fee_per_gas <= 10**12 or
                type(intent.max_priority_fee_per_gas) is not int or
                not 0 <= intent.max_priority_fee_per_gas <= intent.max_fee_per_gas or
                intent.maximum_fee != 21000 * intent.max_fee_per_gas):
            return PolicyDecision("DENY", ("Unsupported or inconsistent EVM signing method",), None)
        if intent.amount > limits["evm_max_value_wei"] or intent.maximum_fee > limits["evm_max_fee_wei"]:
            return PolicyDecision("DENY", ("Sepolia value/fee exceeds policy cap",), None)
    else:
        if intent.signature_type != "PSBT P2WPKH SIGHASH_ALL":
            return PolicyDecision("DENY", ("Unsupported Bitcoin signing method",), None)
        if intent.maximum_fee > limits["btc_max_fee_sats"]:
            return PolicyDecision("DENY", ("Bitcoin fee exceeds policy cap",), None)
        if (type(intent.fee_rate) not in (int, float) or not math.isfinite(intent.fee_rate) or
                intent.fee_rate < 0 or intent.fee_rate > limits["btc_max_fee_rate_sat_vb"]):
            return PolicyDecision("DENY", ("Bitcoin fee rate exceeds policy cap or is non-finite",), None)
    label = next((entry["label"] for entry in profile["verified_addresses"]
                  if (entry["network"], entry["account"], entry["address"]) ==
                  (intent.network, intent.account, address)), None)
    if label is None:
        return PolicyDecision("REQUIRE_EXTRA_CONFIRMATION", ("Unverified recipient; compare full address offline",), None)
    return PolicyDecision("ALLOW_FOR_REVIEW", ("Verified address label; compare full address anyway",), label)


def decide_erc20(profile: dict, root, payload: dict) -> tuple[dict | None, PolicyDecision]:
    """Review raw calldata using independently configured wallet-bound offline rules.

    This returns a manual-review decision only; native sign_evm remains unchanged.
    """
    from .evm_erc20 import parse_erc20_calldata, review_erc20_transaction, checked_address
    try:
        validate_profile(profile, root)
        decoded = parse_erc20_calldata(payload["data"])
        contract = checked_address(payload["to"], "transaction contract")
        method = decoded["method"]
        party = decoded["recipient"] if method == "transfer" else decoded["spender"]
        quantity = decoded["amount"] if method == "transfer" else decoded["allowance"]
        matching = [r for r in profile.get("contract_rules", []) if
                    (r["contract"], r["method"], r["counterparty"]) == (contract, method, party)]
        if len(matching) != 1:
            raise ValueError("No matching independently configured offline contract rule")
        rule = matching[0]
        if quantity > rule["max_amount"]:
            raise ValueError("Token amount or allowance exceeds offline rule")
        review = review_erc20_transaction(
            payload, expected_contract=rule["contract"],
            expected_counterparty=rule["counterparty"], expected_amount=quantity,
            expected_method=rule["method"], expected_nonce=rule["expected_nonce"],
            trusted_contracts=[r["contract"] for r in profile["contract_rules"]],
            max_fee_wei=profile["limits"]["evm_max_fee_wei"])
        return review, PolicyDecision(
            "REQUIRE_EXTRA_CONFIRMATION",
            ("Allowlisted ERC-20 operation requires full offline human review; contract signing remains disabled",),
            None)
    except (ValueError, TypeError, KeyError, OverflowError) as exc:
        return None, PolicyDecision("DENY", (str(exc),), None)


def decide_eip712(profile: dict, root, typed_data: dict, *, now_timestamp: int) -> tuple[dict | None, PolicyDecision]:
    """Use only wallet-bound offline typed rules for review; signing is forbidden."""
    from .evm_eip712 import review_eip712_intent
    from .evm_erc20 import checked_address, checked_uint
    try:
        validate_profile(profile, root)
        # Clock must be provided by the trusted offline side; it cannot be taken
        # from exchange JSON, RPC responses, or untrusted online metadata.
        checked_uint(now_timestamp, "trusted offline timestamp")
        domain = typed_data["domain"]
        message = typed_data["message"]
        contract = checked_address(domain["verifyingContract"], "verifying contract")
        schema = typed_data["primaryType"]
        if schema not in ("WalletTransferIntent", "WalletApprovalIntent"):
            raise ValueError("Unknown EIP-712 schema")
        party_field = "recipient" if schema == "WalletTransferIntent" else "spender"
        amount_field = "amount" if schema == "WalletTransferIntent" else "allowance"
        party = checked_address(message[party_field], "typed counterparty")
        quantity = checked_uint(message[amount_field], "typed amount")
        matches = [r for r in profile.get("typed_rules", []) if
                   (r["contract"], r["schema"], r["counterparty"]) == (contract, schema, party)]
        if len(matches) != 1:
            raise ValueError("No matching independent offline EIP-712 policy rule")
        rule = matches[0]
        if quantity > rule["max_amount"]:
            raise ValueError("Typed amount exceeds offline policy cap")
        reviewed = review_eip712_intent(
            typed_data, expected_contract=contract,
            expected_owner=evm_account(root).address, expected_primary_type=rule["schema"],
            expected_counterparty=rule["counterparty"], expected_amount=quantity,
            expected_nonce=rule["expected_nonce"], expected_deadline=rule["deadline"],
            trusted_contracts=[r["contract"] for r in profile["typed_rules"]],
            now_timestamp=now_timestamp)
        return reviewed, PolicyDecision(
            "REQUIRE_EXTRA_CONFIRMATION",
            ("EIP-712 schema review only; nonce consumption and signature authorization unavailable",),
            None)
    except (ValueError, KeyError, TypeError, OverflowError) as exc:
        return None, PolicyDecision("DENY", (str(exc),), None)
