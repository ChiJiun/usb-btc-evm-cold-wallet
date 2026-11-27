"""Strict, size-bounded USB interchange; hash is INTEGRITY, not authentication.

The payload schemas are positive allowlists, not just secret-name denylists:
no arbitrary keys, nested objects, strings or bytes are ever exported.
Untrusted online requests must still be independently reviewed OFFLINE.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path

from eth_utils import to_checksum_address
from embit import networks, script

from .vault import save_vault

FORMAT = "usb-cold-wallet-exchange"
VERSION = 1
MAX_BYTES = 200_000
KINDS = {
    "btc-request": "bitcoin-testnet",
    "btc-signed": "bitcoin-testnet",
    "evm-request": "sepolia",
    "evm-signed": "sepolia",
    "watch-only": "testnet-sepolia",
}
# Defense in depth: schema allowlists are the primary protection.
FORBIDDEN_KEYS = {"mnemonic", "seed", "private_key", "privatekey", "secret", "xprv", "vault", "passphrase", "password"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX8 = re.compile(r"^[0-9a-fA-F]{8}$")
_HEX_TX = re.compile(r"^[0-9a-fA-F]+$")
_BTC_NETWORK = networks.NETWORKS["test"]
_MAX_MONEY = 21_000_000 * 100_000_000
_EVM_TX_FIELDS = {
    "type", "chainId", "nonce", "to", "value", "gas", "maxFeePerGas", "maxPriorityFeePerGas",
}
_EVM_TX_OPTIONAL = {"data", "accessList"}
_EVM_SIGNED_FIELDS = {
    "chain_id", "from", "to", "value_wei", "max_fee_wei", "max_total_wei",
    "transaction_hash", "signed_raw_transaction", "decoded_transaction",
}
_BTC_SIGNED_FIELDS = {
    "network", "recipient", "amount_sats", "fee_sats", "signature_count",
    "signed_psbt_base64", "finalized_tx_hex",
}


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _no_secrets(value, depth=0):
    if depth > 16:
        raise ValueError("Exchange payload nesting limit exceeded")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Exchange object keys must be strings")
            normalized = key.lower().replace("-", "_")
            if (normalized in FORBIDDEN_KEYS or any(token in normalized for token in
                    ("mnemonic", "passphrase", "private", "seed", "secret", "xprv", "password"))):
                raise ValueError("Secret field is forbidden in exchange data")
            _no_secrets(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _no_secrets(item, depth + 1)
    elif value is not None and type(value) not in (str, int, bool):
        raise ValueError("Unsupported exchange payload value")


def _fields(obj, required, optional=frozenset(), label="payload"):
    if type(obj) is not dict or not required <= obj.keys() or obj.keys() - (required | optional):
        raise ValueError(f"Unexpected {label} fields")


def _int(value, label, lo=0, hi=(1 << 256) - 1):
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f"Invalid {label}")
    return value


def _address(value):
    if type(value) is not str or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        raise ValueError("Invalid Ethereum address")
    canonical = to_checksum_address(value)
    if value != canonical:
        raise ValueError("Ethereum address must be checksummed")
    return value


def _btc_address(value):
    if (type(value) is not str or not re.fullmatch(r"tb1q[023456789acdefghjklmnpqrstuvwxyz]{38}", value)):
        raise ValueError("Only canonical Bitcoin testnet BIP84 P2WPKH address allowed")
    try:
        if script.address_to_scriptpubkey(value).address(_BTC_NETWORK) != value:
            raise ValueError("Noncanonical Bitcoin testnet address")
    except Exception as exc:
        raise ValueError("Invalid Bitcoin testnet address") from exc
    return value


def _psbt_base64(value, label):
    if type(value) is not str or len(value) > 180_000 or not value:
        raise ValueError(f"{label} must be bounded PSBT base64")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"Invalid {label} base64") from exc
    if not data.startswith(b"psbt\xff") or len(data) > 130_000:
        raise ValueError(f"Invalid or oversized {label}")
    return data


def _validate_unsigned_evm(payload):
    _fields(payload, _EVM_TX_FIELDS, _EVM_TX_OPTIONAL, "EVM request")
    if _int(payload["type"], "type", 2, 2) != 2 or _int(payload["chainId"], "chain", 11155111, 11155111) != 11155111:
        raise ValueError("Sepolia type-2 required")
    _int(payload["nonce"], "nonce", 0, (1 << 53) - 1)
    _int(payload["value"], "value Wei", 1)
    _int(payload["gas"], "gas", 21000, 21000)
    max_fee = _int(payload["maxFeePerGas"], "maxFeePerGas", 1, 1_000_000_000_000)
    _int(payload["maxPriorityFeePerGas"], "priority fee", 0, max_fee)
    _address(payload["to"])
    if payload.get("data", "0x") not in ("0x", ""):
        raise ValueError("Contract data prohibited")
    if payload.get("accessList", []) != []:
        raise ValueError("Access list prohibited")


def _validate_watch_only(payload):
    _fields(payload, {"bitcoin", "evm"}, label="watch-only")
    btc, evm = payload["bitcoin"], payload["evm"]
    _fields(btc, {"network", "derivation", "account_tpub", "receive_addresses"},
            {"master_fingerprint"}, "Bitcoin public")
    _fields(evm, {"network", "chain_id", "derivation", "address"}, label="EVM public")
    if btc["network"] != "testnet" or btc["derivation"] != "m/84h/1h/0h":
        raise ValueError("Watch-only Bitcoin path/network mismatch")
    tpub = btc["account_tpub"]
    if type(tpub) is not str or not re.fullmatch(r"tpub[1-9A-HJ-NP-Za-km-z]{100,115}", tpub):
        raise ValueError("Invalid testnet account tpub")
    from embit import bip32
    try:
        account = bip32.HDKey.from_base58(tpub)
        if account.is_private:
            raise ValueError("Private BIP32 keys must never be exported")
        if (account.depth != 3 or account.child_number != 0x80000000 or
                account.version != _BTC_NETWORK["xpub"]):
            raise ValueError("Expected Bitcoin testnet BIP84 account m/84h/1h/0h")
    except Exception as exc:
        raise ValueError("Malformed public tpub") from exc
    if "master_fingerprint" in btc and (
        type(btc["master_fingerprint"]) is not str or not _HEX8.fullmatch(btc["master_fingerprint"])
    ):
        raise ValueError("Malformed master fingerprint")
    addrs = btc["receive_addresses"]
    if type(addrs) is not list or not 1 <= len(addrs) <= 20:
        raise ValueError("Watch-only address count out of bounds")
    if any(type(addr) is not str for addr in addrs):
        raise ValueError("Invalid Bitcoin watch-only receive address")
    if len(set(addrs)) != len(addrs):
        raise ValueError("Duplicate Bitcoin address")
    for index, addr in enumerate(addrs):
        _btc_address(addr)
        derived = script.p2wpkh(account.derive(f"m/0/{index}").key).address(_BTC_NETWORK)
        if derived != addr:
            raise ValueError("Public Bitcoin address does not match testnet account tpub")
    if evm["network"] != "Sepolia" or _int(evm["chain_id"], "Sepolia", 11155111, 11155111) != 11155111:
        raise ValueError("Watch-only EVM network mismatch")
    if evm["derivation"] != "m/44h/60h/0h/0/0":
        raise ValueError("Unexpected EVM derivation")
    _address(evm["address"])


def _validate_evm_signed(payload):
    _fields(payload, _EVM_SIGNED_FIELDS, label="signed EVM")
    if _int(payload["chain_id"], "signed chain", 11155111, 11155111) != 11155111:
        raise ValueError("Signed chain mismatch")
    _address(payload["from"])
    _address(payload["to"])
    _int(payload["value_wei"], "signed value", 1)
    _int(payload["max_fee_wei"], "signed fee", 0)
    _int(payload["max_total_wei"], "signed total", 1)
    raw = payload["signed_raw_transaction"]
    if type(raw) is not str or len(raw) > 8194 or not raw.startswith("0x") or not _HEX_TX.fullmatch(raw[2:]):
        raise ValueError("Invalid raw EVM signature")
    if type(payload["transaction_hash"]) is not str or not re.fullmatch(r"0x[0-9a-f]{64}", payload["transaction_hash"]):
        raise ValueError("Invalid EVM transaction hash")
    from .evm import decode_signed_eip1559, review_signed_evm_transaction
    decoded = decode_signed_eip1559(raw)
    # The nested object must reflect the actual signed bytes exactly. No
    # arbitrary nested strings are allowed, even under innocuous key names.
    if type(payload["decoded_transaction"]) is not dict or payload["decoded_transaction"] != decoded:
        raise ValueError("Signed EVM nested metadata does not match raw transaction")
    checked = review_signed_evm_transaction(raw, payload["to"], payload["value_wei"])
    if (checked["from"] != payload["from"] or checked["transaction_hash"] != payload["transaction_hash"] or
            checked["max_fee_wei"] != payload["max_fee_wei"] or checked["max_total_wei"] != payload["max_total_wei"]):
        raise ValueError("Signed EVM metadata mismatches signed transaction")


def _validate_btc_signed(payload):
    _fields(payload, _BTC_SIGNED_FIELDS, label="signed BTC")
    if payload["network"] != "bitcoin-testnet":
        raise ValueError("Signed Bitcoin network mismatch")
    _btc_address(payload["recipient"])
    amount = _int(payload["amount_sats"], "Bitcoin amount", 1, _MAX_MONEY)
    fee = _int(payload["fee_sats"], "Bitcoin fee", 0, _MAX_MONEY)
    count = _int(payload["signature_count"], "signature count", 1, 20)
    data = _psbt_base64(payload["signed_psbt_base64"], "signed PSBT")
    raw = payload["finalized_tx_hex"]
    if type(raw) is not str or len(raw) > 140_000 or len(raw) % 2 or not _HEX_TX.fullmatch(raw):
        raise ValueError("Malformed finalized Bitcoin transaction")
    from .btc import _read_psbt
    from embit import ec, transaction
    psbt = _read_psbt(payload["signed_psbt_base64"])
    if count != len(psbt.inputs) or len(psbt.outputs) > 2 or psbt.tx.version != 2 or psbt.tx.locktime != 0:
        raise ValueError("Invalid signed PSBT counts or transaction policy")
    if any(vin.sequence != 0xffffffff for vin in psbt.tx.vin):
        raise ValueError("Unsupported Bitcoin locktime/RBF")
    if psbt.unknown or psbt.xpubs or any(out.unknown or out.bip32_derivations for out in psbt.outputs):
        raise ValueError("Unexpected signed Bitcoin metadata")
    inputs_total = 0
    for ix, scope in enumerate(psbt.inputs):
        if (scope.unknown or len(scope.partial_sigs) != 1 or scope.final_scriptsig is not None or
                scope.final_scriptwitness is not None or scope.redeem_script is not None or
                scope.witness_script is not None or scope.taproot_sigs or scope.taproot_scripts or
                scope.taproot_bip32_derivations or scope.taproot_internal_key is not None or
                scope.taproot_merkle_root is not None or scope.non_witness_utxo is None or
                scope.witness_utxo is None or scope.sighash_type not in (None, 1)):
            raise ValueError("Unexpected signed Bitcoin input metadata")
        if scope.non_witness_utxo.txid() != psbt.tx.vin[ix].txid:
            raise ValueError("Bitcoin previous transaction mismatch")
        prevout_index = psbt.tx.vin[ix].vout
        if not 0 <= prevout_index < len(scope.non_witness_utxo.vout):
            raise ValueError("Bitcoin prevout index out of range")
        prev = scope.non_witness_utxo.vout[prevout_index]
        if prev.value != scope.witness_utxo.value or prev.script_pubkey.data != scope.witness_utxo.script_pubkey.data:
            raise ValueError("Bitcoin input UTXO mismatch")
        if not prev.script_pubkey.data.startswith(b"\x00\x14") or len(prev.script_pubkey.data) != 22:
            raise ValueError("Bitcoin input not P2WPKH")
        inputs_total += prev.value
        pub, sig = next(iter(scope.partial_sigs.items()))
        # A mathematically valid ECDSA signature from an unrelated key cannot
        # spend this P2WPKH prevout. Bind the witness key to its HASH160 script.
        if script.p2wpkh(pub).data != prev.script_pubkey.data:
            raise ValueError("Signed Bitcoin public key does not match P2WPKH UTXO")
        if len(sig) < 2 or sig[-1] != 1 or not pub.verify(ec.Signature.parse(sig[:-1]), psbt.sighash(ix, sighash=1)):
            raise ValueError("Invalid signed Bitcoin ECDSA signature")
    outputs_total = 0
    recipient_hits = 0
    for out in psbt.tx.vout:
        if len(out.script_pubkey.data) != 22 or not out.script_pubkey.data.startswith(b"\x00\x14"):
            raise ValueError("Unexpected BTC output script (possible data exfiltration)")
        outputs_total += out.value
        if out.script_pubkey.address(_BTC_NETWORK) == payload["recipient"] and out.value == amount:
            recipient_hits += 1
    if recipient_hits != 1 or inputs_total - outputs_total != fee:
        raise ValueError("Signed Bitcoin output/fee mismatch")
    try:
        final = transaction.Transaction.parse(bytes.fromhex(raw))
    except Exception as exc:
        raise ValueError("Malformed finalized Bitcoin transaction") from exc
    if final.txid() != psbt.tx.txid() or len(final.vin) != len(psbt.inputs) or final.vout != psbt.tx.vout:
        raise ValueError("Finalized Bitcoin transaction mismatch")
    for ix, inp in enumerate(final.vin):
        if inp.script_sig.data or len(inp.witness.items) != 2:
            raise ValueError("Invalid finalized Bitcoin witness")
        pub, sig = next(iter(psbt.inputs[ix].partial_sigs.items()))
        if inp.witness.items != [sig, pub.sec()]:
            raise ValueError("Finalized witness does not match PSBT signature")


def _validate_payload(kind, payload):
    _no_secrets(payload)
    if kind == "btc-request":
        _psbt_base64(payload, "BTC request")
        # Integrity alone is not enough: reject malformed/PSBTv2 framing
        # before `inspect-transfer` reports a valid exchange envelope.
        from .btc import _read_psbt
        _read_psbt(payload)
    elif kind == "evm-request":
        _validate_unsigned_evm(payload)
    elif kind == "watch-only":
        _validate_watch_only(payload)
    elif kind == "btc-signed":
        _validate_btc_signed(payload)
    elif kind == "evm-signed":
        _validate_evm_signed(payload)
    else:
        raise ValueError("Unknown exchange kind")


def package(kind: str, payload):
    if type(kind) is not str or kind not in KINDS:
        raise ValueError("Unrecognized exchange kind")
    _validate_payload(kind, payload)
    content = {"format": FORMAT, "version": VERSION, "kind": kind,
               "network": KINDS[kind], "payload": payload}
    encoded = _canonical(content)
    if len(encoded) > MAX_BYTES:
        raise ValueError("Exchange exceeds maximum size")
    return {**content, "sha256": hashlib.sha256(encoded).hexdigest()}


def verify(data, expected_kind=None):
    if not isinstance(data, dict) or set(data) != {
        "format", "version", "kind", "network", "payload", "sha256"
    }:
        raise ValueError("Invalid exchange envelope fields")
    kind = data["kind"]
    if (data["format"] != FORMAT or type(data["version"]) is not int or
            data["version"] != VERSION or type(kind) is not str or kind not in KINDS or
            data["network"] != KINDS[kind] or
            (expected_kind is not None and kind != expected_kind)):
        raise ValueError("Exchange format, type, or network mismatch")
    _validate_payload(kind, data["payload"])
    content = {field: data[field] for field in ("format", "version", "kind", "network", "payload")}
    encoded = _canonical(content)
    if len(encoded) > MAX_BYTES:
        raise ValueError("Exchange exceeds maximum size")
    digest = hashlib.sha256(encoded).hexdigest()
    if type(data["sha256"]) is not str or not hmac.compare_digest(digest, data["sha256"]):
        raise ValueError("Exchange SHA-256 integrity check failed")
    return data["payload"]


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key in exchange envelope")
        result[key] = value
    return result


def read_bounded(path: Path, limit=MAX_BYTES + 8192):
    """Read a single regular file once, never follow a symbolic link or block on devices."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(Path(path), flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Transfer must be a regular file, not a device or pipe")
        raw = os.read(fd, limit + 1)
        if len(raw) > limit:
            raise ValueError("Exchange file too large")
        return raw
    finally:
        os.close(fd)


def read_envelope(path: Path, expected_kind=None):
    raw = read_bounded(path)
    try:
        data = json.loads(raw.decode("utf-8"),
                          object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON number")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid exchange JSON") from exc
    verify(data, expected_kind)
    return data


def read(path: Path, expected_kind=None):
    return read_envelope(path, expected_kind)["payload"]


def write(path: Path, kind: str, payload):
    save_vault(path, package(kind, payload))
