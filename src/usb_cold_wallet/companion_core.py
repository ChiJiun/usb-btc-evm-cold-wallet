"""Online-only watch-only companion. Never import vault/seed/signing-key code here.

USB exchange v1 is compatible with the pending Issue #5 envelope; checksums
detect corruption but do NOT authenticate the offline source.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from embit import bip32, networks, script
from eth_account import Account
from eth_account.typed_transactions import TypedTransaction
from eth_utils import is_checksum_address, to_checksum_address, keccak
from hexbytes import HexBytes

CHAIN_ID = 11155111
CHAIN_HEX = hex(CHAIN_ID)
MAX_EXCHANGE_BYTES = 200_000
MAX_RPC_BYTES = 256_000
MAX_GWEI = 1_000  # hard safety ceiling for the testnet prototype
EVM_PATH = "m/44h/60h/0h/0/0"
BTC_PATH = "m/84h/1h/0h"
FORMAT = "usb-cold-wallet-exchange"
KIND_NETWORK = {
    "watch-only": "testnet-sepolia",
    "evm-request": "sepolia",
    "evm-signed": "sepolia",
    "btc-request": "bitcoin-testnet",
    "btc-signed": "bitcoin-testnet",
}
TX_FIELDS = ("type", "chainId", "nonce", "to", "value", "gas", "maxFeePerGas", "maxPriorityFeePerGas", "data")
ADDRESS_RE = re.compile(r"^0x[0-9A-Fa-f]{40}$")
HASH_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
RAW_RE = re.compile(r"^0x[0-9a-fA-F]{2,8192}$")
SENSITIVE = ("mnemonic", "passphrase", "private", "seed", "secret", "xprv", "password", "vault")


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON property")
        obj[key] = value
    return obj


def decode_json(data: bytes):
    if not isinstance(data, bytes) or len(data) > MAX_EXCHANGE_BYTES:
        raise ValueError("Input must be a bounded JSON file")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JSON") from exc


def _public_fields(value, depth=0):
    if depth > 16:
        raise ValueError("Nested data exceeds limit")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or any(word in key.lower().replace("-", "_") for word in SENSITIVE):
                raise ValueError("Secret or invalid field in public exchange data")
            _public_fields(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _public_fields(item, depth + 1)
    elif value is not None and type(value) not in (str, int, float, bool):
        raise ValueError("Unsupported JSON value")


def pack_envelope(kind: str, payload) -> dict:
    """Use the same strict transport schema as the physically offline signer."""
    from .exchange import package
    return package(kind, payload)


def unpack_envelope(data: dict, kind: str):
    """Reject any envelope that the offline exchange validator would reject."""
    from .exchange import verify
    return verify(data, kind)


def checked_address(value: str) -> str:
    if not isinstance(value, str) or not ADDRESS_RE.fullmatch(value):
        raise ValueError("Invalid Ethereum address")
    body = value[2:]
    if any(ch.islower() for ch in body if ch.isalpha()) and any(ch.isupper() for ch in body if ch.isalpha()):
        if not is_checksum_address(value):
            raise ValueError("Mixed-case address has invalid EIP-55 checksum")
    return to_checksum_address(value)


def _quantity(value, label) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,64}", value):
        raise ValueError(f"RPC supplied invalid {label}")
    return int(value, 16)


def _eth_to_wei(value: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,20})(?:\.[0-9]{1,18})?", value):
        raise ValueError("Amount must be a positive ETH decimal (max 18 places)")
    try:
        wei = int(Decimal(value) * Decimal(10**18))
    except InvalidOperation as exc:
        raise ValueError("Invalid ETH amount") from exc
    if wei <= 0 or wei >= 2**256:
        raise ValueError("ETH amount is out of bounds")
    return wei


def validate_watch_only(data) -> dict:
    if not isinstance(data, dict) or set(data) != {"bitcoin", "evm"}:
        raise ValueError("Watch-only export must contain bitcoin and evm")
    _public_fields(data)
    btc, evm = data["bitcoin"], data["evm"]
    if (not isinstance(evm, dict) or set(evm) != {"network", "chain_id", "derivation", "address"}
            or evm["network"] != "Sepolia" or type(evm["chain_id"]) is not int or evm["chain_id"] != CHAIN_ID
            or evm["derivation"] != EVM_PATH):
        raise ValueError("Unsupported EVM watch-only account")
    evm_addr = checked_address(evm["address"])
    required_btc = {"network", "derivation", "account_tpub", "receive_addresses"}
    if (not isinstance(btc, dict) or not required_btc <= set(btc)
            or set(btc) - required_btc - {"master_fingerprint"}
            or btc["network"] != "testnet" or btc["derivation"] != BTC_PATH
            or not isinstance(btc["account_tpub"], str) or len(btc["account_tpub"]) > 150
            or not isinstance(btc["receive_addresses"], list)
            or not 1 <= len(btc["receive_addresses"]) <= 20):
        raise ValueError("Unsupported BTC watch-only export")
    try:
        tpub = bip32.HDKey.from_base58(btc["account_tpub"])
        if tpub.is_private or tpub.depth != 3 or tpub.version != networks.NETWORKS["test"]["xpub"]:
            raise ValueError("BTC account key is not a testnet public account key")
        expected = [script.p2wpkh(tpub.derive(f"0/{i}").key).address(networks.NETWORKS["test"])
                    for i in range(len(btc["receive_addresses"]))]
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ValueError("Invalid BTC account public key") from exc
    if btc["receive_addresses"] != expected:
        raise ValueError("BTC receive addresses do not match account tpub")
    fp = btc.get("master_fingerprint")
    if fp is not None and (type(fp) is not str or not re.fullmatch(r"[0-9a-f]{8}", fp)):
        raise ValueError("Invalid BTC master fingerprint")
    return {"bitcoin": {**btc}, "evm": {**evm, "address": evm_addr}}


def parse_watch_only(raw: bytes) -> dict:
    data = decode_json(raw)
    if isinstance(data, dict) and data.get("format") == FORMAT:
        data = unpack_envelope(data, "watch-only")
    return validate_watch_only(data)


class JsonRpc:
    """Fixed-endpoint, bounded, no-retry JSON RPC client for Sepolia only."""

    def __init__(self, url: str, timeout: float = 8):
        parts = urlsplit(url)
        if (parts.scheme not in ("https", "http") or not parts.hostname
                or parts.username or parts.password or parts.fragment
                or (parts.scheme == "http" and parts.hostname not in ("localhost", "127.0.0.1", "::1"))):
            raise ValueError("RPC must be HTTPS or localhost HTTP without URL credentials")
        if not 1 <= timeout <= 30:
            raise ValueError("RPC timeout out of bounds")
        self.url = url
        self.timeout = timeout
        self.display_endpoint = f"{parts.scheme}://{parts.hostname}" + (f":{parts.port}" if parts.port else "")

    def call(self, method: str, params: list):
        request_id = secrets.randbelow(2**31)
        body = canonical({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        request = Request(self.url, data=body,
                          headers={"Content-Type": "application/json", "Accept": "application/json"},
                          method="POST")
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RPC_BYTES + 1)
        except HTTPError as exc:
            raise ValueError(f"RPC HTTP error ({exc.code})") from None
        except (URLError, TimeoutError, OSError) as exc:
            raise ValueError("RPC unavailable or timed out; no transaction was automatically retried") from None
        if len(raw) > MAX_RPC_BYTES:
            raise ValueError("RPC response exceeds size limit")
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                              parse_constant=lambda v: (_ for _ in ()).throw(ValueError("Non-finite RPC JSON number")))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("RPC returned invalid JSON") from exc
        if not isinstance(data, dict) or data.get("jsonrpc") != "2.0" or data.get("id") != request_id:
            raise ValueError("RPC response ID mismatch")
        if data.get("error") is not None:
            raise ValueError("RPC rejected the request; inspect the transaction and RPC endpoint")
        if "result" not in data:
            raise ValueError("RPC missing result")
        return data["result"]

    def assert_sepolia(self):
        if _quantity(self.call("eth_chainId", []), "chain ID") != CHAIN_ID:
            raise ValueError("RPC chain mismatch: refusing non-Sepolia transaction")

    def account_state(self, address: str):
        self.assert_sepolia()
        balance = _quantity(self.call("eth_getBalance", [address, "latest"]), "balance")
        nonce = _quantity(self.call("eth_getTransactionCount", [address, "pending"]), "pending nonce")
        return balance, nonce

    def fee_quote(self):
        block = self.call("eth_getBlockByNumber", ["latest", False])
        if not isinstance(block, dict):
            raise ValueError("RPC supplied invalid latest block")
        base = _quantity(block.get("baseFeePerGas"), "base fee")
        priority = _quantity(self.call("eth_maxPriorityFeePerGas", []), "priority fee")
        if base > MAX_GWEI * 10**9 or priority > MAX_GWEI * 10**9:
            raise ValueError("RPC fee quote exceeds safety cap")
        return min(MAX_GWEI * 10**9, 2 * base + priority), priority


class CompanionSession:
    """One pending signing intent. All session data is volatile/public."""

    def __init__(self, rpc: JsonRpc):
        self.rpc = rpc
        self.wallet = None
        self.pending = None
        self.lock = threading.RLock()

    def import_wallet(self, raw: bytes):
        wallet = parse_watch_only(raw)
        with self.lock:
            if self.pending is not None:
                raise ValueError("Cancel the current transaction before switching wallets")
            self.wallet = wallet
        return self.public_view()

    def public_view(self):
        with self.lock:
            if self.wallet is None:
                return {"loaded": False, "rpc": self.rpc.display_endpoint, "chain": "Sepolia"}
            btc = self.wallet["bitcoin"]
            return {"loaded": True, "rpc": self.rpc.display_endpoint, "chain": "Sepolia",
                    "evm_address": self.wallet["evm"]["address"],
                    "btc_network": "Bitcoin testnet", "btc_addresses": btc["receive_addresses"],
                    "btc_account_tpub": btc["account_tpub"],
                    "pending": self.pending_view()}

    def pending_view(self):
        if self.pending is None:
            return None
        p = self.pending
        return {"request_id": p["request_id"], "digest": p["digest"], "tx": p["tx"],
                "stage": p["stage"], "tx_hash": p.get("tx_hash"),
                "result": p.get("result"), "reorg_warning": p.get("reorg_warning", False),
                "block_number": p.get("block_number")}

    def overview(self):
        with self.lock:
            if self.wallet is None:
                raise ValueError("Import a PUBLIC watch-only export first")
            address = self.wallet["evm"]["address"]
            balance, nonce = self.rpc.account_state(address)
            fee, priority = self.rpc.fee_quote()
            return {"address": address, "balance_wei": str(balance), "pending_nonce": nonce,
                    "suggested_max_fee_gwei": str(Decimal(fee) / 10**9),
                    "suggested_priority_fee_gwei": str(Decimal(priority) / 10**9),
                    "rpc": self.rpc.display_endpoint, "chain": "Sepolia", "chain_id": CHAIN_ID}

    def prepare(self, recipient: str, amount_eth: str, max_fee_gwei: str = ""):
        with self.lock:
            if self.wallet is None:
                raise ValueError("Import a PUBLIC watch-only export first")
            if self.pending is not None:
                raise ValueError("Cancel or finish the previous request before preparing a new one")
            target = checked_address(recipient)
            amount_wei = _eth_to_wei(amount_eth)
            sender = self.wallet["evm"]["address"]
            balance, nonce = self.rpc.account_state(sender)
            estimated_fee, priority = self.rpc.fee_quote()
            fee = estimated_fee
            if max_fee_gwei:
                if not isinstance(max_fee_gwei, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,3})(?:\.[0-9]{1,9})?", max_fee_gwei):
                    raise ValueError("Max fee must be decimal gwei with up to 9 places")
                fee = int(Decimal(max_fee_gwei) * 10**9)
            if not 0 < fee <= MAX_GWEI * 10**9 or priority > fee:
                raise ValueError("Fee cap is invalid or below RPC priority fee")
            if nonce >= 2**64:
                raise ValueError("RPC nonce is implausible")
            tx = {"type": 2, "chainId": CHAIN_ID, "nonce": nonce, "to": target,
                  "value": amount_wei, "gas": 21000, "maxFeePerGas": fee,
                  "maxPriorityFeePerGas": priority, "data": "0x"}
            max_total = amount_wei + fee * 21000
            if max_total > balance:
                raise ValueError("Insufficient balance for amount plus maximum network fee")
            envelope = pack_envelope("evm-request", tx)
            self.pending = {"request_id": secrets.token_hex(16), "digest": hashlib.sha256(canonical(tx)).hexdigest(),
                            "tx": tx, "stage": "prepared", "envelope": envelope}
            return {"pending": self.pending_view(), "envelope": envelope,
                    "max_fee_wei": str(fee * 21000), "max_total_wei": str(max_total)}

    def request_envelope(self):
        with self.lock:
            if self.pending is None or self.pending["stage"] != "prepared":
                raise ValueError("No pending unsigned request")
            return self.pending["envelope"]

    def request_raw_json(self, *, legacy=False) -> bytes:
        """Download exact Python integers, never via JavaScript Number."""
        with self.lock:
            if self.pending is None or self.pending["stage"] != "prepared":
                raise ValueError("No pending unsigned request")
            source = self.pending["tx"] if legacy else self.pending["envelope"]
            return canonical(source) + b"\n"

    def accept_signed(self, raw: bytes):
        with self.lock:
            if self.pending is None or self.pending["stage"] != "prepared":
                raise ValueError("No unsigned request waiting for a signature")
            data = decode_json(raw)
            payload = unpack_envelope(data, "evm-signed") if isinstance(data, dict) and data.get("format") == FORMAT else data
            if not isinstance(payload, dict) or set(payload) != {
                "chain_id", "from", "to", "value_wei", "max_fee_wei",
                "max_total_wei", "decoded_transaction", "transaction_hash",
                "signed_raw_transaction",
            }:
                raise ValueError("Invalid signed EVM payload")
            signed_hex = payload["signed_raw_transaction"]
            if not isinstance(signed_hex, str) or not RAW_RE.fullmatch(signed_hex):
                raise ValueError("Invalid signed raw transaction")
            raw_tx = HexBytes(signed_hex)
            if raw_tx[0] != 2:
                raise ValueError("Only EIP-1559 type-2 signatures are supported")
            try:
                decoded = TypedTransaction.from_bytes(raw_tx).as_dict()
                recovered = checked_address(Account.recover_transaction(raw_tx))
            except (ValueError, TypeError, IndexError, KeyError) as exc:
                raise ValueError("Cannot decode or recover signed transaction") from exc
            wanted = self.pending["tx"]
            if (type(decoded.get("type")) is not int or decoded["type"] != 2
                    or any(type(decoded.get(k)) is not int or decoded[k] != wanted[k] for k in (
                        "chainId", "nonce", "value", "gas", "maxFeePerGas", "maxPriorityFeePerGas"
                    ))
                    or bytes(decoded.get("to", b"")) != bytes.fromhex(wanted["to"][2:])
                    or bytes(decoded.get("data", b"")) != b""
                    or decoded.get("accessList") not in ([], ())
                    or recovered != self.wallet["evm"]["address"]):
                raise ValueError("Signed transaction differs from the approved request or signer")
            tx_hash = "0x" + keccak(raw_tx).hex()
            if (type(payload["chain_id"]) is not int or payload["chain_id"] != CHAIN_ID
                    or checked_address(payload["from"]) != recovered
                    or checked_address(payload["to"]) != wanted["to"]
                    or type(payload["value_wei"]) is not int or payload["value_wei"] != wanted["value"]
                    or not isinstance(payload["transaction_hash"], str)
                    or not HASH_RE.fullmatch(payload["transaction_hash"])
                    or payload["transaction_hash"].removeprefix("0x").lower() != tx_hash[2:]):
                raise ValueError("Signed metadata / transaction hash mismatch")
            expected_meta = {
                "type": 2, "chain_id": decoded["chainId"], "nonce": decoded["nonce"],
                "max_priority_fee_per_gas": decoded["maxPriorityFeePerGas"],
                "max_fee_per_gas": decoded["maxFeePerGas"], "gas": decoded["gas"],
                "to": wanted["to"], "value_wei": decoded["value"],
                "data": "0x", "access_list": [],
                "signature": {
                    "y_parity": decoded["v"], "r": hex(decoded["r"]),
                    "s": hex(decoded["s"]),
                },
                "transaction_hash": tx_hash,
            }
            maximum_fee = decoded["gas"] * decoded["maxFeePerGas"]
            if (type(payload["max_fee_wei"]) is not int
                    or payload["max_fee_wei"] != maximum_fee
                    or type(payload["max_total_wei"]) is not int
                    or payload["max_total_wei"] != decoded["value"] + maximum_fee
                    or payload["decoded_transaction"] != expected_meta):
                raise ValueError("Signed fee or decoded transaction metadata mismatch")
            # Do not echo signed bytes to logs/UI; never accept a second response.
            self.pending.update({"stage": "verified", "signed": signed_hex, "tx_hash": tx_hash})
            return self.pending_view()

    def broadcast(self):
        with self.lock:
            if self.pending is None or self.pending["stage"] != "verified":
                raise ValueError("Requires a unique verified signature; broadcast cannot repeat")
            self.rpc.assert_sepolia()
            nonce = _quantity(self.rpc.call(
                "eth_getTransactionCount", [self.wallet["evm"]["address"], "pending"]), "pending nonce")
            if nonce > self.pending["tx"]["nonce"]:
                raise ValueError("Stale nonce: an earlier or concurrent transaction is pending")
            # Mark ambiguous *before* network I/O: timeout may mean RPC accepted it.
            self.pending["stage"] = "broadcast_unknown"
            try:
                network_hash = self.rpc.call("eth_sendRawTransaction", [self.pending["signed"]])
            except ValueError:
                raise ValueError("Broadcast result unknown; query transaction status before taking further action") from None
            if not isinstance(network_hash, str) or network_hash.lower() != self.pending["tx_hash"].lower():
                raise ValueError("RPC returned a different transaction hash; do not resubmit automatically")
            self.pending["stage"] = "broadcasted"
            return self.pending_view()

    def check_status(self):
        with self.lock:
            if self.pending is None or self.pending.get("tx_hash") is None:
                raise ValueError("No signed transaction to query")
            self.rpc.assert_sepolia()
            tx_hash = self.pending["tx_hash"]
            receipt = self.rpc.call("eth_getTransactionReceipt", [tx_hash])
            previous = self.pending.get("result")
            if receipt is None:
                transaction = self.rpc.call("eth_getTransactionByHash", [tx_hash])
                result = "pending" if isinstance(transaction, dict) else "not_found"
                # A formerly included transaction can disappear during a reorg.
                if previous in ("confirmed", "reverted", "reorg_suspected"):
                    self.pending["result"] = "reorg_suspected"
                    self.pending["reorg_warning"] = True
                else:
                    self.pending["result"] = result
            else:
                if not isinstance(receipt, dict) or not isinstance(receipt.get("transactionHash"), str) or receipt["transactionHash"].lower() != tx_hash.lower():
                    raise ValueError("RPC returned invalid receipt")
                outcome = _quantity(receipt.get("status"), "receipt status")
                if outcome not in (0, 1):
                    raise ValueError("Invalid receipt status")
                new_hash = receipt.get("blockHash")
                if new_hash is not None and (not isinstance(new_hash, str) or not HASH_RE.fullmatch(new_hash)):
                    raise ValueError("Invalid receipt block hash")
                if self.pending.get("block_hash") and new_hash and new_hash != self.pending["block_hash"]:
                    self.pending["reorg_warning"] = True
                self.pending["result"] = "confirmed" if outcome == 1 else "reverted"
                self.pending["block_number"] = _quantity(receipt.get("blockNumber"), "block number")
                if new_hash:
                    self.pending["block_hash"] = new_hash
            return self.pending_view()

    def cancel(self):
        with self.lock:
            self.pending = None
            return {"cancelled": True}
