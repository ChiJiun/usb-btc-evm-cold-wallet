"""Transport-neutral offline transaction review and explicit-signing state.

This module is intentionally UI-toolkit agnostic. USB-B files and QR-decoded
text both terminate in the same exchange verifier, then the existing BTC/EVM
backend performs the actual policy review and signing.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import hashlib
import json
from pathlib import Path
from typing import Any

from embit import networks, script

from .btc import _read_psbt, review_btc_psbt, sign_btc_psbt
from .evm import review_evm_transaction, sign_evm
from .exchange import package, read_envelope, verify, _unique_object, MAX_BYTES
from .keys import btc_key, evm_account, watch_only
from .policy import enforce_review_policy
from .vault import save_vault

_MAX_CHANGE_SCAN = 1000


@dataclass(frozen=True)
class ReviewField:
    key: str
    value: str
    source: str
    critical: bool = True


@dataclass(frozen=True)
class ReviewPage:
    key: str
    fields: tuple[ReviewField, ...]


@dataclass(frozen=True)
class ReviewPlan:
    kind: str
    envelope_kind: str
    request_digest: str
    review_digest: str
    network: str
    account: str
    recipient: str
    amount_atomic: int
    fee_atomic: int
    pages: tuple[ReviewPage, ...]
    challenge: str
    payload_snapshot: str
    change_index: int | None = None

    @property
    def signed_kind(self) -> str:
        return "evm-signed" if self.kind == "evm" else "btc-signed"


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _field(key: str, value: Any, source: str, *, critical: bool = True) -> ReviewField:
    if isinstance(value, (dict, list, tuple)):
        rendered = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    elif isinstance(value, bool):
        rendered = "true" if value else "false"
    else:
        rendered = str(value)
    return ReviewField(key=key, value=rendered, source=source, critical=critical)


def _review_document(kind: str, request_digest: str, pages: tuple[ReviewPage, ...]) -> dict:
    return {
        "schema": "usb-cold-wallet-offline-review-v1",
        "kind": kind,
        "request_sha256": request_digest,
        "pages": [
            {
                "key": page.key,
                "fields": [
                    {
                        "key": field.key,
                        "value": field.value,
                        "source": field.source,
                        "critical": field.critical,
                    }
                    for field in page.fields
                ],
            }
            for page in pages
        ],
    }


def _with_review_digest(
    *,
    kind: str,
    envelope_kind: str,
    request_digest: str,
    network: str,
    account: str,
    recipient: str,
    amount_atomic: int,
    fee_atomic: int,
    pages: tuple[ReviewPage, ...],
    payload_snapshot: str,
    change_index: int | None = None,
) -> ReviewPlan:
    digest = hashlib.sha256(_canonical(_review_document(kind, request_digest, pages))).hexdigest()
    digest_page = ReviewPage(
        key="integrity",
        fields=(
            _field("request_digest", request_digest, "verified exchange envelope.sha256"),
            _field("review_digest", digest, "SHA-256(canonical offline reviewed fields)"),
        ),
    )
    full_pages = (pages[0], digest_page, *pages[1:])
    challenge = f"SIGN {kind.upper()} {recipient[-8:]} {digest[:8]}"
    return ReviewPlan(
        kind=kind,
        envelope_kind=envelope_kind,
        request_digest=request_digest,
        review_digest=digest,
        network=network,
        account=account,
        recipient=recipient,
        amount_atomic=amount_atomic,
        fee_atomic=fee_atomic,
        pages=full_pages,
        challenge=challenge,
        payload_snapshot=payload_snapshot,
        change_index=change_index,
    )


def _format_eth(wei: int) -> str:
    return f"{Decimal(wei) / Decimal(10**18):f} ETH"


def _evm_plan(payload: dict, request_digest: str, root) -> ReviewPlan:
    if not isinstance(payload, dict):
        raise ValueError("EVM request payload must be an object")
    recipient = payload.get("to")
    amount = payload.get("value")
    reviewed = review_evm_transaction(payload, recipient, amount)
    tx = reviewed["transaction"]
    account = evm_account(root).address

    pages = (
        ReviewPage(
            key="network_account",
            fields=(
                _field("network", "Ethereum Sepolia", "offline EVM policy"),
                _field("chain_id", reviewed["chain_id"], "payload.chainId"),
                _field("account", account, "vault m/44h/60h/0h/0/0"),
                _field("transaction_type", tx["type"], "payload.type"),
            ),
        ),
        ReviewPage(
            key="recipient",
            fields=(
                _field("recipient", reviewed["recipient"], "payload.to"),
            ),
        ),
        ReviewPage(
            key="amount_fee",
            fields=(
                _field("amount_wei", reviewed["value_wei"], "payload.value"),
                _field("amount_display", _format_eth(reviewed["value_wei"]), "computed from payload.value"),
                _field("nonce", tx["nonce"], "payload.nonce"),
                _field("gas_limit", tx["gas"], "payload.gas"),
                _field("max_priority_fee_per_gas", tx["maxPriorityFeePerGas"], "payload.maxPriorityFeePerGas"),
                _field("max_fee_per_gas", tx["maxFeePerGas"], "payload.maxFeePerGas"),
                _field("max_network_fee_wei", reviewed["max_fee_wei"], "payload.gas * payload.maxFeePerGas"),
                _field("max_total_spend_wei", reviewed["max_total_wei"], "payload.value + maximum network fee"),
            ),
        ),
        ReviewPage(
            key="policy",
            fields=(
                _field("operation", "native ETH transfer", "offline EVM signing policy"),
                _field("calldata", tx.get("data", "0x"), "payload.data"),
                _field("access_list", tx.get("accessList", []), "payload.accessList"),
                _field("contract_calls", "rejected", "offline EVM signing policy"),
            ),
        ),
    )
    return _with_review_digest(
        kind="evm",
        envelope_kind="evm-request",
        request_digest=request_digest,
        network="sepolia",
        account=account,
        recipient=reviewed["recipient"],
        amount_atomic=reviewed["value_wei"],
        fee_atomic=reviewed["max_fee_wei"],
        pages=pages,
        payload_snapshot=_canonical(payload).decode("ascii"),
    )


def _change_scripts(root) -> dict[bytes, int]:
    return {
        script.p2wpkh(btc_key(root, 1, index).key).data: index
        for index in range(_MAX_CHANGE_SCAN)
    }


def _btc_plan(payload: str, request_digest: str, root) -> ReviewPlan:
    if not isinstance(payload, str):
        raise ValueError("BTC request payload must be a base64 PSBT string")
    encoded = payload.strip()
    parsed = _read_psbt(encoded)
    change_by_script = _change_scripts(root)

    outputs: list[dict[str, Any]] = []
    recipients: list[dict[str, Any]] = []
    change: list[dict[str, Any]] = []
    for index, txout in enumerate(parsed.tx.vout):
        try:
            address = txout.script_pubkey.address(networks.NETWORKS["test"])
        except Exception as exc:
            raise ValueError("Unsupported Bitcoin output script") from exc
        if not address:
            raise ValueError("Bitcoin output is not a reviewable testnet address")
        change_index = change_by_script.get(txout.script_pubkey.data)
        item = {
            "index": index,
            "address": address,
            "value_sats": txout.value,
            "classification": "change" if change_index is not None else "recipient",
            "change_index": change_index,
        }
        outputs.append(item)
        (change if change_index is not None else recipients).append(item)

    if len(recipients) != 1:
        raise ValueError("Bitcoin review requires exactly one non-change recipient output")
    if len(change) > 1:
        raise ValueError("Bitcoin review supports at most one change output")

    recipient = recipients[0]["address"]
    amount = recipients[0]["value_sats"]
    change_index = change[0]["change_index"] if change else None
    try:
        fee = parsed.fee()
    except Exception as exc:
        raise ValueError("PSBT fee cannot be determined from offline UTXO data") from exc
    if type(fee) is not int or fee < 0:
        raise ValueError("Invalid Bitcoin transaction fee")

    reviewed = review_btc_psbt(
        root,
        encoded,
        recipient,
        amount,
        fee,
        change_index=change_index,
    )

    inputs: list[dict[str, Any]] = []
    for index, inp in enumerate(parsed.inputs):
        vin = parsed.tx.vin[index]
        if inp.witness_utxo is None:
            raise ValueError("Bitcoin input lacks reviewable witness UTXO data")
        derivations = []
        for origin in inp.bip32_derivations.values():
            derivations.append("/".join(str(component) for component in origin.derivation))
        inputs.append(
            {
                "index": index,
                "outpoint": f"{vin.txid.hex()}:{vin.vout}",
                "value_sats": inp.witness_utxo.value,
                "derivation": ",".join(derivations) if derivations else "validated wallet input",
            }
        )

    public = watch_only(root, count=1)["bitcoin"]
    account = public["account_tpub"]
    input_total = sum(item["value_sats"] for item in inputs)
    output_total = sum(item["value_sats"] for item in outputs)

    input_fields: list[ReviewField] = []
    for item in inputs:
        input_fields.extend(
            (
                _field(f"input_{item['index']}_outpoint", item["outpoint"], f"PSBT.tx.vin[{item['index']}]"),
                _field(f"input_{item['index']}_value_sats", item["value_sats"], f"PSBT.inputs[{item['index']}].witness_utxo"),
                _field(f"input_{item['index']}_derivation", item["derivation"], f"PSBT.inputs[{item['index']}].bip32_derivations"),
            )
        )

    output_fields: list[ReviewField] = []
    for item in outputs:
        source = f"PSBT.tx.vout[{item['index']}]"
        output_fields.extend(
            (
                _field(f"output_{item['index']}_role", item["classification"], source),
                _field(f"output_{item['index']}_address", item["address"], source),
                _field(f"output_{item['index']}_value_sats", item["value_sats"], source),
            )
        )
        if item["change_index"] is not None:
            output_fields.append(
                _field(f"output_{item['index']}_change_index", item["change_index"], "vault BIP84 change branch match")
            )

    pages = (
        ReviewPage(
            key="network_account",
            fields=(
                _field("network", "Bitcoin testnet", "offline BTC signing policy"),
                _field("account", account, "vault m/84h/1h/0h public account"),
                _field("input_count", reviewed["input_count"], "validated PSBT inputs"),
            ),
        ),
        ReviewPage(key="inputs", fields=tuple(input_fields)),
        ReviewPage(key="outputs", fields=tuple(output_fields)),
        ReviewPage(
            key="amount_fee",
            fields=(
                _field("recipient", reviewed["recipient"], "validated non-change PSBT output"),
                _field("amount_sats", reviewed["amount_sats"], "validated recipient PSBT output"),
                _field("change_sats", reviewed["change_sats"], "validated wallet change output"),
                _field("input_total_sats", input_total, "sum(validated input UTXOs)"),
                _field("output_total_sats", output_total, "sum(PSBT outputs)"),
                _field("fee_sats", reviewed["fee_sats"], "input total - output total"),
            ),
        ),
    )
    return _with_review_digest(
        kind="btc",
        envelope_kind="btc-request",
        request_digest=request_digest,
        network="bitcoin-testnet",
        account=account,
        recipient=reviewed["recipient"],
        amount_atomic=reviewed["amount_sats"],
        fee_atomic=reviewed["fee_sats"],
        pages=pages,
        payload_snapshot=encoded,
        change_index=change_index,
    )


def build_review_plan(envelope: dict, root, expected_kind: str | None = None) -> ReviewPlan:
    payload = verify(envelope, expected_kind)
    kind = envelope["kind"]
    request_digest = envelope["sha256"]
    if kind == "evm-request":
        return _evm_plan(payload, request_digest, root)
    if kind == "btc-request":
        return _btc_plan(payload, request_digest, root)
    raise ValueError("Only unsigned BTC/EVM requests can enter transaction review")


def load_review_file(path: Path, root, expected_kind: str | None = None) -> ReviewPlan:
    """Read an untrusted USB file once, then review the in-memory verified payload."""
    return build_review_plan(read_envelope(path, expected_kind), root, expected_kind)


def load_review_qr(text: str, root, expected_kind: str | None = None) -> ReviewPlan:
    """Apply the same canonical #11 validation to bounded QR-decoded JSON."""
    if type(text) is not str:
        raise ValueError("QR exchange must be text")
    try:
        if len(text.encode("utf-8")) > MAX_BYTES + 8192:
            raise ValueError("QR exchange too large")
        envelope = json.loads(
            text, object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError("Invalid QR numeric constant: " + value)))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid QR JSON") from exc
    return build_review_plan(envelope, root, expected_kind)


def _fresh_plan(plan: ReviewPlan, root) -> ReviewPlan:
    if plan.kind == "evm":
        payload = json.loads(plan.payload_snapshot)
        return _evm_plan(payload, plan.request_digest, root)
    return _btc_plan(plan.payload_snapshot, plan.request_digest, root)


def review_policy_decision(plan: ReviewPlan, root, profile):
    """Check the exact reviewed intent against the independently loaded offline policy."""
    fresh = _fresh_plan(plan, root)
    if fresh.review_digest != plan.review_digest or fresh.account != plan.account:
        raise ValueError("Reviewed transaction or wallet account changed; confirmation reset required")
    if profile is None:
        raise ValueError("Encrypted offline policy is mandatory before signing")
    if plan.kind == "evm":
        payload = json.loads(plan.payload_snapshot)
        review = review_evm_transaction(payload, plan.recipient, plan.amount_atomic)
    else:
        review = review_btc_psbt(
            root, plan.payload_snapshot, plan.recipient,
            plan.amount_atomic, plan.fee_atomic, plan.change_index)
    return enforce_review_policy(profile, root, review, kind=plan.kind)[1]


def sign_review_plan(plan: ReviewPlan, root, profile) -> dict:
    """Re-review, enforce the wallet-bound policy, and preserve signed-v1 schema."""
    review_policy_decision(plan, root, profile)
    if plan.kind == "evm":
        payload = json.loads(plan.payload_snapshot)
        return sign_evm(root, payload, plan.recipient, plan.amount_atomic)
    return sign_btc_psbt(
        root, plan.payload_snapshot, plan.recipient,
        plan.amount_atomic, plan.fee_atomic, plan.change_index)


class ReviewSession:
    """Fail-closed confirmation state for exactly one reviewed transaction."""

    def __init__(self, plan: ReviewPlan):
        self.plan = plan
        self._acknowledged: set[int] = set()
        self._confirmation = ""
        self._canceled = False
        self._signed_envelope: dict | None = None

    @property
    def acknowledged_pages(self) -> frozenset[int]:
        return frozenset(self._acknowledged)

    @property
    def signed(self) -> bool:
        return self._signed_envelope is not None

    @property
    def can_sign(self) -> bool:
        return (
            not self._canceled
            and not self.signed
            and self._acknowledged == set(range(len(self.plan.pages)))
            and self._confirmation == self.plan.challenge
        )

    def replace_plan(self, plan: ReviewPlan) -> None:
        self.plan = plan
        self._acknowledged.clear()
        self._confirmation = ""
        self._canceled = False
        self._signed_envelope = None

    def acknowledge(self, page_index: int, review_digest: str) -> None:
        if self._canceled or self.signed:
            raise ValueError("Review is no longer active")
        if review_digest != self.plan.review_digest:
            self._acknowledged.clear()
            self._confirmation = ""
            raise ValueError("Review digest changed; all confirmations were reset")
        if not 0 <= page_index < len(self.plan.pages):
            raise ValueError("Invalid review page")
        self._acknowledged.add(page_index)

    def revoke(self, page_index: int) -> None:
        self._acknowledged.discard(page_index)
        self._confirmation = ""

    def set_confirmation(self, value: str, review_digest: str) -> None:
        if review_digest != self.plan.review_digest:
            self._acknowledged.clear()
            self._confirmation = ""
            raise ValueError("Review digest changed; all confirmations were reset")
        self._confirmation = value

    def clear_confirmation(self) -> None:
        self._confirmation = ""

    def cancel(self) -> None:
        self._canceled = True
        self._acknowledged.clear()
        self._confirmation = ""

    def sign(self, root, profile, *, extra_confirmation: str | None = None) -> dict:
        if not self.can_sign:
            raise ValueError("Every review page and the final challenge must be explicitly confirmed")
        decision = review_policy_decision(self.plan, root, profile)
        if decision.status == "REQUIRE_EXTRA_CONFIRMATION" and extra_confirmation != "UNVERIFIED RECIPIENT":
            raise ValueError("Unknown recipient requires an additional typed confirmation")
        payload = sign_review_plan(self.plan, root, profile)
        envelope = package(self.plan.signed_kind, payload)
        verify(envelope, self.plan.signed_kind)
        self._signed_envelope = envelope
        self._acknowledged.clear()
        self._confirmation = ""
        return envelope

    def signed_envelope_text(self) -> str:
        if self._signed_envelope is None:
            raise ValueError("Transaction has not been signed")
        return json.dumps(self._signed_envelope, ensure_ascii=True, sort_keys=True, indent=2) + "\n"

    def export_signed(self, path: Path) -> None:
        if self._signed_envelope is None:
            raise ValueError("Transaction has not been signed")
        verify(self._signed_envelope, self.plan.signed_kind)
        save_vault(path, self._signed_envelope)


def build_erc20_review_pages(payload: dict, root, offline_profile: dict) -> tuple[tuple[ReviewPage, ...], object]:
    """Existing GUI ReviewPage abstraction; never authorizes a signature."""
    from .policy import decide_erc20
    review, decision = decide_erc20(offline_profile, root, payload)
    if decision.status == "DENY":
        return (ReviewPage("policy", (_field("decision", "DENY", "offline contract policy"),
                                      _field("reason", "; ".join(decision.reasons), "offline contract policy"))),), decision
    operation = review["method"]
    party_field = "recipient" if operation == "transfer" else "spender"
    quantity_field = "amount" if operation == "transfer" else "allowance"
    pages = (
        ReviewPage("network_account", (
            _field("network", "Ethereum Sepolia", "offline EVM policy"),
            _field("chain_id", review["chain_id"], "raw transaction"),
            _field("account", evm_account(root).address, "offline wallet"))),
        ReviewPage("contract", (
            _field("contract", review["contract"], "offline contract allowlist"),
            _field("method", operation, "strict 4-byte selector"),
            _field(party_field, review[party_field], "decoded calldata"),
            _field(quantity_field + "_atomic", review[quantity_field], "decoded uint256, no untrusted decimals"),
            _field("revoke", operation == "approve" and review["allowance"] == 0, "decoded allowance"))),
        ReviewPage("fees", (
            _field("nonce", review["nonce"], "raw transaction"),
            _field("gas", review["gas"], "raw transaction"),
            _field("max_fee_per_gas", review["max_fee_per_gas"], "raw transaction"),
            _field("max_priority_fee_per_gas", review["max_priority_fee_per_gas"], "raw transaction"),
            _field("maximum_fee_wei", review["max_fee_wei"], "computed from transaction"))),
        ReviewPage("policy", (
            _field("decision", decision.status, "encrypted offline contract policy"),
            _field("reason", "; ".join(decision.reasons), "offline contract policy"),
            _field("signing_enabled", False, "runtime safety gate"))),
    )
    return pages, decision


def build_eip712_review_pages(typed_data: dict, *, trusted_approval: dict) -> tuple[ReviewPage, ...]:
    """Explicitly review preverified typed-data; no EIP-712 signature path exists.

    Caller must obtain trusted_approval from authenticated offline state, never
    from an exchange envelope, RPC, or online-decoded JSON.
    """
    from .evm_eip712 import review_eip712_intent
    reviewed = review_eip712_intent(typed_data, **trusted_approval)
    operation = reviewed["primary_type"]
    party_field = "recipient" if operation == "WalletTransferIntent" else "spender"
    qty_field = "amount" if operation == "WalletTransferIntent" else "allowance"
    return (
        ReviewPage("typed_domain", (
            _field("network", "Ethereum Sepolia", "offline policy"),
            _field("chain_id", reviewed["chain_id"], "EIP-712 domain"),
            _field("verifying_contract", reviewed["domain"]["verifyingContract"], "EIP-712 domain"),
            _field("owner", reviewed["owner"], "EIP-712 message"),
            _field("schema", operation, "strict schema allowlist"))),
        ReviewPage("typed_intent", (
            _field(party_field, reviewed[party_field], "EIP-712 message"),
            _field(qty_field + "_atomic", reviewed[qty_field], "EIP-712 uint256"),
            _field("nonce", reviewed["nonce"], "EIP-712 message"),
            _field("deadline", reviewed["deadline"], "EIP-712 message"),
            _field("signing_digest", reviewed["signing_digest"], "EIP-712 canonical hash"),
            _field("signing_enabled", False, "no trusted nonce consumption/deployed verifier"))),
    )
