"""Offline CLI, paper recovery and integrity-checked removable-media exchange.

SHA-256 detects accidental changes; it does NOT authenticate a hostile USB.
"""
import argparse
import getpass
import hashlib
import json
import sys
from pathlib import Path
from dataclasses import asdict

from .btc import review_btc_psbt, sign_btc_psbt
from .evm import review_evm_transaction, sign_evm
from .exchange import (read as read_exchange, read_envelope, read_bounded,
                       _unique_object, write as write_exchange, MAX_BYTES)
from .keys import root_from_mnemonic, watch_only
from .policy import (
    default_profile, load_profile, load_policy_snapshot, read_policy_snapshot,
    save_profile, set_limit, register_verified_address, normalize_address,
    enforce_review_policy, _bounded_policy_read,
)
from .recovery import rehearsal, restore_paper_wallet
from .vault import encrypt_mnemonic, load_vault, new_mnemonic, save_vault


def _password(confirm=False):
    first = getpass.getpass("Vault encryption passphrase: ")
    if confirm and first != getpass.getpass("Repeat passphrase: "):
        raise ValueError("Passphrases do not match")
    return first


def _wallet_root(args):
    mnemonic = load_vault(args.vault, _password())
    return root_from_mnemonic(mnemonic, getpass.getpass("Optional BIP39 passphrase (Enter if none): "))


def _approve(challenge):
    if input(f"OFFLINE: independently verify details above; type '{challenge}': ").strip() != challenge:
        raise ValueError("Signing canceled: independent confirmation mismatch")


def _display(review):
    safe = {key: value for key, value in review.items() if key not in ("psbt", "transaction")}
    print(json.dumps(safe, indent=2))
    return safe


def _read_legacy_evm(path):
    """One bounded regular-file read; reject duplicate keys, invalid UTF-8 and NaN."""
    try:
        return json.loads(read_bounded(path, limit=MAX_BYTES).decode("utf-8"),
                          object_pairs_hook=_unique_object,
                          parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"Invalid JSON number {x}")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid legacy EVM transaction JSON") from exc


def _read_legacy_btc(path):
    """Read only bounded textual PSBT from an untrusted transfer USB."""
    try:
        return read_bounded(path, limit=MAX_BYTES).decode("ascii").strip()
    except UnicodeError as exc:
        raise ValueError("Invalid legacy PSBT encoding") from exc


def _assert_offline_flags(args):
    if not args.offline_ack or not args.i_have_paper_backup:
        raise ValueError("Require --offline-ack and --i-have-paper-backup on trusted offline host")



def _print_anchor_for_independent_record(path: Path) -> None:
    digest = hashlib.sha256(_bounded_policy_read(path)).hexdigest()
    print(f"POLICY SHA256 (record independently; old copies must never be trusted): {digest}")


def _signing_policy_snapshot(args) -> bytes:
    """Fail closed on absent/stale externally recorded policy before vault unlock."""
    expected = args.vault.with_name(args.vault.name + ".policy")
    if args.policy is not None and args.policy.resolve() != expected.resolve():
        raise ValueError("Signing policy override must match <vault>.policy")
    return read_policy_snapshot(expected, args.expected_policy_sha256)


def _manage_policy(args) -> int:
    expected = args.vault.with_name(args.vault.name + ".policy")
    if args.file.resolve() != expected.resolve() or args.file.is_symlink():
        raise ValueError("Offline policy file must be <vault>.policy, without symlinks")
    if args.action == "init" and args.file.exists():
        raise ValueError("Encrypted offline policy already exists")
    # The wallet and policy passphrase must be entered on the offline host.
    root = _wallet_root(args)
    password = _password()
    if args.action == "init":
        profile = default_profile(root)
        _approve("CREATE OFFLINE POLICY")
        save_profile(args.file, profile, root, password)
    else:
        profile = load_profile(args.file, root, password)
        if args.action == "set-limit":
            if args.field is None or args.value is None:
                raise ValueError("--field and --value are required")
            profile = set_limit(profile, root, args.field, args.value)
            print(f"New limit {args.field}: {args.value}")
            _approve("CHANGE OFFLINE POLICY")
            save_profile(args.file, profile, root, password, replace=True)
        elif args.action == "verify-address":
            if not (args.network and args.address and args.label):
                raise ValueError("--network, --address and --label are required")
            canonical = normalize_address(args.network, args.address)
            print(f"Check full {args.network} address offline: {canonical}; label: {args.label}")
            _approve("VERIFY FULL ADDRESS")
            if input("Re-enter full verified address: ").strip() != canonical:
                raise ValueError("Full address did not match")
            profile = register_verified_address(profile, root, args.network, canonical, args.label)
            save_profile(args.file, profile, root, password, replace=True)
    print(json.dumps(profile, indent=2, ensure_ascii=False))
    _print_anchor_for_independent_record(args.file)
    return 0


def _display_policy_and_confirm(root, review: dict, profile: dict, *, kind: str) -> None:
    """Shared policy decision; ordinary signing confirmation is handled afterward."""
    intent, decision = enforce_review_policy(profile, root, review, kind=kind)
    _display(review)
    print(json.dumps({"intent": asdict(intent), "policy_decision": asdict(decision)}, indent=2))
    if decision.status == "REQUIRE_EXTRA_CONFIRMATION":
        # The full recipient is printed in the review; do not trust online labels.
        _approve("UNVERIFIED RECIPIENT")

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="usb-cold-wallet",
        description="EXPERIMENTAL TESTNET-only BTC + EVM offline signer (NOT audited)",
    )
    parser.add_argument("--vault", type=Path, default=Path("wallet.vault"))
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create encrypted BIP39 wallet on a trusted offline host")
    init.add_argument("--offline-ack", action="store_true")
    init.add_argument("--i-have-paper-backup", action="store_true")

    recovery = sub.add_parser("recover", help="Restore from PAPER only on offline host, never overwrite")
    recovery.add_argument("--offline-ack", action="store_true")
    recovery.add_argument("--i-have-paper-backup", action="store_true")
    recovery.add_argument("--expected-btc", required=True, help="First testnet receive address copied independently from paper")
    recovery.add_argument("--expected-evm", required=True, help="Sepolia address copied independently from paper")

    sub.add_parser("rehearse-recovery", help="Destroy and restore disposable PUBLIC test-only vault")

    addresses = sub.add_parser("addresses", help="Display public testnet watch-only data")
    addresses.add_argument("--count", type=int, default=3)
    watch = sub.add_parser("export-watch-only", help="Create integrity-checked PUBLIC export")
    watch.add_argument("--count", type=int, default=3)
    watch.add_argument("--out", type=Path, required=True)

    pack = sub.add_parser("pack-request", help="On online host: wrap UNSIGNED request with SHA-256")
    pack.add_argument("--kind", choices=["btc-request", "evm-request"], required=True)
    pack.add_argument("--input", type=Path, required=True)
    pack.add_argument("--out", type=Path, required=True)
    inspect = sub.add_parser("inspect-transfer", help="Validate envelope integrity and show PUBLIC metadata")
    inspect.add_argument("--input", type=Path, required=True)
    view = sub.add_parser("show-watch-only", help="Read and display verified PUBLIC watch-only export, no vault")
    view.add_argument("--input", type=Path, required=True)

    evm = sub.add_parser("sign-evm", help="Review and sign Sepolia native ETH transfer")
    evm_source = evm.add_mutually_exclusive_group(required=True)
    evm_source.add_argument("--tx", type=Path, help="Legacy unsigned EVM JSON")
    evm_source.add_argument("--request", type=Path, help="Verified exchange envelope")
    evm.add_argument("--to", required=True, help="Independently verified recipient")
    evm.add_argument("--wei", required=True, type=int, help="Independently verified value")
    evm.add_argument("--out", type=Path, required=True)
    evm.add_argument("--policy", type=Path, help="Must equal <vault>.policy")
    evm.add_argument("--expected-policy-sha256", required=True,
                     help="Required: independently recorded current encrypted policy SHA-256")

    btc = sub.add_parser("sign-btc", help="Review and sign Bitcoin testnet P2WPKH PSBT")
    btc_source = btc.add_mutually_exclusive_group(required=True)
    btc_source.add_argument("--psbt", type=Path, help="Legacy unsigned PSBT base64")
    btc_source.add_argument("--request", type=Path, help="Verified exchange envelope")
    btc.add_argument("--to", required=True, help="Independently verified testnet recipient")
    btc.add_argument("--sats", type=int, required=True)
    btc.add_argument("--max-fee-sats", type=int, required=True)
    btc.add_argument("--change-index", type=int, default=None)
    btc.add_argument("--out", type=Path, required=True)
    btc.add_argument("--policy", type=Path, help="Must equal <vault>.policy")
    btc.add_argument("--expected-policy-sha256", required=True,
                     help="Required: independently recorded current encrypted policy SHA-256")

    policy = sub.add_parser("policy", help="Manage encrypted offline wallet policy and verified addresses")
    policy.add_argument("--file", type=Path, required=True)
    policy.add_argument("--action", choices=["init", "show", "set-limit", "verify-address"], required=True)
    policy.add_argument("--field", choices=["evm_max_value_wei", "evm_max_fee_wei",
                                          "btc_max_fee_sats", "btc_max_fee_rate_sat_vb"])
    policy.add_argument("--value", type=int)
    policy.add_argument("--network", choices=["sepolia", "bitcoin-testnet"])
    policy.add_argument("--address")
    policy.add_argument("--label")

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            _assert_offline_flags(args)
            if args.vault.exists():
                raise ValueError("Vault exists; refusing to overwrite")
            mnemonic = new_mnemonic()
            print("\nSECRET: write the following mnemonic on PAPER, never photograph it.\n")
            print(mnemonic)
            print("\nNever store the mnemonic on your transport USB or online computer.")
            if input("Enter LAST mnemonic word to confirm paper backup: ").strip() != mnemonic.split()[-1]:
                raise ValueError("Mnemonic not confirmed; no vault written")
            save_vault(args.vault, encrypt_mnemonic(mnemonic, _password(confirm=True)))
            print(f"Encrypted vault created: {args.vault}")
            return 0

        if args.command == "recover":
            _assert_offline_flags(args)
            if args.vault.exists():
                raise ValueError("Vault exists; recovery refuses to overwrite")
            print("ENTER PAPER WORDS ONLY ON A TRUSTED, PHYSICALLY OFFLINE HOST.")
            mnemonic = getpass.getpass("Paper BIP39 words (hidden input): ")
            bip39_passphrase = getpass.getpass("Paper BIP39 passphrase (Enter if none): ")
            _approve("RESTORE TESTNET WALLET")
            info = restore_paper_wallet(args.vault, mnemonic, bip39_passphrase,
                                        args.expected_btc, args.expected_evm,
                                        _password(confirm=True))
            print("Restored vault after BOTH independently recorded addresses matched.")
            print(json.dumps(info, indent=2))
            return 0

        if args.command == "rehearse-recovery":
            print("PUBLIC KNOWN-COMPROMISED TEST VECTOR ONLY. Do NOT fund these addresses.")
            print(json.dumps(rehearsal("public-test-only-rehearsal-password"), indent=2))
            return 0

        if args.command == "pack-request":
            if args.kind == "btc-request":
                raw = read_bounded(args.input).decode("utf-8").strip()
            else:
                raw = json.loads(read_bounded(args.input).decode("utf-8"),
                                 object_pairs_hook=_unique_object)
            write_exchange(args.out, args.kind, raw)
            print(f"Created {args.kind} integrity envelope: {args.out} (NOT authenticated)")
            return 0

        if args.command == "inspect-transfer":
            # Load once: avoid a second unbounded read after validating integrity.
            envelope = read_envelope(args.input)
            print(json.dumps({"kind": envelope["kind"], "network": envelope["network"],
                              "sha256": envelope["sha256"], "payload_type": type(envelope["payload"]).__name__,
                              "integrity_only_not_authenticated": True,
                              "standalone_check_does_not_authorize_broadcast": True,
                              "btc_change_not_bound_to_approved_request": envelope["kind"] == "btc-signed"}, indent=2))
            return 0

        if args.command == "show-watch-only":
            public = read_exchange(args.input, "watch-only")
            print("PUBLIC ONLY / UNTRUSTED USB / BITCOIN TESTNET + SEPOLIA")
            print("WARNING: checksum is NOT authentication. Independently verify every receiving address.")
            print(json.dumps(public, indent=2, ensure_ascii=True))
            return 0

        if args.command == "policy":
            return _manage_policy(args)

        print("WARNING: testnet prototype. SHA-256 is NOT a trusted authorization.", file=sys.stderr)
        if args.command in ("addresses", "export-watch-only"):
            root = _wallet_root(args)
            info = watch_only(root, count=args.count)
            print("NETWORKS: BITCOIN TESTNET + ETHEREUM SEPOLIA (chainId 11155111)")
            print(json.dumps(info, indent=2))
            if args.command == "export-watch-only":
                _approve("EXPORT PUBLIC WATCH ONLY")
                write_exchange(args.out, "watch-only", info)
                print(f"PUBLIC watch-only envelope written to {args.out}")
        elif args.command == "sign-evm":
            raw = read_exchange(args.request, "evm-request") if args.request else _read_legacy_evm(args.tx)
            reviewed = review_evm_transaction(raw, args.to, args.wei)
            snapshot = _signing_policy_snapshot(args)
            root = _wallet_root(args)
            profile = load_policy_snapshot(snapshot, root, _password())
            print("NETWORK: ETHEREUM SEPOLIA (chainId 11155111) — NOT MAINNET")
            _display_policy_and_confirm(root, reviewed, profile, kind="evm")
            _approve(f"SEPOLIA {reviewed['recipient'][-8:]} {reviewed['value_wei']}")
            result = sign_evm(root, raw, args.to, args.wei)
            if args.request:
                write_exchange(args.out, "evm-signed", result)
            else:
                save_vault(args.out, result)
            print(f"Signed transfer saved: {args.out}")
        elif args.command == "sign-btc":
            encoded = read_exchange(args.request, "btc-request") if args.request else _read_legacy_btc(args.psbt)
            from .btc import _read_psbt
            _read_psbt(encoded)  # reject malicious PSBT framing before vault unlock
            snapshot = _signing_policy_snapshot(args)
            root = _wallet_root(args)
            reviewed = review_btc_psbt(root, encoded, args.to, args.sats,
                                       args.max_fee_sats, args.change_index)
            profile = load_policy_snapshot(snapshot, root, _password())
            print("NETWORK: BITCOIN TESTNET — NOT MAINNET")
            _display_policy_and_confirm(root, reviewed, profile, kind="btc")
            _approve(f"BTC TESTNET {reviewed['recipient'][-8:]} {reviewed['amount_sats']} {reviewed['fee_sats']}")
            result = sign_btc_psbt(root, encoded, args.to, args.sats, args.max_fee_sats, args.change_index)
            if args.request:
                write_exchange(args.out, "btc-signed", result)
            else:
                save_vault(args.out, result)
            print(f"Signed transfer saved: {args.out}")
        return 0
    except (ValueError, OSError, KeyError, TypeError, OverflowError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
