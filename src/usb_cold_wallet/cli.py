"""Offline-only interactive CLI. No RPC and no broadcast code."""
import argparse
import getpass
import json
import os
import stat
import sys
from pathlib import Path

from .btc import _read_psbt, review_btc_psbt, sign_btc_psbt
from .evm import review_evm_transaction, sign_evm
from .keys import root_from_mnemonic, watch_only
from .policy import (default_profile, load_profile, save_profile, set_limit,
                     register_verified_address, evm_intent, btc_intent, decide)
from dataclasses import asdict
from .vault import encrypt_mnemonic, load_vault, new_mnemonic, save_vault


def _password(confirm: bool = False) -> str:
    first = getpass.getpass("Vault encryption passphrase: ")
    if confirm and first != getpass.getpass("Repeat passphrase: "):
        raise ValueError("Passphrases do not match")
    return first


def _wallet_root(args):
    mnemonic = load_vault(args.vault, _password())
    return root_from_mnemonic(mnemonic, getpass.getpass("Optional BIP39 passphrase (Enter if none): "))


MAX_TRANSFER_BYTES = 200_000


def _read_unsigned_before_unlock(path: Path) -> bytes:
    """Read untrusted USB request once, without following links or blocking on FIFOs."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Unsigned request must be a regular file")
        raw = os.read(fd, MAX_TRANSFER_BYTES + 1)
        if len(raw) > MAX_TRANSFER_BYTES:
            raise ValueError("Unsigned request exceeds size limit")
        return raw
    finally:
        os.close(fd)


def _strict_unsigned_json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate unsigned JSON key")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON constant")))


def _approve(phrase: str) -> None:
    if input(f"Type '{phrase}' on the OFFLINE COMPUTER to proceed: ").strip() != phrase:
        raise ValueError("Signing canceled")


def _write_signed(path: Path, result: dict) -> None:
    save_vault(path, result)
    print(f"Signed output written to {path} (safe to transfer for broadcast).")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="usb-cold-wallet",
        description="EXPERIMENTAL TESTNET-only BTC PSBT + EVM Sepolia offline signer",
    )
    parser.add_argument("--vault", type=Path, default=Path("wallet.vault"), help="Encrypted wallet file on offline USB")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create a new encrypted BIP39 wallet OFFLINE")
    init.add_argument("--offline-ack", action="store_true", help="Affirm the machine is physically offline")
    init.add_argument("--i-have-paper-backup", action="store_true", help="Affirm mnemonic is backed up outside USB")
    addresses = sub.add_parser("addresses", help="Show public testnet addresses and BTC account tpub")
    addresses.add_argument("--count", type=int, default=3)
    evm = sub.add_parser("sign-evm", help="Review and sign a Sepolia native ETH transfer")
    evm.add_argument("--tx", type=Path, required=True, help="Unsigned type-2 transaction JSON")
    evm.add_argument("--to", required=True, help="Independently verified recipient")
    evm.add_argument("--wei", required=True, type=int, help="Independently verified value in wei")
    evm.add_argument("--out", type=Path, required=True)
    evm.add_argument("--policy", type=Path, help="Must equal <vault>.policy; signing always requires encrypted policy")
    evm.add_argument("--expected-policy-sha256", help="Required: independent paper-verified SHA-256 of encrypted policy file")
    btc = sub.add_parser("sign-btc", help="Review and sign Bitcoin testnet BIP84 PSBT")
    btc.add_argument("--psbt", type=Path, required=True, help="Unsigned PSBT base64 file")
    btc.add_argument("--to", required=True, help="Independently verified recipient testnet address")
    btc.add_argument("--sats", type=int, required=True, help="Expected recipient satoshis")
    btc.add_argument("--max-fee-sats", type=int, required=True)
    btc.add_argument("--change-index", type=int, default=None, help="Expected BIP84 internal change index, if any")
    btc.add_argument("--out", type=Path, required=True)
    btc.add_argument("--policy", type=Path, help="Must equal <vault>.policy; signing always requires encrypted policy")
    btc.add_argument("--expected-policy-sha256", help="Optional independent paper-verified SHA-256 of encrypted policy file")
    policy = sub.add_parser("policy", help="Create/edit encrypted offline policy or verified address book")
    policy.add_argument("--file", type=Path, required=True, help="Local offline policy file, NEVER transfer USB")
    policy.add_argument("--action", choices=["init", "show", "set-limit", "verify-address"], required=True)
    policy.add_argument("--field", choices=["evm_max_value_wei", "evm_max_fee_wei", "btc_max_fee_sats", "btc_max_fee_rate_sat_vb"])
    policy.add_argument("--value", type=int)
    policy.add_argument("--network", choices=["sepolia", "bitcoin-testnet"])
    policy.add_argument("--address")
    policy.add_argument("--label")
    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            if not args.offline_ack or not args.i_have_paper_backup:
                raise ValueError("Pass --offline-ack and --i-have-paper-backup after arranging a trusted offline environment and paper backup")
            if args.vault.exists():
                raise ValueError("Vault already exists; refusing to overwrite")
            mnemonic = new_mnemonic()
            print("\nSECRET: write the following on paper, never photograph or paste online.\n")
            print(mnemonic)
            print("\nWARNING: Losing both your mnemonic and vault can permanently lose funds.")
            if input("Type the LAST mnemonic word to acknowledge your paper copy: ").strip() != mnemonic.split()[-1]:
                raise ValueError("Mnemonic not confirmed; vault was not written")
            data = encrypt_mnemonic(mnemonic, _password(confirm=True))
            save_vault(args.vault, data)
            print(f"Encrypted vault created: {args.vault}. No seed is saved in plaintext.")
            return 0

        print("WARNING: this is a testnet research prototype, not audited for real funds.", file=sys.stderr)
        # Reject malformed or blocking USB input before mnemonic or wallet_root enters RAM.
        unsigned_tx = None
        unsigned_psbt = None
        if args.command == "sign-evm":
            unsigned_tx = _strict_unsigned_json(_read_unsigned_before_unlock(args.tx))
            review_evm_transaction(unsigned_tx, args.to, args.wei)
        elif args.command == "sign-btc":
            unsigned_psbt = _read_unsigned_before_unlock(args.psbt).decode("ascii")
            _read_psbt(unsigned_psbt)
        root = _wallet_root(args)
        policy_path = getattr(args, "policy", None)
        if args.command in ("sign-evm", "sign-btc"):
            if (type(args.expected_policy_sha256) is not str
                    or len(args.expected_policy_sha256) != 64
                    or any(ch not in "0123456789abcdef" for ch in args.expected_policy_sha256)):
                raise ValueError("An independently verified policy SHA-256 anchor is mandatory for signing")
            mandatory_policy = args.vault.with_name(args.vault.name + ".policy")
            if policy_path is not None and policy_path.resolve() != mandatory_policy.resolve():
                raise ValueError("Policy override path forbidden; policy is always bound beside the vault")
            policy_path = mandatory_policy
        _policy_password = _password() if args.command == "policy" or (policy_path is not None and policy_path.exists()) else None
        if args.command == "policy":
            # A policy is local wallet state; never accept labels from a transfer payload.
            from .policy import normalize_address
            if args.file.resolve() != args.vault.with_name(args.vault.name + ".policy").resolve():
                raise ValueError("Policy path must be <vault>.policy beside the encrypted vault")
            if args.action == "init":
                if args.file.exists():
                    raise ValueError("Policy already exists")
                profile = default_profile(root)
                print("Default profile binds to this unlocked wallet; creation requires confirmation.")
                _approve("CREATE OFFLINE POLICY")
                save_profile(args.file, profile, root, _policy_password)
            else:
                profile = load_profile(args.file, root, _policy_password)
                if args.action == "set-limit":
                    if args.field is None or args.value is None:
                        raise ValueError("--field and --value required")
                    profile = set_limit(profile, root, args.field, args.value)
                    print(f"New limit {args.field}: {args.value}")
                    _approve("CHANGE OFFLINE POLICY")
                    save_profile(args.file, profile, root, _policy_password, replace=True)
                elif args.action == "verify-address":
                    if not all((args.network, args.address, args.label)):
                        raise ValueError("--network, --address and --label required")
                    canonical = normalize_address(args.network, args.address)
                    print(f"Verify full address on the OFFLINE screen, not from Online labels:\n{args.network}\n{canonical}\nLabel: {args.label}")
                    _approve("VERIFY FULL ADDRESS")
                    if input("Re-enter full verified address: ").strip() != canonical:
                        raise ValueError("Full address did not match")
                    profile = register_verified_address(profile, root, args.network, canonical, args.label)
                    save_profile(args.file, profile, root, _policy_password, replace=True)
                print(json.dumps(profile, indent=2, ensure_ascii=False))
        elif args.command == "addresses":
            print(json.dumps(watch_only(root, count=args.count), ensure_ascii=False, indent=2))
        elif args.command == "sign-evm":
            raw = unsigned_tx
            review = review_evm_transaction(raw, args.to, args.wei)
            profile = load_profile(policy_path, root, _policy_password, expected_sha256=args.expected_policy_sha256)
            intent = evm_intent(root, review)
            decision = decide(profile, root, intent)
            print(json.dumps({"intent": asdict(intent), "decision": asdict(decision)}, indent=2))
            if decision.status == "DENY":
                raise ValueError("Offline policy denied EVM transaction")
            if decision.status == "REQUIRE_EXTRA_CONFIRMATION":
                _approve("UNVERIFIED RECIPIENT")
            _approve("SIGN SEPOLIA")
            result = sign_evm(root, raw, args.to, args.wei)
            _write_signed(args.out, result)
        elif args.command == "sign-btc":
            encoded = unsigned_psbt
            review = review_btc_psbt(root, encoded, args.to, args.sats, args.max_fee_sats, args.change_index)
            profile = load_profile(policy_path, root, _policy_password, expected_sha256=args.expected_policy_sha256)
            intent = btc_intent(root, review)
            decision = decide(profile, root, intent)
            print(json.dumps({"intent": asdict(intent), "decision": asdict(decision),
                              "change_sats": review["change_sats"], "input_count": review["input_count"]}, indent=2))
            if decision.status == "DENY":
                raise ValueError("Offline policy denied Bitcoin transaction")
            if decision.status == "REQUIRE_EXTRA_CONFIRMATION":
                _approve("UNVERIFIED RECIPIENT")
            _approve("SIGN BITCOIN TESTNET")
            result = sign_btc_psbt(root, encoded, args.to, args.sats, args.max_fee_sats, args.change_index)
            _write_signed(args.out, result)
        return 0
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
