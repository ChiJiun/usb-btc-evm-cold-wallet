"""Offline-only interactive CLI. No RPC and no broadcast code."""
import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from .btc import review_btc_psbt, sign_btc_psbt
from .evm import review_evm_transaction, sign_evm
from .exchange import (
    _unique_object,
    read as read_exchange,
    read_bounded,
    write as write_exchange,
)
from .keys import root_from_mnemonic, watch_only
from .vault import encrypt_mnemonic, load_vault, new_mnemonic, save_vault


def _password(confirm: bool = False) -> str:
    first = getpass.getpass("Vault encryption passphrase: ")
    if confirm and first != getpass.getpass("Repeat passphrase: "):
        raise ValueError("Passphrases do not match")
    return first


def _wallet_root(args):
    mnemonic = load_vault(args.vault, _password())
    return root_from_mnemonic(mnemonic, getpass.getpass("Optional BIP39 passphrase (Enter if none): "))


def _approve(phrase: str) -> None:
    if input(f"Type '{phrase}' on the OFFLINE COMPUTER to proceed: ").strip() != phrase:
        raise ValueError("Signing canceled")


def _write_signed(path: Path, result: dict) -> None:
    save_vault(path, result)
    print(f"Signed output written to {path} (safe to transfer for broadcast).")


def _read_legacy_evm(path: Path) -> dict:
    raw = read_bounded(path)
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("Non-finite JSON number")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid legacy EVM JSON") from exc


def _read_legacy_psbt(path: Path) -> str:
    raw = read_bounded(path)
    try:
        return raw.decode("ascii").strip()
    except UnicodeError as exc:
        raise ValueError("Legacy PSBT must be ASCII base64") from exc


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
    evm_source = evm.add_mutually_exclusive_group(required=True)
    evm_source.add_argument("--tx", type=Path, help="Legacy unsigned type-2 transaction JSON")
    evm_source.add_argument("--request", type=Path, help="Verified exchange envelope")
    evm.add_argument("--to", required=True, help="Independently verified recipient")
    evm.add_argument("--wei", required=True, type=int, help="Independently verified value in wei")
    evm.add_argument("--out", type=Path, required=True)
    btc = sub.add_parser("sign-btc", help="Review and sign Bitcoin testnet BIP84 PSBT")
    btc_source = btc.add_mutually_exclusive_group(required=True)
    btc_source.add_argument("--psbt", type=Path, help="Legacy unsigned PSBT base64 file")
    btc_source.add_argument("--request", type=Path, help="Verified exchange envelope")
    btc.add_argument("--to", required=True, help="Independently verified recipient testnet address")
    btc.add_argument("--sats", type=int, required=True, help="Expected recipient satoshis")
    btc.add_argument("--max-fee-sats", type=int, required=True)
    btc.add_argument("--change-index", type=int, default=None, help="Expected BIP84 internal change index, if any")
    btc.add_argument("--out", type=Path, required=True)
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
        root = _wallet_root(args)
        if args.command == "addresses":
            print(json.dumps(watch_only(root, count=args.count), ensure_ascii=False, indent=2))
        elif args.command == "sign-evm":
            raw = (
                read_exchange(args.request, "evm-request")
                if args.request
                else _read_legacy_evm(args.tx)
            )
            review = review_evm_transaction(raw, args.to, args.wei)
            print(json.dumps({key: value for key, value in review.items() if key != "transaction"}, indent=2))
            _approve("SIGN SEPOLIA")
            result = sign_evm(root, raw, args.to, args.wei)
            if args.request:
                write_exchange(args.out, "evm-signed", result)
                print(f"Signed exchange envelope written to {args.out}.")
            else:
                _write_signed(args.out, result)
        elif args.command == "sign-btc":
            encoded = (
                read_exchange(args.request, "btc-request")
                if args.request
                else _read_legacy_psbt(args.psbt)
            )
            review = review_btc_psbt(root, encoded, args.to, args.sats, args.max_fee_sats, args.change_index)
            print(json.dumps({key: value for key, value in review.items() if key != "psbt"}, indent=2))
            _approve("SIGN BITCOIN TESTNET")
            result = sign_btc_psbt(root, encoded, args.to, args.sats, args.max_fee_sats, args.change_index)
            if args.request:
                write_exchange(args.out, "btc-signed", result)
                print(f"Signed exchange envelope written to {args.out}.")
            else:
                _write_signed(args.out, result)
        return 0
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
