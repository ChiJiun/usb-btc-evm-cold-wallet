"""Testnet-only JSON side of an offline UR:BYTES QR bridge.

Never connects to RPC or broadcasts transactions. Render/scanning happens in
qr-transport/ browser bundle; signing occurs only on a trusted offline host.
"""
import argparse
import getpass
import json
import os
import stat
import sys
from pathlib import Path

from .btc import review_btc_psbt
from .evm import review_evm_transaction
from .keys import root_from_mnemonic
from .policy import (read_policy_snapshot, load_policy_snapshot,
                     enforce_review_policy)
from .qr_session import MAX_BYTES, _check, REQUEST_KEYS, RESPONSE_KEYS
from .qr_workflow import prepare_btc_qr, prepare_evm_qr, sign_offline, verify_evm_response, verify_btc_response
from .vault import load_vault, save_vault


def _unique_json(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON key")
        obj[key] = value
    return obj


def _read_bytes(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("QR import must be a regular file")
        data = os.read(fd, MAX_BYTES + 4097)
        if len(data) > MAX_BYTES + 4096:
            raise ValueError("QR import exceeds size cap")
    finally:
        os.close(fd)
    return data


def _read(path):
    return json.loads(_read_bytes(path).decode("utf-8"), object_pairs_hook=_unique_json,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON number")))


def _approve(challenge):
    typed = input(f"OFFLINE review: type '{challenge}' exactly: ")
    if typed.strip() != challenge:
        raise ValueError("QR signing cancelled")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="usb-cold-wallet-qr",
                                     description="Offline QR request/response JSON bridge (TESTNET ONLY)")
    sub = parser.add_subparsers(dest="command", required=True)
    evm = sub.add_parser("prepare-evm")
    evm.add_argument("--tx", type=Path, required=True)
    evm.add_argument("--account", required=True)
    evm.add_argument("--to", required=True)
    evm.add_argument("--wei", type=int, required=True)
    evm.add_argument("--out", type=Path, required=True)

    btc = sub.add_parser("prepare-btc")
    btc.add_argument("--psbt", type=Path, required=True)
    btc.add_argument("--fingerprint", required=True)
    btc.add_argument("--to", required=True)
    btc.add_argument("--sats", type=int, required=True)
    btc.add_argument("--max-fee-sats", type=int, required=True)
    btc.add_argument("--change-index", type=int)
    btc.add_argument("--out", type=Path, required=True)

    sign = sub.add_parser("offline-sign")
    sign.add_argument("--offline-ack", action="store_true", help="User asserts a trusted physically offline host")
    sign.add_argument("--vault", type=Path, required=True)
    sign.add_argument("--request", type=Path, required=True)
    sign.add_argument("--to", required=True, help="Recipient independently verified on offline device")
    sign.add_argument("--amount", type=int, required=True, help="Satoshis or wei, independently verified")
    sign.add_argument("--max-fee-sats", type=int)
    sign.add_argument("--change-index", type=int)
    sign.add_argument("--out", type=Path, required=True)
    sign.add_argument("--expected-policy-sha256", help="Independently stored current encrypted policy SHA-256")

    for command in ("verify-evm", "verify-btc"):
        check = sub.add_parser(command)
        check.add_argument("--request", type=Path, required=True)
        check.add_argument("--response", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "prepare-evm":
            req = prepare_evm_qr(_read(args.tx), args.account, args.to, args.wei)
            save_vault(args.out, req)
            print("Created UNSIGNED Sepolia request JSON. Display as UR:BYTES QR; not a signing authorization.")
        elif args.command == "prepare-btc":
            req = prepare_btc_qr(_read_bytes(args.psbt).decode("ascii").strip(),
                                 args.fingerprint, args.to, args.sats,
                                 args.max_fee_sats, args.change_index)
            save_vault(args.out, req)
            print("Created UNSIGNED Bitcoin testnet request JSON. Verify UTXOs offline before approving.")
        elif args.command == "offline-sign":
            if not args.offline_ack:
                raise ValueError("Require --offline-ack on physically disconnected trusted host")
            req = _read(args.request)
            _check(req, REQUEST_KEYS, "unsigned")
            # Refuse absent/rolled-back policy before bringing wallet keys into RAM.
            policy_path = args.vault.with_name(args.vault.name + ".policy")
            snapshot = read_policy_snapshot(policy_path, args.expected_policy_sha256)
            mnemonic = load_vault(args.vault, getpass.getpass("Vault encryption passphrase: "))
            bip39_pass = getpass.getpass("Optional BIP39 passphrase (Enter if none): ")
            root = root_from_mnemonic(mnemonic, bip39_pass)
            policy_password = getpass.getpass("Encrypted offline policy passphrase: ")
            profile = load_policy_snapshot(snapshot, root, policy_password)
            mnemonic = ""
            bip39_pass = ""
            policy_password = ""
            snapshot = b""
            print(f"NETWORK: {req['network'].upper()} (TESTNET ONLY)\n"
                  f"Recipient: {args.to}\nAmount (wei/sats): {args.amount}\n"
                  "CHECK THESE FROM A SEPARATE TRUSTED SOURCE, NOT THE UNTRUSTED QR.")
            if req["network"] == "sepolia":
                reviewed = review_evm_transaction(req["payload"]["transaction"], args.to, args.amount)
                print(f"Maximum gas fee (wei): {reviewed['max_fee_wei']}")
            else:
                reviewed = review_btc_psbt(root, req["payload"]["psbt"], args.to,
                                           args.amount, args.max_fee_sats, args.change_index)
                print(f"Bitcoin network fee (sats): {reviewed['fee_sats']}")
                print(f"Change output (sats): {reviewed['change_sats']}")
            kind = "evm" if req["network"] == "sepolia" else "btc"
            intent, decision = enforce_review_policy(profile, root, reviewed, kind=kind)
            print(f"OFFLINE POLICY: {decision.status}; {', '.join(decision.reasons)}")
            approved_extra = False
            if decision.status == "REQUIRE_EXTRA_CONFIRMATION":
                print(f"Unverified recipient: {intent.recipient}")
                _approve("UNVERIFIED RECIPIENT")
                approved_extra = True
            _approve(f"QR SIGN {req['network']} {args.to[-8:]} {args.amount}")
            result = sign_offline(root, req, recipient=args.to, amount=args.amount,
                                  max_fee_sats=args.max_fee_sats, change_index=args.change_index,
                                  policy_profile=profile,
                                  accept_unverified_recipient=approved_extra)
            save_vault(args.out, result)
            print("Signed response saved. Show ONLY signed data in QR; keep vault and mnemonic OFFLINE.")
        elif args.command in ("verify-evm", "verify-btc"):
            request, response = _read(args.request), _read(args.response)
            _check(request, REQUEST_KEYS, "unsigned")
            _check(response, RESPONSE_KEYS, "signed")
            if args.command == "verify-evm":
                verify_evm_response(request, response)
            else:
                verify_btc_response(request, response)
            print("Verified signed transaction against pending request binding; broadcast remains manual.")
        return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
