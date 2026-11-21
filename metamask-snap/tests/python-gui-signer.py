"""Public, compromised test mnemonic only: production Snap → Python GUI adapter → Snap."""

import json
import sys

from usb_cold_wallet.gui_qr_bridge import parse_qr_input, bind_qr_to_review, signed_qr_text
from usb_cold_wallet.keys import evm_account, root_from_mnemonic
from usb_cold_wallet.policy import default_profile
from usb_cold_wallet.review import ReviewSession, build_review_plan

PUBLIC_MNEMONIC = "abandon " * 11 + "about"


def main():
    root = root_from_mnemonic(PUBLIC_MNEMONIC)
    if sys.argv[1:] == ["address"]:
        print(evm_account(root).address)
        return

    if sys.argv[1:] != ["sign"]:
        raise SystemExit("use address or sign")
    qr = sys.stdin.read()
    envelope, request = parse_qr_input(qr, "evm-request")
    if request is None:
        raise ValueError("Native Snap QR v1 request required")
    plan = build_review_plan(envelope, root)
    bind_qr_to_review(request, plan, root)
    session = ReviewSession(plan)
    for index in range(len(plan.pages)):
        session.acknowledge(index, plan.review_digest)
    session.set_confirmation(plan.challenge, plan.review_digest)
    signed = session.sign(
        root, default_profile(root),
        extra_confirmation="UNVERIFIED RECIPIENT",
    )
    sys.stdout.write(signed_qr_text(request, signed, "evm-signed"))


if __name__ == "__main__":
    main()
