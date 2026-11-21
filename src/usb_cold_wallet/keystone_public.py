"""Offline export of public EVM account metadata for Keystone BC-UR pairing.

Only BIP32 extended PUBLIC key data is exported. Never copy a seed, vault, or
root private material into the QR renderer. Research-only Sepolia usage.
"""
from __future__ import annotations

from .keys import EVM_ACCOUNT_PATH, evm_account

FORMAT = "usb-cold-keystone-public-v1"
EVM_PARENT_PATH = "m/44h/60h/0h"


def export_keystone_public(root) -> dict:
    """Public account xpub at 44'/60'/0' and the existing m/.../0/0 address."""
    account_key = root.derive(EVM_PARENT_PATH)
    public = account_key.to_public()
    address_key = root.derive(EVM_ACCOUNT_PATH).to_public()
    return {
        "format": FORMAT,
        "network": "sepolia",
        "chain_id": 11155111,
        "master_fingerprint": root.my_fingerprint.hex(),
        "account_derivation": EVM_PARENT_PATH,
        "address_derivation": EVM_ACCOUNT_PATH,
        "account_public_key": public.key.sec().hex(),
        "account_chain_code": public.chain_code.hex(),
        "account_parent_fingerprint": root.derive("m/44h/60h").my_fingerprint.hex(),
        "address_public_key": address_key.key.sec().hex(),
        "address_chain_code": address_key.chain_code.hex(),
        "address_parent_fingerprint": root.derive("m/44h/60h/0h/0").my_fingerprint.hex(),
        "address": evm_account(root).address,
    }
