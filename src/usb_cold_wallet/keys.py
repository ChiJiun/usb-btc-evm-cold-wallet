"""BIP39 / BIP32 derivation. Testnet-first: no custom crypto primitives."""
from embit import bip32, bip39, networks, script
from eth_account import Account

BTC_ACCOUNT_PATH = "m/84h/1h/0h"
EVM_ACCOUNT_PATH = "m/44h/60h/0h/0/0"


def root_from_mnemonic(mnemonic: str, bip39_passphrase: str = ""):
    return bip32.HDKey.from_seed(bip39.mnemonic_to_seed(mnemonic, password=bip39_passphrase))


def btc_key(root, branch: int = 0, index: int = 0):
    if branch not in (0, 1) or not 0 <= index <= 999:
        raise ValueError("Only BIP84 receiving (0) or change (1) path indexes 0..999 are supported")
    return root.derive(f"{BTC_ACCOUNT_PATH}/{branch}/{index}")


def btc_address(root, branch: int = 0, index: int = 0) -> str:
    return script.p2wpkh(btc_key(root, branch, index).key).address(networks.NETWORKS["test"])


def evm_account(root):
    key = root.derive(EVM_ACCOUNT_PATH).key.secret
    return Account.from_key(key)


def watch_only(root, count: int = 3) -> dict:
    if not 1 <= count <= 20:
        raise ValueError("count must be between 1 and 20")
    return {
        "bitcoin": {
            "network": "testnet",
            "derivation": BTC_ACCOUNT_PATH,
            "account_tpub": root.derive(BTC_ACCOUNT_PATH).to_public().to_base58(version=networks.NETWORKS["test"]["xpub"]),
            "receive_addresses": [btc_address(root, 0, index) for index in range(count)],
        },
        "evm": {
            "network": "Sepolia",
            "chain_id": 11155111,
            "derivation": EVM_ACCOUNT_PATH,
            "address": evm_account(root).address,
        },
    }
