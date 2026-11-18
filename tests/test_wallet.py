"""Known compromised BIP39 test mnemonic. NEVER use for real funds."""
import base64

import pytest
from embit import bip32, networks, psbt, script, transaction
from eth_account import Account

from usb_cold_wallet.btc import review_btc_psbt, sign_btc_psbt
from usb_cold_wallet.evm import review_evm_transaction, sign_evm
from usb_cold_wallet.keys import btc_address, btc_key, evm_account, root_from_mnemonic, watch_only
from usb_cold_wallet.vault import decrypt_mnemonic, encrypt_mnemonic, validate_mnemonic

TEST_MNEMONIC = "abandon " * 11 + "about"
PASSWORD = "fictional-test-password-strong"
RECIPIENT = "0x000000000000000000000000000000000000dEaD"


@pytest.fixture(scope="module")
def root():
    return root_from_mnemonic(TEST_MNEMONIC)


def test_bip39_standard_ethereum_vector(root):
    assert evm_account(root).address == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"


def test_wallet_addresses_testnet(root):
    info = watch_only(root, 2)
    assert info["bitcoin"]["receive_addresses"][0].startswith("tb1q")
    assert info["bitcoin"]["account_tpub"].startswith("tpub")
    assert len(info["bitcoin"]["receive_addresses"]) == 2
    assert info["evm"]["chain_id"] == 11155111


def test_bip39_invalid_checksum():
    with pytest.raises(ValueError):
        validate_mnemonic("abandon " * 12)


def test_encrypted_wallet_roundtrip_and_wrong_password():
    container = encrypt_mnemonic(TEST_MNEMONIC, PASSWORD)
    assert TEST_MNEMONIC not in str(container)
    assert decrypt_mnemonic(container, PASSWORD) == TEST_MNEMONIC
    with pytest.raises(ValueError, match="Incorrect"):
        decrypt_mnemonic(container, "this-is-not-my-password")


def _sepolia_tx():
    return {
        "type": 2,
        "chainId": 11155111,
        "nonce": 0,
        "to": RECIPIENT,
        "value": 1_000_000_000_000,
        "gas": 21000,
        "maxFeePerGas": 2_000_000_000,
        "maxPriorityFeePerGas": 1_000_000_000,
        "data": "0x",
    }


def test_evm_sign_and_recover(root):
    tx = _sepolia_tx()
    reviewed = review_evm_transaction(tx, RECIPIENT, tx["value"])
    assert reviewed["max_fee_wei"] == 42_000_000_000_000
    signed = sign_evm(root, tx, RECIPIENT, tx["value"])
    assert signed["from"] == evm_account(root).address
    assert Account.recover_transaction(signed["signed_raw_transaction"]) == signed["from"]


@pytest.mark.parametrize("changed", [
    {"chainId": 1}, {"chainId": 137}, {"type": 0}, {"gas": 60000},
    {"data": "0x1234"}, {"to": "0x0000000000000000000000000000000000000001"},
    {"value": 2}, {"maxPriorityFeePerGas": 3_000_000_000},
    {"gasPrice": 1}, {"nonce": -1}, {"value": True},
])
def test_rejects_unapproved_evm_variants(changed):
    tx = _sepolia_tx()
    tx.update(changed)
    with pytest.raises(ValueError):
        review_evm_transaction(tx, RECIPIENT, 1_000_000_000_000)


def _test_psbt(root, change=True, fee=1200):
    receive_key = btc_key(root, 0, 0)
    input_utxo = transaction.TransactionOutput(120_000, script.p2wpkh(receive_key.key))
    destination = btc_address(root, 0, 1)
    outputs = [transaction.TransactionOutput(60_000, script.address_to_scriptpubkey(destination))]
    if change:
        outputs.append(transaction.TransactionOutput(60_000 - fee, script.p2wpkh(btc_key(root, 1, 0).key)))
    else:
        outputs[0].value = 120_000 - fee
    previous = transaction.Transaction(
        vin=[transaction.TransactionInput(bytes.fromhex("22" * 32), 0)],
        vout=[input_utxo],
    )
    tx = transaction.Transaction(
        vin=[transaction.TransactionInput(previous.txid(), 0)],
        vout=outputs,
    )
    obj = psbt.PSBT(tx)
    obj.inputs[0].non_witness_utxo = previous
    obj.inputs[0].witness_utxo = input_utxo
    obj.inputs[0].bip32_derivations[receive_key.key.get_public_key()] = psbt.DerivationPath(
        root.my_fingerprint, bip32.parse_path("m/84h/1h/0h/0/0")
    )
    return base64.b64encode(obj.serialize()).decode(), destination, outputs[0].value


def test_btc_psbt_sign(root):
    encoded, recipient, value = _test_psbt(root)
    review = review_btc_psbt(root, encoded, recipient, value, 2000, change_index=0)
    assert review["fee_sats"] == 1200
    result = sign_btc_psbt(root, encoded, recipient, value, 2000, change_index=0)
    parsed = psbt.PSBT.parse(base64.b64decode(result["signed_psbt_base64"]))
    assert result["signature_count"] == 1
    assert len(parsed.inputs[0].partial_sigs) == 1


def test_btc_rejects_wrong_fee_and_missing_change(root):
    encoded, recipient, value = _test_psbt(root)
    with pytest.raises(ValueError):
        review_btc_psbt(root, encoded, recipient, value, 100, change_index=0)
    with pytest.raises(ValueError):
        review_btc_psbt(root, encoded, recipient, value, 3000)
    with pytest.raises(ValueError):
        review_btc_psbt(root, encoded, recipient, value + 1, 3000, change_index=0)


def test_btc_rejects_foreign_input(root):
    encoded, recipient, value = _test_psbt(root)
    parsed = psbt.PSBT.parse(base64.b64decode(encoded))
    parsed.inputs[0].witness_utxo.script_pubkey = script.address_to_scriptpubkey(
        "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr"
    )
    with pytest.raises(ValueError):
        review_btc_psbt(root, parsed.to_base64(), recipient, value, 2000, change_index=0)
