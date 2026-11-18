"""Known compromised BIP39 test mnemonic. NEVER use for real funds."""
import base64

import pytest
import rlp
from embit import bip32, networks, psbt, script, transaction
from eth_account import Account

from usb_cold_wallet.btc import review_btc_psbt, sign_btc_psbt
from usb_cold_wallet.evm import (
    decode_signed_eip1559,
    review_evm_transaction,
    review_signed_evm_transaction,
    sign_evm,
)
from usb_cold_wallet.keys import btc_address, btc_key, evm_account, root_from_mnemonic, watch_only
from usb_cold_wallet.vault import decrypt_mnemonic, encrypt_mnemonic, validate_mnemonic

TEST_MNEMONIC = "abandon " * 11 + "about"
PASSWORD = "fictional-test-password-strong"
RECIPIENT = "0x000000000000000000000000000000000000dEaD"
# External Sepolia EIP-1559 raw transaction independently decoded with Foundry `cast from-rlp`.
# Provenance is documented in docs/EVM_TEST_VECTORS.md. It intentionally uses gas=196608,
# so our stricter native-transfer policy must decode it but refuse to approve/sign it.
EXTERNAL_SEPOLIA_TYPE2 = (
    "0x02f87583aa36a714847735940085174876e8008303000094"
    "b0920c523d582040f2bcb1bd7fb1c7c1ecebdb34865af3107a400080c001"
    "a03f8ed18cb03ee0fe3fbc3f0a7477a2f68db6ec84450e77e702b82a3f2c873aa4"
    "a0205c4f6a16ea8ad13a148cc3105814cd4a6860cd26a771651199c85ccb7c7f0f"
)


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
    assert signed["max_total_wei"] == tx["value"] + 42_000_000_000_000

    decoded = decode_signed_eip1559(signed["signed_raw_transaction"])
    assert decoded == signed["decoded_transaction"]
    assert decoded["chain_id"] == 11155111
    assert decoded["gas"] == 21000
    assert decoded["to"] == RECIPIENT
    assert decoded["value_wei"] == tx["value"]
    assert decoded["data"] == "0x"
    assert decoded["access_list"] == []

    signed_review = review_signed_evm_transaction(
        signed["signed_raw_transaction"], RECIPIENT, tx["value"]
    )
    assert signed_review["from"] == signed["from"]
    assert signed_review["transaction_hash"] == signed["transaction_hash"]


def test_external_sepolia_eip1559_vector_decodes_but_policy_rejects():
    decoded = decode_signed_eip1559(EXTERNAL_SEPOLIA_TYPE2)
    assert decoded["chain_id"] == 11155111
    assert decoded["nonce"] == 20
    assert decoded["max_priority_fee_per_gas"] == 2_000_000_000
    assert decoded["max_fee_per_gas"] == 100_000_000_000
    assert decoded["gas"] == 196_608
    assert decoded["to"] == "0xB0920c523d582040f2BCB1bD7FB1c7C1ECEbdB34"
    assert decoded["value_wei"] == 100_000_000_000_000
    assert decoded["data"] == "0x"
    assert decoded["access_list"] == []
    assert decoded["signature"]["y_parity"] == 1
    assert decoded["transaction_hash"] == "0x07bfbeb337e19763a1f74d989dae2953807dcb06822354cfefb16405a11beb93"
    assert Account.recover_transaction(EXTERNAL_SEPOLIA_TYPE2) == "0x7e41354AfE84800680ceB104c5Fc99eCB98A25f0"

    with pytest.raises(ValueError, match="21,000-gas"):
        review_signed_evm_transaction(
            EXTERNAL_SEPOLIA_TYPE2,
            "0xB0920c523d582040f2BCB1bD7FB1c7C1ECEbdB34",
            100_000_000_000_000,
        )


def test_signed_eip1559_decoder_rejects_wrong_type_truncation_and_noncanonical_integer():
    with pytest.raises(ValueError, match="type 2"):
        decode_signed_eip1559("0x01" + EXTERNAL_SEPOLIA_TYPE2[4:])
    with pytest.raises(ValueError, match="Malformed"):
        decode_signed_eip1559(EXTERNAL_SEPOLIA_TYPE2[:-2])

    raw = bytes.fromhex(EXTERNAL_SEPOLIA_TYPE2[2:])
    fields = rlp.decode(raw[1:])
    fields[1] = b"\x00\x14"
    malformed = "0x02" + rlp.encode(fields).hex()
    with pytest.raises(ValueError, match="not canonically encoded"):
        decode_signed_eip1559(malformed)


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
    tx = transaction.Transaction(
        vin=[transaction.TransactionInput(bytes.fromhex("11" * 32), 0)],
        vout=outputs,
    )
    obj = psbt.PSBT(tx)
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
