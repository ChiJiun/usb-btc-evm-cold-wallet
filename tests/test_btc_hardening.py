"""Adversarial PSBT vectors; the BIP39 mnemonic is public and compromised."""
import base64
import random

import pytest
from embit import bip32, ec, psbt, script, transaction

from usb_cold_wallet.btc import _read_psbt, review_btc_psbt, sign_btc_psbt
from usb_cold_wallet.keys import btc_address, btc_key, root_from_mnemonic

ROOT = root_from_mnemonic("abandon " * 11 + "about")
DEST = btc_address(ROOT, 0, 1)


def vector():
    key = btc_key(ROOT, 0, 0)
    prev = transaction.Transaction(
        vin=[transaction.TransactionInput(b"\x42" * 32, 0)],
        vout=[transaction.TransactionOutput(100_000, script.p2wpkh(key.key))],
    )
    spend = transaction.Transaction(
        vin=[transaction.TransactionInput(prev.txid(), 0)],
        vout=[
            transaction.TransactionOutput(60_000, script.address_to_scriptpubkey(DEST)),
            transaction.TransactionOutput(39_000, script.p2wpkh(btc_key(ROOT, 1, 0).key)),
        ],
    )
    p = psbt.PSBT(spend)
    # embit 0.8.0 scopes use a shared default unknown dict; isolate each vector.
    p.inputs[0].unknown = {}
    for scope in p.outputs:
        scope.unknown = {}
    p.inputs[0].witness_utxo = prev.vout[0]
    p.inputs[0].non_witness_utxo = prev
    p.inputs[0].bip32_derivations[key.key.get_public_key()] = psbt.DerivationPath(
        ROOT.my_fingerprint, bip32.parse_path("m/84h/1h/0h/0/0")
    )
    return p


def review(p):
    return review_btc_psbt(ROOT, p.to_base64(), DEST, 60_000, 1500, 0)


def test_signatures_verify_using_public_key():
    p = vector()
    result = sign_btc_psbt(ROOT, p.to_base64(), DEST, 60_000, 1500, 0)
    signed = psbt.PSBT.parse(base64.b64decode(result["signed_psbt_base64"]))
    key, sig = next(iter(signed.inputs[0].partial_sigs.items()))
    assert sig[-1] == 1
    assert key.verify(ec.Signature.parse(sig[:-1]), signed.sighash(0, sighash=1))
    final = transaction.Transaction.parse(bytes.fromhex(result["finalized_tx_hex"]))
    assert final.txid() == signed.tx.txid()
    assert final.vin[0].witness.items == [sig, key.sec()]


def test_reject_missing_or_forged_previous_transaction():
    p = vector()
    p.inputs[0].non_witness_utxo = None
    with pytest.raises(ValueError, match="both"):
        review(p)
    p = vector()
    p.inputs[0].non_witness_utxo.vout[0].value += 1000
    with pytest.raises(ValueError, match="ID mismatch"):
        review(p)
    p = vector()
    p.inputs[0].witness_utxo = transaction.TransactionOutput(
        200_000, p.inputs[0].witness_utxo.script_pubkey
    )
    with pytest.raises(ValueError, match="witness UTXO mismatch"):
        review(p)


@pytest.mark.parametrize("path", [
    "m/84h/0h/0h/0/0", "m/84h/1h/1h/0/0", "m/84h/1h/0h/2/0",
    "m/84h/1h/0h/0/100", "m/84h/1h/0h/0/0/1",
])
def test_reject_unapproved_paths(path):
    p = vector()
    pub = next(iter(p.inputs[0].bip32_derivations))
    p.inputs[0].bip32_derivations[pub] = psbt.DerivationPath(
        ROOT.my_fingerprint, bip32.parse_path(path)
    )
    with pytest.raises(ValueError, match="derivation"):
        review(p)


def test_reject_wrong_fingerprint_and_public_key():
    p = vector()
    pub = next(iter(p.inputs[0].bip32_derivations))
    p.inputs[0].bip32_derivations[pub] = psbt.DerivationPath(
        b"\x00" * 4, bip32.parse_path("m/84h/1h/0h/0/0")
    )
    with pytest.raises(ValueError):
        review(p)
    p = vector()
    origin = next(iter(p.inputs[0].bip32_derivations.values()))
    p.inputs[0].bip32_derivations.clear()
    p.inputs[0].bip32_derivations[btc_key(ROOT, 0, 2).key.get_public_key()] = origin
    with pytest.raises(ValueError, match="public key"):
        review(p)


def test_reject_duplicate_outpoint():
    p = vector()
    p.inputs.append(p.inputs[0])
    with pytest.raises(ValueError, match="Duplicate"):
        review(p)


@pytest.mark.parametrize("mutator", [
    lambda p: setattr(p.inputs[0], "sighash_type", 0x81),
    lambda p: setattr(p.inputs[0], "redeem_script", script.Script(b"\x51")),
    lambda p: p.inputs[0].partial_sigs.update({btc_key(ROOT, 0, 0).key.get_public_key(): b"abc"}),
    lambda p: p.inputs[0].unknown.update({b"\xfc": b"x"}),
    lambda p: p.outputs[1].unknown.update({b"\xfc": b"x"}),
    lambda p: setattr(p.outputs[0], "value", 0),
])
def test_reject_hostile_metadata(mutator):
    p = vector()
    mutator(p)
    with pytest.raises(ValueError):
        review(p)


def test_change_index_and_fee_policy():
    p = vector()
    with pytest.raises(ValueError):
        review_btc_psbt(ROOT, p.to_base64(), DEST, 60_000, 1500, 1)
    with pytest.raises(ValueError):
        review_btc_psbt(ROOT, p.to_base64(), DEST, 60_000, 999, 0)
    with pytest.raises(ValueError):
        review_btc_psbt(ROOT, p.to_base64(), DEST, 60_000, 1500, None)


def test_reject_malformed_base64_trailing_bytes_and_size():
    p = vector()
    raw = p.serialize()
    for malformed in ["!", "", base64.b64encode(raw + b"garbage").decode(),
                      base64.b64encode(b"psbt\xff" + b"\xfd\xff\xff").decode(),
                      "A" * 300_000]:
        with pytest.raises(ValueError):
            _read_psbt(malformed)


def test_deterministic_parser_mutation_fuzz():
    raw = vector().serialize()
    rng = random.Random(20261118)
    for _ in range(250):
        data = bytearray(raw)
        for _ in range(rng.randrange(1, 5)):
            location = rng.randrange(len(data))
            data[location] ^= 1 << rng.randrange(8)
        try:
            _read_psbt(base64.b64encode(data).decode())
        except (ValueError, IndexError, OverflowError, MemoryError) as exc:
            # All malformed input must be rejected with a controlled ValueError.
            assert type(exc) is ValueError
