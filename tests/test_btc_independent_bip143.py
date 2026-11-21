"""Independent BIP143 witness signature, prevout and PSBT binding regressions.

Only the permanently compromised public BIP39 test vector from test_btc_hardening.
BIP143 SHA256d and ECDSA verification do not use embit's sighash or verify.
"""
import base64
import hashlib
import struct

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from embit import psbt, script, transaction

from test_btc_hardening import ROOT, DEST, vector
from usb_cold_wallet.btc import _read_psbt, sign_btc_psbt


def hash256(value: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()


def hash160(value: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(value).digest()).digest()


def independent_bip143_sighash(tx, prev_value: int, compressed_pub: bytes, index=0) -> bytes:
    """BIP143 SIGHASH_ALL for native P2WPKH; no embit PSBT sighash calls."""
    assert len(compressed_pub) == 33 and compressed_pub[0] in (2, 3)
    assert tx.version == 2 and tx.locktime == 0
    pubhash = hash160(compressed_pub)
    scriptcode = b"\x19\x76\xa9\x14" + pubhash + b"\x88\xac"
    inputs = [vin.serialize() for vin in tx.vin]
    hash_prevouts = hash256(b"".join(raw[:36] for raw in inputs))
    hash_sequences = hash256(b"".join(raw[-4:] for raw in inputs))
    hash_outputs = hash256(b"".join(out.serialize() for out in tx.vout))
    payload = (
        struct.pack("<I", tx.version)
        + hash_prevouts + hash_sequences
        + inputs[index][:36] + scriptcode
        + struct.pack("<Q", prev_value) + inputs[index][-4:]
        + hash_outputs
        + struct.pack("<I", tx.locktime)
        + struct.pack("<I", 1)  # SIGHASH_ALL
    )
    return hash256(payload)


def signed_fixture():
    result = sign_btc_psbt(ROOT, vector().to_base64(), DEST, 60_000, 1_500, 0)
    signed_psbt = psbt.PSBT.parse(base64.b64decode(result["signed_psbt_base64"]))
    final = transaction.Transaction.parse(bytes.fromhex(result["finalized_tx_hex"]))
    return result, signed_psbt, final


def independently_verify_exported_spend(signed_psbt, final):
    """Check consensus-relevant P2WPKH witness/UTXO bindings independently.

    The test imports embit only to decode the transaction and PSBT. It
    calculates HASH160, BIP143 digest and ECDSA verification independently.
    """
    assert len(signed_psbt.tx.vin) == len(final.vin) == 1
    assert final.txid() == signed_psbt.tx.txid(), "unsigned transaction mismatch"
    unsigned_input = signed_psbt.tx.vin[0]
    spend_input = final.vin[0]
    assert spend_input.txid == unsigned_input.txid
    assert spend_input.vout == unsigned_input.vout
    assert not spend_input.script_sig.data
    assert len(spend_input.witness.items) == 2
    raw_sig, compressed_pub = spend_input.witness.items
    assert len(raw_sig) > 1 and raw_sig[-1] == 1, "non-SIGHASH_ALL witness"
    assert len(compressed_pub) == 33 and compressed_pub[0] in (2, 3)

    scope = signed_psbt.inputs[0]
    assert scope.non_witness_utxo is not None and scope.witness_utxo is not None
    prev_tx = scope.non_witness_utxo
    assert prev_tx.txid() == unsigned_input.txid, "non-witness UTXO outpoint TXID mismatch"
    assert 0 <= unsigned_input.vout < len(prev_tx.vout), "outpoint index mismatch"
    prevout = prev_tx.vout[unsigned_input.vout]
    assert prevout.value == scope.witness_utxo.value, "witness UTXO value mismatch"
    assert (prevout.script_pubkey.data == scope.witness_utxo.script_pubkey.data
            ), "witness UTXO script mismatch"
    assert prevout.script_pubkey.data == b"\x00\x14" + hash160(compressed_pub), (
        "P2WPKH ScriptPubKey HASH160 mismatch"
    )

    assert len(scope.partial_sigs) == 1, "PSBT must contain one partial signature"
    (psbt_pubkey, psbt_signature), = scope.partial_sigs.items()
    assert psbt_pubkey.sec() == compressed_pub, "witness/PSBT public key mismatch"
    assert psbt_signature == raw_sig, "witness/PSBT signature differs"

    digest = independent_bip143_sighash(signed_psbt.tx, prevout.value, compressed_pub)
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), compressed_pub)
    public.verify(raw_sig[:-1], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return prevout.value, raw_sig, compressed_pub, public


def test_independent_bip143_verifies_exported_signature_and_fee():
    result, signed_psbt, final = signed_fixture()
    assert result["fee_sats"] == 1_000
    assert result["signature_count"] == 1
    value, raw_sig, pubkey, public = independently_verify_exported_spend(signed_psbt, final)
    assert value == 100_000
    assert sum(out.value for out in final.vout) == 99_000
    assert value - sum(out.value for out in final.vout) == result["fee_sats"]
    assert final.vout[0].value == 60_000
    assert final.vout[0].script_pubkey.data == script.address_to_scriptpubkey(DEST).data

    # ECDSA must reject a forged prevout value or changed signed recipient.
    with pytest.raises(InvalidSignature):
        public.verify(raw_sig[:-1],
                      independent_bip143_sighash(signed_psbt.tx, value + 1, pubkey),
                      ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    altered = transaction.Transaction.parse(signed_psbt.tx.serialize())
    altered.vout[0].value += 1
    with pytest.raises(InvalidSignature):
        public.verify(raw_sig[:-1],
                      independent_bip143_sighash(altered, value, pubkey),
                      ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def test_independent_verifier_rejects_prevout_and_script_mismatches():
    _, signed_psbt, final = signed_fixture()
    wrong_witness = psbt.PSBT.parse(signed_psbt.serialize())
    wrong_witness.inputs[0].witness_utxo.script_pubkey = script.Script(
        b"\x00\x14" + b"\x13" * 20
    )
    with pytest.raises(AssertionError, match="witness UTXO script mismatch"):
        independently_verify_exported_spend(wrong_witness, final)

    wrong_non_witness = psbt.PSBT.parse(signed_psbt.serialize())
    wrong_non_witness.inputs[0].non_witness_utxo.vout[0].value += 1
    with pytest.raises(AssertionError, match="outpoint TXID mismatch"):
        independently_verify_exported_spend(wrong_non_witness, final)

    wrong_pubkey = transaction.Transaction.parse(final.serialize())
    signature = wrong_pubkey.vin[0].witness.items[0]
    wrong_pubkey.vin[0].witness = transaction.Witness(
        [signature, b"\x02" + b"\x00" * 32]
    )
    with pytest.raises(AssertionError, match="P2WPKH ScriptPubKey"):
        independently_verify_exported_spend(signed_psbt, wrong_pubkey)


def test_independent_verifier_rejects_signature_substitution():
    _, signed_psbt, final = signed_fixture()
    original_sig, original_pub = final.vin[0].witness.items

    wrong_final = transaction.Transaction.parse(final.serialize())
    wrong_final.vin[0].witness = transaction.Witness(
        [bytes([original_sig[0] ^ 1]) + original_sig[1:], original_pub]
    )
    with pytest.raises(AssertionError, match="witness/PSBT signature differs"):
        independently_verify_exported_spend(signed_psbt, wrong_final)

    wrong_psbt = psbt.PSBT.parse(signed_psbt.serialize())
    only_pubkey = next(iter(wrong_psbt.inputs[0].partial_sigs))
    wrong_psbt.inputs[0].partial_sigs[only_pubkey] = (
        bytes([original_sig[0] ^ 1]) + original_sig[1:]
    )
    with pytest.raises(AssertionError, match="witness/PSBT signature differs"):
        independently_verify_exported_spend(wrong_psbt, final)


def test_raw_psbt_prefix_and_compactsize_boundary_regressions():
    raw = vector().serialize()
    # Truncations must be converted to ValueError; never IndexError or OOM.
    for end in (0, 1, 4, 5, 6, 7, 8, 9, len(raw) // 2, len(raw) - 1):
        with pytest.raises(ValueError):
            _read_psbt(base64.b64encode(raw[:end]).decode("ascii"))
    for encoded in (
        base64.b64encode(b"psbt\xff" + b"\xff" + b"\xff" * 8).decode(),
        base64.b64encode(b"psbt\xff" + b"\xfe" + b"\xff" * 4).decode(),
        base64.b64encode(b"psbt\xff" + b"\xfd" + b"\xff" * 2).decode(),
        base64.b64encode(b"psbt\xff" + b"\x01\x00\xff" + b"\xff" * 8).decode(),
        base64.b64encode(b"psbt\xff" + b"\x01\x00\x01\x00").decode(),
        base64.b64encode(raw + b"\x00").decode(),
    ):
        with pytest.raises(ValueError):
            _read_psbt(encoded)


def test_declared_psbt_maximum_size_fails_before_parser():
    raw = vector().serialize()
    oversized = base64.b64encode(raw + b"X" * 200_001).decode()
    with pytest.raises(ValueError, match="size limit"):
        _read_psbt(oversized)
