"""Independent BIP143 witness sighash, DER verification and resource regression.

Only the permanently compromised public BIP39 test vector from test_btc_hardening.
Independent SHA256d/BIP143 implementation deliberately avoids embit.sighash.
"""
import base64
import hashlib
import struct
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from embit import psbt, transaction

from test_btc_hardening import ROOT, DEST, vector
from usb_cold_wallet.btc import _read_psbt, sign_btc_psbt


def hash256(value: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()


def independent_bip143_sighash(tx, prev_value: int, compressed_pub: bytes, index=0) -> bytes:
    """BIP143 SIGHASH_ALL for native P2WPKH; no embit PSBT sighash calls."""
    assert len(compressed_pub) == 33 and compressed_pub[0] in (2, 3)
    assert tx.version == 2 and tx.locktime == 0
    pubhash = hashlib.new("ripemd160", hashlib.sha256(compressed_pub).digest()).digest()
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


def test_independent_bip143_verifies_exported_signature_and_fee():
    original = vector()
    result = sign_btc_psbt(ROOT, original.to_base64(), DEST, 60_000, 1_500, 0)
    assert result["fee_sats"] == 1_000
    assert result["signature_count"] == 1

    signed_psbt = psbt.PSBT.parse(base64.b64decode(result["signed_psbt_base64"]))
    final = transaction.Transaction.parse(bytes.fromhex(result["finalized_tx_hex"]))
    assert final.txid() == signed_psbt.tx.txid()
    assert final.vin[0].witness.items[1] == next(iter(signed_psbt.inputs[0].partial_sigs)).sec()

    raw_sig, compressed_pub = final.vin[0].witness.items
    assert raw_sig[-1] == 1  # SIGHASH_ALL and no ANYONECANPAY/SINGLE
    digest = independent_bip143_sighash(signed_psbt.tx, 100_000, compressed_pub)
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), compressed_pub)
    public.verify(raw_sig[:-1], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    # Independent signature verification must reject false prevout value and
    # any subtle change to a signed output.
    with pytest.raises(InvalidSignature):
        public.verify(raw_sig[:-1],
                      independent_bip143_sighash(signed_psbt.tx, 100_001, compressed_pub),
                      ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    altered = transaction.Transaction.parse(signed_psbt.tx.serialize())
    altered.vout[0].value += 1
    with pytest.raises(InvalidSignature):
        public.verify(raw_sig[:-1],
                      independent_bip143_sighash(altered, 100_000, compressed_pub),
                      ec.ECDSA(utils.Prehashed(hashes.SHA256())))


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
