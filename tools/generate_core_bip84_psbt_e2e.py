"""Reproducible Bitcoin Core regtest PSBT creation + independent finalize oracle.

Requires a local Bitcoin Core node with regtest RPC reachable through
'docker exec btc-issue2-core bitcoin-cli -regtest'. Public BIP39 test mnemonic ONLY.
The unsigned transaction and previous transaction originate in Bitcoin Core;
embit adds the metadata that our offline policy requires (BIP32 derivation and
both prevout representations). Bitcoin Core then independently finalizes and
decodes the cold-signed PSBT. Never use live seeds.
"""
import base64
from decimal import Decimal
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from embit import bip32, networks, psbt, script, transaction

ROOTDIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOTDIR / "src"))
sys.path.insert(0, str(ROOTDIR / "tests"))

from usb_cold_wallet.btc import sign_btc_psbt  # noqa: E402
from usb_cold_wallet.keys import btc_address, btc_key, root_from_mnemonic  # noqa: E402
from test_btc_independent_bip143 import independently_verify_exported_spend  # noqa: E402

ROOT = root_from_mnemonic("abandon " * 11 + "about")
COIN = 100_000_000


def core(*args):
    cmd = ["docker", "exec", "btc-issue2-core", "bitcoin-cli", "-regtest",
           *[json.dumps(arg, separators=(",", ":")) if isinstance(arg, (dict, list, bool))
             else str(arg) for arg in args]]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
    output = result.stdout.strip()
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return output


def regtest_address(branch, index):
    return script.p2wpkh(btc_key(ROOT, branch, index).key).address(
        networks.NETWORKS["regtest"])


def sats_to_btc(sats):
    return str(Decimal(sats) / COIN)


def generate():
    source = regtest_address(0, 0)
    recipient = regtest_address(0, 1)
    change = regtest_address(1, 0)
    blocks = core("generatetoaddress", 101, source)
    first_block = core("getblock", blocks[0])
    prevtxid = first_block["tx"][0]
    prevraw = core("getrawtransaction", prevtxid, False, blocks[0])
    prev = transaction.Transaction.parse(bytes.fromhex(prevraw))
    vout = next(i for i, o in enumerate(prev.vout)
                if o.script_pubkey.data == script.p2wpkh(btc_key(ROOT, 0, 0).key).data)
    input_sats = prev.vout[vout].value
    recipient_sats = 60_000
    fee_sats = 1_000
    change_sats = input_sats - recipient_sats - fee_sats
    assert change_sats > 0

    # Bitcoin Core is the independent PSBT unsigned-transaction creator.
    core_psbt = core("createpsbt",
                     [{"txid": prevtxid, "vout": vout, "sequence": 4294967295}],
                     [{recipient: sats_to_btc(recipient_sats)},
                      {change: sats_to_btc(change_sats)}], 0, False)
    p = psbt.PSBT.parse(base64.b64decode(core_psbt))
    assert p.version is None and len(p.inputs) == 1 and len(p.outputs) == 2
    p.inputs[0].unknown = {}
    for out in p.outputs:
        out.unknown = {}
    p.inputs[0].witness_utxo = prev.vout[vout]
    p.inputs[0].non_witness_utxo = prev
    key = btc_key(ROOT, 0, 0)
    p.inputs[0].bip32_derivations[key.key.get_public_key()] = psbt.DerivationPath(
        ROOT.my_fingerprint, bip32.parse_path("m/84h/1h/0h/0/0"))

    ready_psbt = p.to_base64()
    testnet_recipient = btc_address(ROOT, 0, 1)
    signed = sign_btc_psbt(ROOT, ready_psbt, testnet_recipient,
                           recipient_sats, fee_sats, 0)
    external = core("finalizepsbt", signed["signed_psbt_base64"], True)
    assert external["complete"] is True, "Bitcoin Core cannot finalize cold signature"
    assert external["hex"] == signed["finalized_tx_hex"], "Core extract differs from cold transaction"
    decoded = core("decoderawtransaction", external["hex"])
    final = transaction.Transaction.parse(bytes.fromhex(external["hex"]))
    assert decoded["txid"] == final.txid()[::-1].hex()
    assert final.vout[0].value == recipient_sats
    assert final.vout[1].value == change_sats
    assert input_sats - sum(out.value for out in final.vout) == fee_sats
    signed_parsed = psbt.PSBT.parse(base64.b64decode(signed["signed_psbt_base64"]))
    independently_verify_exported_spend(signed_parsed, final)
    return {
        "provenance": "Bitcoin Core RPC createpsbt on synthetic regtest coinbase; metadata enrichment via embit; Core finalizepsbt and decoderawtransaction",
        "core_version": core("getnetworkinfo")["subversion"],
        "core_block_hash": blocks[0],
        "core_prev_txid": prevtxid,
        "core_prev_raw_hex": prevraw,
        "core_unsigned_psbt_base64": core_psbt,
        "enriched_psbt_base64": ready_psbt,
        "signed_psbt_base64": signed["signed_psbt_base64"],
        "core_finalized_tx_hex": external["hex"],
        "core_txid": decoded["txid"],
        "core_wtxid": decoded["hash"],
        "public_bip39_mnemonic": "abandon " * 11 + "about",
        "derivation": "m/84h/1h/0h/0/0",
        "recipient_testnet": testnet_recipient,
        "recipient_sats": recipient_sats,
        "change_sats": change_sats,
        "fee_sats": fee_sats,
        "psbt_sha256": hashlib.sha256(base64.b64decode(ready_psbt)).hexdigest(),
    }


if __name__ == "__main__":
    output = generate()
    path = ROOTDIR / "btc-core-e2e-result.json"
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"core_version": output["core_version"],
                      "core_txid": output["core_txid"],
                      "psbt_sha256": output["psbt_sha256"],
                      "fixture": str(path.name)}))
