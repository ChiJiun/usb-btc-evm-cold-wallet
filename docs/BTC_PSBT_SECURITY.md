# Bitcoin PSBT v0 validation (Issue #2)

**Research prototype; Bitcoin testnet only. Mainnet signing remains disabled.**

The offline signer accepts only a PSBT v0 with 1–20 native BIP84 testnet
P2WPKH inputs and one payment output, optionally one change output.
It rejects unknown metadata, preexisting signatures, unsupported scripts,
duplicate outpoints, and extra data after the serialized PSBT.
Base64 input is limited to 200 KB decoded.

For **each input**, both `witness_utxo` and `non_witness_utxo` are now
mandatory. The latter must hash to the outpoint TXID and contain a
matching indexed output (same amount and script). A naked witness UTXO
must not be trusted for fee approval. Each input must specify exactly one
BIP32 derivation: the wallet's master fingerprint and
`m/84'/1'/0'/{0,1}/index` with index below 100, matching the specified
public key and P2WPKH script.

The operator independently provides a testnet destination, satoshi amount,
maximum absolute fee and optionally change index. Every output must match
that policy; no unknown output is permitted. Inputs/outputs are checked
against Bitcoin's maximum monetary supply and the computed fee must be
between zero and the explicit upper bound.

Signatures are validated against the transaction's SegWit v0 SIGHASH_ALL
digest and public keys. The produced final SegWit transaction is serialized
and round-tripped before export, alongside the signed PSBT. **Round-tripping
is not Bitcoin consensus/script validation**; broadcast and external
verification remain the watch-only host's responsibility.

## Limitations / next security work

- Current vectors are synthetic deterministic transactions built using
  `embit`, not independently generated Bitcoin Core/Sparrow fixtures.
  Add known external reference vectors with recorded provenance, amounts,
  txids, witnesses, and expected results before considering the issue fully
  closed.
- 250 reproducible random bit mutations exercise the parser; add sustained
  coverage-guided fuzzing and resource-limit / timeout testing.
- There is no full consensus/script interpreter or Bitcoin Core integration,
  and no independent audit. Previous transaction inclusion/unspent status
  is not verified by the offline signer.
- Only P2WPKH / BIP84 testnet derivations within the initial search window
  are supported. Some valid external-wallet PSBTs are intentionally rejected.
- Never use a genuine secret in CI, Devspace, or another networked machine.
