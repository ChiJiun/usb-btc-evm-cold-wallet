# Bitcoin PSBT v0 validation (Issue #2)

**Research prototype; Bitcoin testnet only. Mainnet signing remains disabled.**

The offline signer accepts only a PSBT v0 with 1–20 native BIP84 testnet
P2WPKH inputs and one payment output, optionally one change output. The
embedded Bitcoin transaction must use transaction version 2, locktime 0, and
final (`0xffffffff`) input sequences; RBF and relative/absolute locktime
semantics remain disabled until the offline review UI can approve them
explicitly.

It rejects unknown metadata, preexisting signatures, unsupported scripts,
duplicate outpoints, and extra data after the serialized PSBT. Before the
library parser runs, every raw PSBT map is checked for duplicate keys and
PSBTv2 transaction-construction fields that BIP370 requires to be excluded
from PSBTv0. The raw global unsigned transaction is checked for canonical
serialization and the BIP174 requirement that every scriptSig and witness is
empty. After `embit` parses the PSBT, the reconstructed unsigned transaction
must serialize byte-for-byte identically to that raw global transaction. This
prevents parser normalization or mixed-version fields from changing what the
signer actually signs. Base64 input is limited to 200 KB decoded.

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

## External vector provenance

Regression fixtures are vendored in `tests/fixtures/external_psbt_vectors.json`
so tests do not require network access. They are pinned to:

- Bitcoin Core `bitcoin/bitcoin@e211dd0186e9646167d063a16f0da88e5f72e05f`,
  from `test/functional/data/rpc_psbt.json` and `src/test/psbt_tests.cpp`.
- Sparrow's Bitcoin library
  `sparrowwallet/drongo@f5a0b36b1ff953cf40b32d5fc2a8083ae69fec3f`,
  from `src/test/java/com/sparrowwallet/drongo/psbt/PSBTTest.java`.

The shared BIP174 v0 fixture is parsed and checked against its independently
recorded txid/output values. A shared invalid fixture with scriptSig data in
the unsigned transaction must fail closed, and a Bitcoin Core PSBT v2 fixture
confirms the explicit v0-only gate. Regression tests additionally inject the
BIP370 v2-only global (`0x02`–`0x06`), input (`0x0e`–`0x12`), and output
(`0x03`, `0x04`) transaction-construction fields into otherwise valid v0 maps;
all such mixed-version payloads must fail closed.

BIP370 reference: https://bips.dev/370/

In addition to 250 reproducible bit mutations, Hypothesis exercises the fee
boundary and 300 arbitrary binary parser inputs per run. Parser failures must
be normalized to `ValueError`.

## Limitations / next security work

- The external fixtures validate parser interoperability and fail-closed
  behavior, but there is not yet an independently generated Core/Sparrow
  **BIP84 P2WPKH end-to-end signing fixture** tied to this test wallet.
- Add sustained coverage-guided fuzzing plus explicit resource-limit/timeout
  campaigns beyond the bounded Hypothesis corpus.
- There is no full consensus/script interpreter or Bitcoin Core integration,
  and no independent audit. Previous transaction inclusion/unspent status
  is not verified by the offline signer.
- Only P2WPKH / BIP84 testnet derivations within the initial search window
  are supported. Some valid external-wallet PSBTs are intentionally rejected.
- Never use a genuine secret in CI, Devspace, or another networked machine.
