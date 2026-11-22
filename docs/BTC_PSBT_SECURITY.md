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

## Additional independent signature validation and bounded fuzzing (#2)

`tests/test_btc_independent_bip143.py` re-computes the native P2WPKH
BIP143 `SIGHASH_ALL` preimage with Python `hashlib` and verifies the DER
signature using `cryptography`'s independent secp256k1 ECDSA implementation.
It independently binds the signed PSBT's non-witness transaction TXID and
indexed prevout to the spending outpoint, requires identical witness UTXO value
and script, validates P2WPKH ScriptPubKey = `0x0014 || HASH160(witness_pubkey)`,
and requires exact signed-PSBT partial-signature bytes to match the finalized
witness. It checks the 1000-satoshi fee and rejects changed prevout values,
recipient amounts, scripts, public keys, and substituted witness/PSBT signatures. This is a **locally generated public-mnemonic** vector, not
a Bitcoin Core/Sparrow independently generated fixture.

The coverage-guided `tools/fuzz_btc_psbt.py` mutates a public PSBT seed with
byte flips, splices, inserts/deletions and hostile CompactSize-like bytes.
It retains inputs exposing previously unseen Python lines in `btc.py` and
exercises `_read_psbt` plus the wallet-specific offline review policy. Every
campaign **first executes the unmodified public valid PSBT** and fails if its
full offline review is rejected. Additional parse-valid policy-denial seeds
exercise unsupported `SIGHASH` types and unexpected input metadata. The JSON report separately
counts `parser_accepted`, `parser_rejected`, `policy_accepted`, and
`policy_rejected`; `baseline_policy_accepted` is an explicit success gate.
The `cases` count includes initial seeds. Trace state is restored after every
case, including unexpected exceptions. The corpus and input buffers are bounded,
uncaught exceptions cause non-zero exit, and seed/cases/covered lines/crashes
are included in the report.

Reproduce a local short run (only public test keys):

```bash
python tools/fuzz_btc_psbt.py --seconds 30 --seed 20261121 --max-cases 20000
```

`.github/workflows/btc-psbt-fuzz.yml` defines a **separate optional weekly
and manually dispatched** GitHub-hosted 180-second campaign. It uses pinned
hash-locked dependencies, records the Actions run ID as deterministic seed,
and uploads logs/crash inputs (if any) for triage. Its scheduled execution
starts only after the workflow is merged to the default branch. This is
coverage-guided mutation by Python tracing, not LLVM/AFL edge coverage; it
cannot substantiate claims of exhaustive security fuzzing or stable RSS across
platforms. Keep reproducible crash samples with a regression test before
claiming the Issue's long-running fuzz acceptance is complete.

## Limitations / next security work

- The Core 30.4 independently generated regtest BIP84 P2WPKH E2E fixture
  in `tests/fixtures/bitcoin_core_bip84_regtest_e2e.json` tests a public
  testnet-coin-type key. Regtest address prefixes differ from Bitcoin testnet,
  but the underlying P2WPKH output scripts and BIP143 rules are identical.
- Add sustained coverage-guided fuzzing plus explicit resource-limit/timeout
  campaigns beyond the bounded Hypothesis corpus.
- There is no full consensus/script interpreter or Bitcoin Core integration,
  and no independent audit. Previous transaction inclusion/unspent status
  is not verified by the offline signer.
- Only P2WPKH / BIP84 testnet derivations within the initial search window
  are supported. Some valid external-wallet PSBTs are intentionally rejected.
- Never use a genuine secret in CI, Devspace, or another networked machine.


## Support matrix (current testnet prototype)

| Capability | Status | Enforced boundary |
| --- | --- | --- |
| Bitcoin testnet, BIP84 native P2WPKH | Supported | `m/84'/1'/0'/{0,1}/index`, index < 100 |
| PSBT v0 / BIP174 | Supported | Canonical unsigned transaction; 1–20 inputs, 1–2 outputs; <= 200,000 decoded bytes |
| Both witness UTXO and full non-witness UTXO | Required | TXID, referenced vout, script and satoshis must match |
| BIP143 SIGHASH_ALL | Supported | Exact signature and output/fee policy before export |
| BTC mainnet, PSBT v2 / BIP370 | Rejected | No mainnet or mixed PSBTv2 transaction-construction fields |
| RBF, relative locktime, absolute locktime | Rejected | `sequence=0xffffffff`, `locktime=0`, transaction version 2 |
| Taproot, P2SH, P2WSH, multisig, arbitrary metadata | Rejected | No blind signing or unsupported scripts |
| External consensus/U​TXO inclusion proof | Not implemented | Cold signer checks provided prevout consistency only |

## Bounded fuzz campaign and replay (Issue #2)

The Linux workflow uses `ulimit -v 786432` (768 MiB process virtual memory),
a 12-minute GitHub job watchdog, a 180-second mutation deadline, and a
250-millisecond per-case POSIX timer. Timeout failures are raised outside
the parser's normal `ValueError` boundary and saved as crash artifacts.
The report records random seed, accepted/rejected parser and policy cases,
coverage line count, maximum payload length, per-case timeout enforcement,
peak Linux RSS (KiB), replayed corpus count, and crash hashes. Linux
`ru_maxrss` is a measurement, not a replacement for the address-space cap.

```bash
python tools/fuzz_btc_psbt.py --seconds 180 --max-cases 50000 \
  --seed 20261122 --case-timeout-ms 250 \
  --replay-dir tests/fixtures/btc_psbt_crashes \
  --artifact-dir btc-psbt-crashes
```

Any unexpected exception, elapsed per-case timer or failed replay returns
non-zero and retains the exact byte payload. Preserve the SHA256-named sample
under `tests/fixtures/btc_psbt_crashes/` after triage and add a behavioral
regression. The optional workflow can only substantiate the runs actually
executed; its schedule alone is not evidence of a sustained clean campaign.

## Independent Bitcoin Core BIP84 E2E fixture

`tests/fixtures/bitcoin_core_bip84_regtest_e2e.json` is a **pinned test
fixture** generated by Bitcoin Core 30.4.0 in a disposable regtest node using
only the public BIP39 mnemonic. Core generated the funding coinbase transaction
and the **unsigned PSBT v0** with `createpsbt`. The fixture generator
`tools/generate_core_bip84_psbt_e2e.py` adds the required full non-witness
UTXO, witness UTXO and BIP32 origin from the Core-produced prevout and
public seed. The unchanged hardened offline signer signs the transaction,
then **Bitcoin Core independently** `finalizepsbt` extracts the signed
transaction and `decoderawtransaction` reports TXID and wTXID.

`tests/test_btc_core_e2e_fixture.py` locks that Core TXID and wTXID oracle,
validates the input/output/fee/recipient/change policy, reproduces cold
signing and checks BIP143 with independent SHA256d + cryptography ECDSA.
Malformed / replaced recipient, change, fee, RBF and locktime fail closed.

- Core version: `/Satoshi:30.4.0/`
- Container image manifest digest: `sha256:ca69e5a5e316cdde3334b277caff687dd07b8c322f208063aa29a976132fca34`
- Enriched PSBT SHA256: `24573a87dc2dac3611e9d076dd4fbe9491e1e0ba7f069c8d5ce681fe18b95aab`
- Core-decoded TXID: `65eb7d659ec5d6fc701a0c4ca3e5187c0dc9094b004649c98853bb03136aaf75`
- [Successful upstream Core E2E Actions run](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44927145029), [fixture artifact](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44927145029/artifacts/14716610986)

Reproduce using the pinned `.github/workflows/btc-core-e2e.yml` workflow,
which starts the isolated Core container and runs the fixture generator.
Core creates the raw PSBT and produces the independent TXID oracle; embit is
only used to populate policy-required PSBT metadata. The fixture is
testnet-coin-type/BIP84 compatible but its on-chain funding is **regtest**
only. This E2E verifies cryptographic and structural interoperability, not
public-testnet UTXO inclusion or real-USB operation.
