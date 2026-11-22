# Issues #5 / #21 / #24 / #82 — independent acceptance evidence

Baseline: `main` `fa66ecf2d5ea213a2fe5a640c57dd671cef967b6` (2026-11-22).
These tests are independent of Draft PR #81. Only public, compromised test seeds
are permitted. Never run fault injection on a user Vault or real-money keys.

## Reproduction and decision

```bash
python -m pytest -q tests/test_btc_core_replay_acceptance.py tests/test_btc_core_e2e_fixture.py tests/test_btc_external_vectors.py tests/test_btc_fuzz_campaign_gates.py tests/test_policy_security.py tests/test_cross_boot_state.py
python tools/fuzz_btc_psbt.py --seconds 180 --max-cases 50000 --seed 20261122 --case-timeout-ms 250 --replay-dir tests/fixtures/btc_psbt_crashes --artifact-dir /tmp/btc-psbt-public-crashes
```

Run the hash-locked `.github/workflows/btc-core-e2e.yml` in Actions for an
actual Bitcoin Core 30.4 regtest container. See the pinned fixture
`tests/fixtures/bitcoin_core_bip84_regtest_e2e.json`: Core-origin unsigned
PSBT, enriched with the wallet-required witness/non-witness UTXO and BIP32
origin, offline-signed, Core-finalized and independently decoded TXID/wTXID.
The new integration test covers Core oracle -> v2 request -> offline Policy
-> cold ReplayLedger -> signed response -> online verified import. It never
broadcasts or asserts physical transfer.

| Gate | Current evidence / status | Remaining action |
| --- | --- | --- |
| Bitcoin Core BIP84 PSBT v0 sign/finalize/extract | Existing pinned Core 30.4 regtest source run 44927145029; new in-repo cross-module regression **pending exact-HEAD CI** | Re-run Core workflow on integrated HEAD |
| Sparrow-generated BIP84 P2WPKH PSBT sign/finalize | **NOT TESTED**; existing shared BIP174 Sparrow/Core parser fixture is incompatible with this wallet's BIP84 signing policy | Generate Sparrow testnet BIP84 PSBT with public test seed, record Sparrow/Drongo version and full unsigned PSBT hash, sign offline, verify independently and record TXID; do not relabel shared parser fixture as E2E |
| Coverage-guided PSBT fuzz | Bounded Python line-feedback runner and weekly/manual CI workflow exist; **no new run claimed here** | Record exact run, seed, cases, crashes, duration and RSS; preserve sanitized crash SHA corpus |
| Policy fee and recipient review | New policy-vs-Core fixture assertion; existing policy and GUI tests | Run on integrated GUI with offline independent full address confirmation |
| BIP39/Vault missing/corrupted/truncated/power-cut | Draft PR #81 has separate public-vector and fault-injection tests | Verify #81 exact HEAD and later integrated SHA; physical FAT32 removal remains **BLOCKED** |
| Whole-store history rollback | New cold-ledger negative control: old valid state reloads without trusted anchor; externally pinned expected tip rejects | **BLOCKED** until independent trusted monotonic anchor and checked lifecycle exist |
| USB-A + USB-B Windows/UEFI E2E and manual broadcast | **BLOCKED** (no physical result from this PR) | Run #24/#43 acceptance with exact image SHA and equipment record |

## True rollback boundary

File hashes, AEAD tags, append-only naming, FAT32 filesystem flags, and
journal hashes only detect changes relative to a trusted reference. A hostile
Windows machine with raw USB access can restore *all* files and their hashes.
The expected policy SHA or journal tip must be preserved independently of
the rewritable USB and checked before permitting any new signing. If an
independent current anchor is missing, the integrated cold signer must
**fail closed**; this PR does not claim that the existing API wiring already
implements that boundary. Do not merge/release based on a successful
negative-control demonstration.

## Physical fault and interoperability evidence (no implied PASS)

Use a disposable USB, a compromised public BIP39 fixture, and never test
against a funded wallet. Record at minimum `case_id`, `expected`,
`actual`, `status` (PASS/FAIL/BLOCKED/NOT_TESTED), `main_sha`,
`pr_head_sha`, `image_sha256`, `usb_a_id`, `usb_b_id`,
`uefi_model`, `core_version`, `sparrow_version`, `fuzz_seed`,
`ci_url`, `artifact_sha256`, `timestamp_utc`, and a scrubbed evidence path.
No mnemonic, private key, signed mainnet transaction or passphrase in logs.

For physical testing, power off or remove USB-B during a deliberately
disposable transfer and inspect only the resulting nonsensitive exchange
state. Repeat with a truncated request, recomputed-hash wrong chain/account,
changed recipient/fee, replayed signed response, old fully valid Policy/Vault,
and a reverted cold ReplayLedger plus any USB-local digest. Record fail-close
on actual BIOS/UEFI hardware separately from mock fsync exceptions, Linux
temporary files, QEMU and ordinary CI. Stop if an independent trusted tip is
not available. Do not declare Sparrow E2E or physical USB tests PASS without
corresponding artifacts.

## Scope limits

No signer or Vault rewrite; no real USB access; no release/mainnet permission.
The new test changes a malformed-journal metadata parser boundary only.
Issue #5 recovery fault work remains on PR #81 and must be reviewed at
its own exact SHA.
