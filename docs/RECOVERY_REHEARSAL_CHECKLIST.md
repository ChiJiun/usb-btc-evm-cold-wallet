# Issue #5 — Recovery rehearsal and Vault fault checklist

Scope: disposable **public, compromised BIP39 vector** only. Do not use a funded
seed, personal mnemonic, actual USB, real cold vault, or any externally supplied path.
This checklist does not authorize mainnet use.

## Automated rehearsal (Linux test environment)

```bash
python -m pytest -q tests/test_recovery_fault_rehearsal.py tests/test_recovery_exchange.py tests/test_policy_atomic.py
```

The new tests use pytest-private temporary directories; they never find or
open mounted USB devices. Included exercises:

| Area | Expected result |
| --- | --- |
| Published BIP39 128-bit zero-entropy mnemonic + `TREZOR` passphrase | Full 64-byte seed, independent PBKDF2 and SHA-256 of the published BIP32 master xprv match the pinned Trezor vector |
| Recovery with BIP39 passphrase | First BTC testnet address, Sepolia address, BIP84 account tpub, derivation metadata, master fingerprint, policy wallet binding identical |
| Wrong checksum, mnemonic, BIP39 passphrase, Bitcoin network, BIP84 account/index or independently recorded address | Refuse restore; no final vault created |
| Lost disposable vault, restored from public words | Recover exactly; newly encrypted bytes differ; repeated restore never overwrites |
| Wrong vault encryption password, invalid format/version, malformed or duplicate JSON metadata, non-finite or boolean header values, one-bit ciphertext/salt/nonce tampering, truncated/oversized JSON, symlink or missing Vault | Refuse load; never silently return another wallet |
| Hostile FIFO substituted for Vault path | Reject the non-regular file without blocking on open; keep the original Vault untouched |
| Simulated file `fsync` failure before publish or nonprivate directory | No partial final vault; retry works after injected failure removed; unsafe directory rejected before staging |
| Staging filename replaced by another inode | Injected rename definitely occurs; writer raises, published attacker entry cannot decrypt (same-UID race remains outside trust model) |
| Whole historical authenticated Vault snapshot restored | **Accepted by decryption**: negative evidence that AEAD alone cannot detect replay |
| Historical authenticated Policy restored | Without independent current SHA, load succeeds; with separately retained current SHA, reject |
| Policy bound to another HD wallet | Reject |
| Rehearsal error output | No test mnemonic or encryption password in messages |

The official oracle comes from
[Trezor python-mnemonic `vectors.json` at commit `b57a5ad77a981e743f4167ab2f7927a55c1e82a8`](https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json)
(English vector 0). This test stores only the published full seed and a SHA-256
of the published master xprv. Neither is a live wallet credential.

Recovery's external identity arguments contain BTC and EVM addresses, but
an EVM address does not encode its chain ID. The watch-only metadata is
checked for Sepolia (11155111); a different EVM network using the same
address cannot be rejected by the paper-address check alone. Production
transaction chain validation remains a separate mandatory boundary.

For write interruption after publication (directory fsync failure), interrupted
file writes, and destination no-overwrite races, also see
`tests/test_recovery_exchange.py` and `tests/test_policy_atomic.py`.
These are deterministic fault injections, **not physical power-cut durability
tests**, and do not simulate flash controller behavior.

## Real single-USB acceptance checklist (NOT TESTED in this PR)

Use only a USB explicitly identified as the expendable test device and a
published test seed. Record nonsecret evidence outside the device, under a
new test-run identifier; never record the mnemonic, BIP39 passphrase,
vault encryption password, plaintext wallet state, private keys, or USB
memory dumps. Treat account tpub and addresses as privacy-sensitive;
prefer redacted hashes in artifacts. Never put secrets in environment
variables, test logs, workflow artifacts or the Windows companion.

- [ ] Record exact image SHA-256 and commit, USB model/capacity/physical-drive
      identification, UEFI firmware mode, offline policy, date and scenario ID.
- [ ] Confirm the offline environment is network-disabled and swap-disabled;
      verify Vault mount identity/permissions and never point the disposable
      test at an existing user Vault.
- [ ] Independently record test-vector BTC **testnet** receive address,
      Sepolia (chain ID 11155111) address, master fingerprint, BIP84 account
      tpub hash and public policy wallet binding **before** simulated loss.
- [ ] Create test-only Vault; perform encrypted backup/recovery rehearsal.
      Compare all public identities and a bounded watch-only export.
- [ ] Attempt invalid checksum, different valid mnemonic, incorrect BIP39
      passphrase, incorrect recorded address and wrong encryption password;
      each must fail without publishing a replacement Vault.
- [ ] Corrupt/truncate disposable copies and change format/version; verify
      fail-closed. Existing final vault must remain byte-for-byte unchanged.
- [ ] Simulate loss **only on disposable Vault**, restore to a new path and
      attempt recovery into an existing path; verify no overwrite.
- [ ] On expendable media only, inject removal/power failure before and after
      stage/publish boundaries. Record whether complete final file exists,
      temporary partials remain, and if manual intervention is needed.
      Unknown durability = BLOCKED; do not mark PASS based on QEMU tests.
- [ ] Substitute staged/final files and replay historical valid snapshots.
      Record detection limits explicitly. Do not use those files for signing.
- [ ] Update test policy, retain its new SHA-256 externally, replay an older
      valid encrypted policy; verify mismatch against the **external** digest.
- [ ] Verify no secret appears in shell history, console captures, Windows
      transfer partition, artifacts, exception text or collected evidence.
- [ ] Power down, retain redacted signed-off test result. Clean up only the
      known disposable fixture through explicit operator action.

## Security findings and acceptance boundaries

**Finding R-01 (High, design/operational gap):** A valid historical encrypted
Vault remains decryptable after rollback. AES-GCM detects ciphertext tampering
but supplies no freshness guarantee. An attacker who can rewrite ordinary USB
storage can restore a previously valid snapshot. A separately trusted,
monotonic state anchor is required for general rollback resistance; no such
anchor is established by these tests. Do **not** claim universal rollback
detection from file hashes, encryption, or secure boot alone.

**Finding R-02 (conditional):** Policy rollback is detectable *only* when the
current expected digest is held independently of the attacker-controlled
storage and checked on load/sign. If the digest is read from the same
rewritable USB, old policy plus old digest can both be restored.

**Finding R-03 (hardware evidence gap):** Linux rename, fsync, fault-injection
and CI results do not establish physical removable-FAT32 power-loss
durability or resistance to concurrent same-UID/root modification. Physical
USB acceptance remains BLOCKED until separately performed.

Secrets are intentionally present **only in in-process test fixtures** during
these tests. They are published compromised vectors, not production keys.
This PR minimally hardens `vault.load_vault` and `vault.decrypt_mnemonic`: one
bounded descriptor read (no pathname second-read race), no symlink following,
strict JSON keys/types and rejection of duplicate/non-finite fields. There is no
on-disk format change, cryptographic primitive change, Policy or signer change.
These checks detect malformed metadata; they do not detect replay of a complete,
valid historical Vault, or replacement by another valid Vault that uses the same
decryption password. Independently verify the intended wallet identity and
policy anchor on signing.
