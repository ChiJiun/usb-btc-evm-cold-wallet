# Recovery rehearsal and untrusted USB exchange (Issue #5)

> **Only Bitcoin testnet and Ethereum Sepolia. Unreviewed prototype; never use
> real funds.** Run real paper recovery only on a **trusted physically offline**
> computer, not on a connected developer VM. No GUI, touchscreen or hardware
> secure confirmation exists. The CLI renders human-readable network, recipient,
> amount and fee; confirmation is typed on the offline host.

## Recovery from PAPER (offline host ONLY)

1. Before testing, independently write down BOTH the first BIP84 Bitcoin
   **testnet** receiving address and the Sepolia EVM address. These are
   comparison references, not secret backup material. Protect the paper
   mnemonic and **optional BIP39 passphrase** separately.
2. On a trusted offline Live Linux host, with no production wallet already at
   the destination path, run:
   ```bash
   usb-cold-wallet --vault /offline/new-restored.vault recover \
     --offline-ack --i-have-paper-backup \
     --expected-btc tb1qYOUR_PREVIOUSLY_RECORDED_TESTNET_ADDRESS \
     --expected-evm 0xYOUR_PREVIOUSLY_RECORDED_SEPOLIA_ADDRESS
   ```
3. Enter the paper words through hidden terminal input (they do not appear
   on screen), optional BIP39 passphrase and a **new encryption passphrase**
   of at least 12 characters. Approve `RESTORE TESTNET WALLET` on the
   offline terminal. Both derived public addresses must match the
   independently saved references **before** a vault is written.
4. The destination vault is created with mode 0600 and **never overwritten**.
   If it exists, stop and choose another destination. No "force recovery" or
   destructive user-vault operation exists. Restore does **not** regenerate
   or store your optional BIP39 passphrase.

### Destructive rehearsal using compromised test vector

```bash
usb-cold-wallet rehearse-recovery
```

This uses the publicly known, **compromised** `abandon` × 11 + `about`
mnemonic in a newly created disposable temporary directory; it encrypts,
decrypts, deletes the *test-only* encrypted vault, restores from that test
mnemonic and verifies recovered contents. It never reads or modifies any
user-specified vault. **Never send funds to this seed.** Deletion of a file
is not cryptographic secure erasure of flash media.

## USB exchange format: corruption detection, not authentication

`pack-request` is safe for use on an online host **only for public/unsigned
content**. It wraps JSON or base64 PSBT in an envelope:

```json
{
  "format": "usb-cold-wallet-exchange",
  "version": 1,
  "kind": "evm-request",
  "network": "sepolia",
  "payload": {"chainId": 11155111, "type": 2},
  "sha256": "<64 hex digits of canonical JSON without sha256>"
}
```

The digest covers `format`, `version`, `kind`, `network`, and
`payload` using sorted-key compact ASCII JSON. It detects unintentional
corruption. **A malicious online computer or USB can change the payload and
recompute the digest**, so the checksum conveys **zero sender authenticity**.

Supported kinds: `btc-request`/`btc-signed` (`bitcoin-testnet`),
`evm-request`/`evm-signed` (`sepolia`), and `watch-only`
(`testnet-sepolia`). The parser bounds input size, rejects duplicate
JSON keys, extra envelope fields, nonfinite JSON values, wrong network,
mismatched kind and sensitive key names (mnemonic, seed, private_key,
passphrase, vault, etc.). **All payload kinds are also strictly allowlisted**:
EVM requests require explicit native Sepolia type-2 transfer fields; EVM signed
outputs require exact metadata reproduced from independently decoded/recovered
signed raw bytes; signed Bitcoin outputs must be genuine PSBT v0 P2WPKH with
matching signatures, final witnesses, recipient/fee; and watch-only fields have
bounded, type-checked nested schema, canonical Bitcoin addresses derived from
the account tpub, checksum EVM address and optional eight-hex-digit master
fingerprint. Arbitrary comments, strings, nested extras, or disguised secret
values under innocent keys are **not permitted**. Valid public key materials
and addresses are still privacy-sensitive even though they are not signing
secrets. Exchange reads are limited to regular files, refuse symbolic links,
and validate a **single bounded read** to avoid inspecting metadata from a
different file than the payload just checked. The online request packer also
enforces bounded input size and duplicate-key rejection. A `btc-request`
passes strict PSBT v0 framing checks before `inspect-transfer` succeeds;
its transaction is **not** thereby independently approved for signing.
The Bitcoin account tpub must be a testnet public account at depth 3 with
account child index `0'`, consistent with the declared BIP84 path.

**Important for `btc-signed`:** standalone `verify` / `inspect-transfer`
checks envelope structure, cryptographic signatures, PSBT/UTXO consistency,
recipient, fee, and the finalized witnesses. It **cannot prove that a second
P2WPKH output is the intended wallet change**, because this standalone
validator has neither the unlocked wallet root nor a trusted approved
unsigned request. The command now prints
`standalone_check_does_not_authorize_broadcast=true`; for BTC signed results,
`btc_change_not_bound_to_approved_request=true` is also printed.
**Never broadcast solely because `inspect-transfer` passes.** The online
companion or broadcaster MUST retain the originally approved unsigned PSBT
and compare the complete unsigned transaction, every input, every output,
change script/index and amounts against that trusted pending request before
allowing an explicit user-confirmed broadcast (as in PR #26). If there is no
trusted pending request, reject rather than infer change ownership.

Prepare an unsigned request on online PC:

```bash
usb-cold-wallet pack-request --kind evm-request \
  --input unsigned-sepolia.json --out /transport/unsigned-envelope.json
usb-cold-wallet inspect-transfer --input /transport/unsigned-envelope.json
```

After moving the **transport** USB to the offline computer, create an encrypted
`<vault>.policy` once using `usb-cold-wallet --vault /offline/wallet.vault policy
--file /offline/wallet.vault.policy --action init`. Record the displayed
policy SHA-256 independently on paper and supply it at every signing. Sign
only after independently verifying recipient, amount and the current policy
hash (see [offline policy](OFFLINE_POLICY.md)):

```bash
usb-cold-wallet --vault /offline/wallet.vault sign-evm \
  --request /transport/unsigned-envelope.json \
  --to 0x000000000000000000000000000000000000dEaD \
  --wei 1000000000000 \
  --expected-policy-sha256 INDEPENDENT_CURRENT_POLICY_SHA256 \
  --out /transport/signed-envelope.json
```

For Bitcoin testnet use `pack-request --kind btc-request --input unsigned.psbt`
followed by `sign-btc --request ... --to tb1... --sats ... --max-fee-sats
... --change-index 0 --expected-policy-sha256 CURRENT_HASH --out ...`.
A missing or mismatched external policy SHA-256 fails closed. All recipient/amount/fee policies still
run *after* envelope validation. Signing via legacy `--psbt` or `--tx`
remains available but emits plain JSON; **both legacy inputs are now single-read,
size-bounded, non-symlink regular files**, EVM JSON checks duplicate properties
and NaN, and invalid USB inputs are rejected **before unlocking the vault**.
`--request` emits integrity-checked signed envelopes. The bootable Live USB
appliance (#9) must be separately updated to prefer envelopes over the legacy
entrypoints; that integration is **not** proven by this CLI change.

Export public watch-only data on the offline host:

```bash
usb-cold-wallet --vault /offline/wallet.vault export-watch-only \
  --count 3 --out /transport/watch-only.json
```

On the online PC (no vault, mnemonic or signing dependencies to unlock):

```bash
usb-cold-wallet show-watch-only --input /transport/watch-only.json
```

This exposes only testnet Bitcoin account tpub, receiving addresses, EVM
Sepolia address and derivation metadata. Account tpub **is public key
material but can compromise transaction privacy**; share sparingly and
avoid publishing it. A watch-only file cannot prove on-chain balances or
transaction inclusion. No RPC or network backend is implemented.

## Threat model and failure handling

- **Untrusted USB / BadUSB:** A removable drive can deliver malformed
  payloads, binaries, malicious HID input or storage-controller attacks.
  Only copy **data files**, never run software off transport media. Prefer
  physically separate readonly media / QR transport where available; mount
  `noexec,nodev,nosuid` when appropriate. Checksums cannot defeat a
  re-signed malicious request; human review with an independent source is
  required.
- **Host RAM / malware:** BIP39 mnemonic, passphrase and derived signing
  keys exist in Python process memory during recovery/signing. A compromised
  OS, DMA/peripheral, firmware, swap or cold-boot attacker may extract them.
  Python cannot guarantee reliable zeroization. Power down the offline host
  after use; disable network and swap at OS level (see Live USB work).
- **Lost or incorrect backup:** An optional BIP39 passphrase creates a
  *different* wallet. Incorrect mnemonic checksum or mismatched independent
  references aborts recovery before writing. Keep separately verified paper
  and metal backups where appropriate.
- **Crashes, full disk and filesystem failures:** Create-only writes avoid
  silent overwrite, but a crash during writing can leave an incomplete file.
  A corrupted partial destination must be manually inspected and **moved
  aside**, not reused. The prototype does not implement fsync/atomic
  durability guarantees or secure deletion.
- **Network confusion:** Every signing screen labels **BITCOIN TESTNET**
  or **ETHEREUM SEPOLIA (11155111)**. Mainnet signing is deliberately
  disabled. Do not assume the USB data originates from the chain claimed.

## Acceptance scope

Automated tests cover public-vector delete/recreate rehearsal, recovery
address mismatch and no-overwrite, network and digest tampering, oversized
and malformed exchange files, duplicate JSON keys, secret-field blocking,
watch-only viewing, and a full Sepolia signed-envelope roundtrip. They do
**not** substitute for actual air-gap hardware, hardware screen/keys,
external wallet interoperability, penetration testing, or audit.
