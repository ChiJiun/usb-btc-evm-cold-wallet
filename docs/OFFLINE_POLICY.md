# Offline transaction policy (Issue #21, Phase 1)

**Scope:** Experimental Sepolia native ETH transfers and Bitcoin testnet BIP84 PSBT. Never use with real funds. This is an additional review/deny mechanism and **never** an automatic signer. The existing chain-specific hard validation and an explicit human `SIGN` confirmation always run independently. Unverified recipients require a second confirmation and full-address display.

## Bootstrap

On the physically offline signer, after creating `wallet.vault` and its paper seed backup:

```sh
usb-cold-wallet --vault /mnt/cold-vault/wallet.vault policy \
  --file /mnt/cold-vault/wallet.vault.policy --action init
```

An encrypted policy profile is **required** for signing. A missing, corrupted, wrong-wallet or unknown-version policy fails closed; it does not silently revert to defaults. The profile must be stored at `<vault>.policy` beside the encrypted vault (USB-A), not on the transaction transport USB (USB-B). Each operation unlocks the wallet and the policy, and modifying a profile requires separate typed confirmation. The policy parent directory must be owned by the offline signer user, without group/world write permissions (use a private mount/ownership configuration, including for FAT32).

```sh
usb-cold-wallet --vault /mnt/cold-vault/wallet.vault policy \
  --file /mnt/cold-vault/wallet.vault.policy --action set-limit \
  --field evm_max_fee_wei --value 1000000000000000

usb-cold-wallet --vault /mnt/cold-vault/wallet.vault policy \
  --file /mnt/cold-vault/wallet.vault.policy --action verify-address \
  --network sepolia --address 0x000000000000000000000000000000000000dEaD \
  --label "My test address"
```

Every `policy init`, `set-limit`, and `verify-address` action prints a **new encrypted policy SHA-256**. After every change, record that exact value on **separate trusted paper/metal storage**; the previously recorded digest becomes obsolete. Never fetch the expected hash from USB-A/USB-B while signing. The command refuses to sign if the current independently supplied digest differs.

The `verify-address` command prints the **full canonical address** and requires it to be re-entered from an independently trusted source on the offline machine. Names, token symbols, ABI, labels, chain RPC metadata and decimals received from an online companion are untrusted and cannot populate the verified address book. A verified label reduces recognition effort but never hides the address nor permits automatic signing.

Signing commands first size-bound and parse the unsigned USB request before unlocking the vault, then automatically load `<vault>.policy`. An arbitrary `--policy` path is refused. A missing profile or missing independent `--expected-policy-sha256` anchor is a signing error, even if the default parameters would have allowed the transaction. The original `--to`, `--wei`, `--max-fee-sats`, and change-index confirmations and review rules remain active.

## Trust boundaries and caps

Versioned `TransactionIntent` is built from **already validated** Bitcoin/EVM unsigned inputs, not labels supplied by the online host. A separate `PolicyDecision` is `ALLOW_FOR_REVIEW`, `REQUIRE_EXTRA_CONFIRMATION`, or `DENY`.

- **EVM Sepolia:** strict type-2, chain 11155111, 21,000 gas, native transfer, no calldata, no access list. Intent displays account, full recipient, nonce, amount, gas, maxFeePerGas, maxPriorityFeePerGas, maximum fee and maximum total. Policy caps amount/fee. Unknown smart-contract calls, ERC-20 approvals, Permit/Permit2 and blind EIP-712 signing are **not implemented and refused** by the underlying signer. Never trust online gas estimation as verified on-chain state.
- **BTC testnet:** strict existing core PSBT output/change and fee checks remain mandatory. Policy also caps absolute fee and a **conservative upper bound** on sats/vbyte, calculated using the stripped unsigned transaction byte length (which is no greater than the final virtual size). This rejects some legitimate high-fee transactions rather than underestimating the fee rate. The prototype does not independently know the UTXO set or current fee market.
- An unrecognized recipient triggers extra human confirmation; verified entries remain tied to this wallet and chain. They do not grant any right to sign without user action.

## Storage, restoration, and limitations

Policy writes stage **encrypted ciphertext only** in the policy directory, fsync the stage, verify the staged inode, publish using a pinned parent-directory descriptor, and fsync that directory. Create-only updates use Linux `renameat2(RENAME_NOREPLACE)` so another file is never silently overwritten; explicit policy edits use replacement and require a newly recorded external trusted SHA-256. A write/rename failure before publication preserves the old profile, while failure at the final directory fsync leaves durability **uncertain**: re-read the final file and independently reconcile the new hash before using it. Policy replacement additionally requires the prior encrypted-file SHA-256 for an in-lock compare-and-swap check; stale concurrent editors fail without overwriting another update. The directory must be owned by the effective user and not group/world writable; cooperating editors serialize using an advisory directory lock. A compromised process sharing the same UID, or an uncooperative writer with filesystem access, remains outside this boundary and can still swap named files between validation and rename. This does not provide transactional updates of the external paper anchor, nor automatic anti-rollback. The media must support these Linux filesystem semantics; physical power-loss tests remain necessary.

The profile is encrypted with AES-256-GCM, its own random salt/nonce and scrypt KDF, and fixed domain-separating AAD. It is bound to the public wallet identity, rejecting accidental restore into another wallet. Reading now uses a single size-bounded, no-symlink regular-file descriptor with strict JSON duplicate-key and NaN rejection. Only canonical BIP84 testnet recipients and display-safe normalized address labels are accepted. Never put this file or its passphrase on USB-B. Back up the encrypted policy alongside the encrypted wallet file on trusted offline storage. Losing the policy locks the CLI signer until the user deliberately initializes a new profile; **a new profile does not restore old trusted labels or caps**. The wallet's BIP39 recovery is separate and does not automatically recover this address book. The policy format is version 1; unknown versions fail closed.

### Required offline rollback anchor (manual)

An encrypted profile can be replaced with an older, still-valid ciphertext. To
**detect replacement relative to a separately retained known-good copy**, after
creating or changing the policy, calculate its SHA-256 **on the trusted offline
machine** and record the entire 64-character lowercase value on separate
paper/metal or other independently protected medium:

```sh
sha256sum /mnt/cold-vault/wallet.vault.policy
```

For every signing, pass the independently obtained hash using
`--expected-policy-sha256 64_HEX_CHARACTERS` to `sign-evm` or `sign-btc`.
Example (use the newly recorded value, never the example placeholder):

```sh
usb-cold-wallet --vault /mnt/cold-vault/wallet.vault sign-evm \
  --tx /mnt/transfer/unsigned.json \
  --to 0x000000000000000000000000000000000000dEaD \
  --wei 1000000000000 \
  --expected-policy-sha256 64_HEX_CHARACTERS \
  --out /mnt/transfer/signed.json
```
The signer compares the bytes read **once** from the policy file against the
expected digest **before decrypting** or approving/signing. An old copy, an
unauthorized policy change, or a typo fails closed. Refresh the independently
stored digest **after each authorized policy update**.

This check is **mandatory for CLI signing**, requires independent trusted storage of the newest
digest, and **does not provide automatic anti-rollback**. Reading the expected
hash from the same potentially replaced USB drive defeats the protection.
A compromised offline host, co-replaced paper record or a forged operator
prompt can still undermine this process.

**Shared policy signing gate:** callers first load the single-read encrypted
policy with `read_policy_snapshot(<vault>.policy, independent_hash)` **before
unlocking**, then after deriving the wallet root call
`load_policy_snapshot(snapshot, root, password)` and
`enforce_review_policy(profile, root, validated_review, kind="evm"|"btc")`.
A DENY aborts signing; unknown recipients require extra confirmation.
CLI already enforces this sequence. GUI (#25/#29) and QR (#27) must invoke the
same gate for **every** signature and have independent missing-policy,
wrong-hash and over-limit regression tests before merger.

**Remaining Issue #21 follow-up:** GUI integration (#19); independently
reviewed token/typed-data decoder and display (#3); hardware-backed or
externally trusted monotonic profile revision anchoring, fee calculation
integration with hardened BTC #2, real two-device workflow testing and
backup/restore UX. **Do not describe AES-GCM encryption alone as rollback-safe
or claim the wallet is audited.**
