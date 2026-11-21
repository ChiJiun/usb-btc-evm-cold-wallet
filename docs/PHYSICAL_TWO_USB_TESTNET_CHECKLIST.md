# #66 / #43 — First physical two-USB testnet gate

> **TESTNET ONLY — NOT A RELEASE.** QEMU success is not physical-device acceptance. Use a dedicated publicly disclosed test seed and testnet coins only. Never use a production mnemonic, private key, vault or real assets.

## 0. Identify exact verified image

- [ ] Open the successful **Live USB image verification** run for this PR's **exact HEAD SHA**. Confirm the reproducibility step, `Boot generated USB image using UEFI OVMF/QEMU (TCG)`, `Verify exact image bytes against reproducibility evidence`, and image upload step all succeeded. Do not use a failed, cancelled or different-commit run.
- [ ] Download `testnet-only-NOT-A-RELEASE-usb-cold-wallet` artifact from that run (3-day retention). This is an unsigned CI artifact, **not** a release or proof of GitHub/host provenance. It contains `usb-cold-wallet.img` and `usb-cold-wallet.img.sha256`.
- [ ] Record: repository commit SHA, workflow run URL/id, artifact name/id, image size in bytes, SHA-256 from the artifact, download date. Rehash after download. On Linux, from the unzipped artifact directory: `sha256sum -c usb-cold-wallet.img.sha256`. The same image hash must appear in the run's `run-1.sha256` and `run-2.sha256` evidence.
- [ ] If artifact is absent/expired or any hash differs, **STOP**. Rebuild and rerun full validation for the new exact commit; do not substitute a similarly named or unverified image.

## 1. Prepare and record physical media

- [ ] Select one x86_64 UEFI computer and **two separate empty USB drives**. Record machine make/model, CPU, RAM, firmware version, Secure Boot state, USB drive make/model/capacity and logical sector size (requires 512-byte FAT sector layout). Record USB identifiers without serial numbers if they are sensitive.
- [ ] On a trusted computer identify USB-A by capacity/model and remove all other unnecessary external drives. **Flashing destroys every partition and all data on the selected device.**
- [ ] Flash the verified `.img` as a raw whole-disk image to **USB-A**, using a flashing application with read-back verification (e.g., balenaEtcher). Do not copy the image as a file onto a FAT partition. Verify GPT + `USBCOLD_EFI` and `COLD_VAULT` partition identities; do not reformat either partition.
- [ ] Format **USB-B only** as FAT32 with volume label **`TX_TRANSFER`** (not exFAT). It must be a different physical block device from USB-A. Record format/flash verification outcomes and wall-clock durations.
- [ ] Keep backup of the exact request fixture hashes outside USB-B. Do not store any private seed material or policy anchor on USB-B.

## 2. Boot and security gate (do not sign if any check fails)

- [ ] Cold boot from USB-A through the computer's UEFI boot menu. Record boot-start to appliance-menu duration and any firmware setting needed; do not claim Secure Boot is supported.
- [ ] Verify the on-screen startup and live security audit all report `PASS`; no `LOCKDOWN` or `FAIL`. The expected boundary is RAM-only root, `CONFIG_NET=n` (`/proc/net` absent), no active swap or unexpected writable persistent filesystem, verified boot/vault GPT/USB parent identity, and COLD_VAULT `rw,noexec,nodev,nosuid,sync`.
- [ ] Insert USB-B and choose appliance menu **5** (re-scan). Confirm it is recognized, stays independent of USB-A and no other transfer device matches. Record only the PASS/FAIL information and device details.
- [ ] Negative check with **test-only** media: absent USB-B, incorrect label, cloned/duplicate USB-A, or disconnected transfer drive must refuse signing and must never fall back to an internal disk. If a case would risk destructive media changes, defer and mark untested rather than improvising.
- [ ] If any audit fails, record its public diagnostic and stop the session. Do not bypass audit or edit USB identifiers to force a pass.

## 3. Offline wallet / policy

- [ ] Menu **1**: initialize a dedicated disposable **testnet-only** encrypted wallet (the current menu generates a fresh random mnemonic). Do not enter any production seed. If a *public* test-vector seed is required, provision it through a separately reviewed restore path and document only its public test-vector ID; do not publish a newly generated seed while any vault or test funds remain in use.
- [ ] Menu **2**: show and record **public** Bitcoin testnet BIP84 and Sepolia addresses, their network and derivation/account identity. Confirm they match the online watch-only account.
- [ ] Menu **7**: initialize encrypted offline policy. Write the displayed 64-character **POLICY SHA256** on independent paper; verify against an independently held reference. Record in evidence only whether anchor verification succeeded, not the vault password, seed or secret.
- [ ] Power off and cold boot again to ensure COLD_VAULT persists, only the intended wallet can be opened, and the boot/runtime checks still pass.

## 4. Sepolia native EIP-1559 offline signing

- [ ] On a **separate online computer** construct a fixed type-2 Sepolia **native ETH transfer** request using the existing Companion/CLI. Record the public from/to address, chainId `11155111`, nonce, value in wei, gas limit, maxFeePerGas, maxPriorityFeePerGas, maximum total spend and canonical request digest.
- [ ] Copy the bounded **JSON request envelope** onto USB-B. On cold appliance menu **3**, select the request and independently type the verified destination address, exact wei amount, and independent paper policy SHA-256.
- [ ] Review every canonical offline-parsed field before the explicit approval. Unknown calldata, contract calls, wrong chain, account, nonce, recipient, digest, value, excessive fee or changed USB payload must fail closed.
- [ ] Confirm output `*.signed.json` on USB-B; return to online Companion/CLI and verify the signed transaction's recovered address and every field match the original canonical request. If test ETH is available, **manually** broadcast and record the public tx hash/status (broadcast is optional for this first gate).

## 5. Bitcoin testnet BIP84 PSBT v0 offline signing

- [ ] On the online computer prepare a fixed Bitcoin **testnet BIP84 P2WPKH PSBT v0** request funded from the dedicated test wallet. Record public input outpoints, each output recipient/value, change address/index and value, fee in satoshis, maximum permitted fee, network and canonical request digest.
- [ ] Place the canonical `.psbt` or bounded BTC `.json` request onto USB-B. On cold appliance menu **4**, independently type the verified `tb1...` recipient, satoshi amount, maximum fee, change index (if present), and independent policy SHA-256.
- [ ] Check inputs and outputs, change ownership/index, total spend and fee on the offline parser's review; reject malformed PSBT, unfamiliar scripts, missing ownership, wrong change, wrong network, altered digest or unapproved fee.
- [ ] Confirm `*.signed.json` is written; on the online side validate request/result binding, signatures and finalized transaction against the original PSBT. Only then optionally perform **explicit** Bitcoin testnet broadcast and record public txid/status.

## 6. Evidence & acceptance record

| Field | Value / result |
| --- | --- |
| Date/time (Asia/Taipei), operator | |
| Exact tested commit / workflow run URL | |
| Image artifact name/id / SHA-256 / byte size | |
| USB-A and USB-B models / capacity / sector size | |
| UEFI machine / firmware / Secure Boot state | |
| Image flash time / cold boot time | |
| Startup + runtime audit PASS / lockdown negatives | |
| Vault persistence / policy independent-anchor check | |
| Sepolia public request digest / signed result verification / optional tx hash | |
| BTC testnet public PSBT digest / signed result verification / optional txid | |
| Failure/recovery cases, expected vs. actual | |
| Screenshots with secrets and device identifiers redacted | |
| Remaining untested conditions | |

Never attach mnemonics, private keys, passwords, raw vault files, memory dumps, shell histories or unredacted logs. Public testnet addresses, request digests, hashes and txids are acceptable after confirming that no personal identifiers are included.

**M0 PASS** requires one real x86_64 UEFI boot, live audit PASS, distinct USB-A/USB-B, persisted encrypted vault/policy and both Sepolia and BTC offline sign+online verify. Release Gate #43 remains **OPEN** until its broader two-machine, power-loss, recoverability, GUI/product and security acceptance criteria are actually tested.
