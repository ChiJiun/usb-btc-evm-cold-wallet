# Two-USB M0 acceptance record (#1, #43, #66)

This checklist is for the **merged main image**, not an older PR #7 artifact. CI/QEMU evidence must be tied to the exact image bytes and source commit. QEMU success is never physical USB acceptance. Do not record seed, mnemonic, private keys, vault contents, passphrases, or signed sensitive payloads.

## Build host / image (x86_64 Linux)

```sh
git rev-parse HEAD
make prepare-sources
make image
make verify
make reproducibility-check
scripts/verify_uefi_boot.sh
sha256sum build/output/images/usb-cold-wallet.img
sha256sum -c build/output/images/usb-cold-wallet.img.sha256
```

Run in a clean checkout with adequate disk space. `make reproducibility-check` rebuilds the generated output twice. Record each command's exit status, the **actual** image and kernel hashes, build duration, GitHub Actions run URL, and log artifact. Re-run `make verify` and `scripts/verify_uefi_boot.sh` on the final generated image after reproducibility checking; do not assume a previous image hash identifies the last build. The UEFI smoke test checks serial audit only, not interactive signing.

## Hardware operator procedure (never run destructive commands unattended)

1. Obtain two **empty** USB drives. Confirm their physical identity, serial/model, size, logical sector size, and device path by inspection. Record the verified image SHA-256 before writing. USB-A will be **erased**; back up anything important first.
2. Flash `build/output/images/usb-cold-wallet.img` to **USB-A** using a trusted imaging application with read-back verification. Verify GPT/EFI/COLD_VAULT on the written USB-A and record the result. Do not treat a file hash alone as proof of a correctly flashed device.
3. Format only the separately identified **USB-B** as FAT32 with volume label `TX_TRANSFER`; confirm its physical parent differs from USB-A. Do not format by guessed `/dev/sdX` names.
4. On a real x86_64 UEFI computer, boot USB-A with USB-B present; capture firmware model/version, Secure Boot setting, elapsed boot time, appliance startup audit, `CONFIG_NET=n`, no swap, RAM root, vault mount flags, blocked internal writable mounts, and USB device ancestry. Record actual evidence for each; a serial marker alone is insufficient.
5. With a **public, expendable test wallet only**, initialize/recover the encrypted vault, initialize policy, and keep the required policy SHA anchor on a separately trusted medium. Do not include that medium's secrets in the report.
6. On the online host, use the repository's existing Companion/CLI to create a fixed **Sepolia native EIP-1559** request. Copy the request to USB-B using the existing exchange protocol; on the offline appliance review chainId, address, value, nonce, gas and maximum fee, explicitly approve, and return the signed response on USB-B. Verify signed response binding on the online host. Record transaction hash only if an explicit testnet broadcast actually occurs.
7. Repeat using a **Bitcoin testnet BIP84 PSBT v0** request; review recipient, change, inputs and fee, sign offline, and verify/finalize online. Record txid only if actually broadcast.
8. With **test-only data**, exercise wrong USB parent, duplicate label/PARTUUID, malformed request, replay, wrong network/chain, modified amount or recipient, wrong policy anchor, removed USB-B, and interrupted write. Expected outcome: reject/lock down, never silently sign. Perform power-loss testing only on expendable test media.
9. After reboot, independently check vault persistence and safe recovery. Never infer rollback resistance from AES-GCM integrity or writable USB metadata.

Do not invent CLI command-line flags for transaction generation or signing: take exact syntax from the checked-out `usb-cold-wallet --help` and the current Companion documentation, and record the commands actually run. Do not place test secrets in CI, logs, screenshots, or PR attachments.

## Machine-readable result template

Save as a local JSON file, e.g. `two-usb-m0-results.json`, with one entry per case. Allowed statuses: `PASS`, `FAIL`, `BLOCKED`, `NOT TESTED`. A `PASS` requires a nonempty evidence reference to an actual execution, not a planned command.

```json
{
  "schema_version": 1,
  "source_commit": "",
  "image_sha256": "",
  "kernel_sha256": "",
  "ci_run_urls": [],
  "host": {"architecture": "", "uefi_vendor_version": "", "secure_boot": null},
  "usb_a": {"model": "", "capacity_bytes": null, "logical_sector_bytes": null},
  "usb_b": {"model": "", "capacity_bytes": null, "logical_sector_bytes": null},
  "cases": [
    {"id": "clean-build-reproducibility", "environment": "CI/x86_64", "status": "NOT TESTED", "evidence": [], "notes": ""},
    {"id": "image-gpt-kernel-audit", "environment": "CI/x86_64", "status": "NOT TESTED", "evidence": [], "notes": ""},
    {"id": "qemu-ovmf-startup-audit", "environment": "QEMU", "status": "NOT TESTED", "evidence": [], "notes": ""},
    {"id": "usb-a-flash-readback", "environment": "physical", "status": "NOT TESTED", "evidence": [], "notes": ""},
    {"id": "uefi-boot-runtime-isolation", "environment": "physical", "status": "NOT TESTED", "evidence": [], "notes": ""},
    {"id": "vault-policy-reboot", "environment": "physical", "status": "NOT TESTED", "evidence": [], "notes": ""},
    {"id": "sepolia-usb-b-sign-verify", "environment": "physical", "status": "NOT TESTED", "evidence": [], "notes": ""},
    {"id": "btc-testnet-usb-b-sign-verify", "environment": "physical", "status": "NOT TESTED", "evidence": [], "notes": ""},
    {"id": "negative-input-media-replay", "environment": "physical", "status": "NOT TESTED", "evidence": [], "notes": ""},
    {"id": "power-loss-recovery", "environment": "physical", "status": "NOT TESTED", "evidence": [], "notes": ""}
  ]
}
```

## Release gate

M0 remains **BLOCKED** until exact image bytes are available and a real UEFI boot, both USB-B offline signing/online verification roundtrips, and physical negative cases have evidence. Broadcast is conditional on test funds. The broader #43 two-machine/GUI/recovery release gate remains open after first-device M0; this Draft PR does not close any issue.
