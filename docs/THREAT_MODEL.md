# Threat model / 威脅模型

## Assets

- BIP39 mnemonic and optional BIP39 passphrase
- Derived secp256k1 private keys
- Encrypted `wallet.vault`
- Integrity of unsigned transaction review and signed transaction output
- Integrity of the boot image and dependency supply chain

## Trust boundary

The signing computer is physically offline and boots the project image from **USB-A**. The online computer is treated as untrusted and may create malicious transaction payloads. A separate **USB-B** labelled `TX_TRANSFER` carries only public/transaction data across the air gap.

USB-A contains an EFI boot partition plus `COLD_VAULT`. It is not used as transaction transport.

## Assumptions

- The offline computer's CPU, firmware, keyboard/display path and USB controllers are not malicious.
- The user verifies image hashes and independently checks recipient, amount, network, fee and change information.
- A recovery backup exists outside the USB device.
- Build inputs were obtained from the pinned sources and hashes in this repository.
- No production mnemonic is ever introduced into development/CI/cloud environments.

## Controls implemented

### Network isolation

- Production kernel config contains `# CONFIG_NET is not set`.
- Common BusyBox network clients are explicitly disabled.
- The post-build hook fails if common networking tools survive in the target rootfs.
- The runtime console reports a failure if `/proc/net` unexpectedly exists.

This is stronger than merely disabling Wi-Fi, but it does not prove firmware-level radio or management-engine isolation.

### Storage isolation

- Root filesystem is an initramfs and has no persistent Linux root partition.
- Production kernel config does not enable ATA, NVMe, MMC or VirtIO block storage.
- USB mass storage remains enabled because the boot/vault and transaction USB devices require it.
- Boot EFI and `COLD_VAULT` are resolved by deterministic PARTUUID, must be unique, and must be sibling partitions on the same USB disk before persistence is enabled.
- `COLD_VAULT` is mounted from the exact verified block device with `noexec,nodev,nosuid,sync`.
- `TX_TRANSFER` must resolve to exactly one labelled block device, must be on a different USB disk, and its actual mount source plus restrictive flags are re-checked after mount.
- Active swap is disabled/check-reported at boot.

### Wallet controls

- AAD-bound AES-256-GCM encrypted vault.
- scrypt password KDF.
- Vault creation refuses silent overwrite.
- Bitcoin testnet BIP84 input ownership, output, recipient, amount and fee policy checks.
- Sepolia chainId 11155111, type-2 transaction only, native transfer only, no calldata/blind signing.
- No RPC/broadcast code in the signer.

### Supply-chain controls

- Buildroot version and archive SHA-256 pinned.
- Python target wheel filenames/versions/hashes pinned; the appliance wheelhouse tracks the same hardened `cryptography` version as the host project.
- embit source tarball hash pinned.
- Image and kernel hashes emitted after build.
- Static image verifier checks GPT layout, final kernel config and target network-tool absence.

These controls pin inputs; they do **not yet prove independent bit-for-bit reproducible builds**.

## Not mitigated / out of scope

- Compromised BIOS/UEFI, CPU microcode, keyboard, display or USB controller firmware.
- Evil-maid attacks while the device is unlocked.
- Cold-boot/RAM extraction, DMA paths not covered by the current platform/kernel configuration, and physical side channels.
- Python memory zeroization. Immutable Python strings may leave secret copies in RAM until power-off.
- Malicious USB firmware (BadUSB) or filesystem/parser vulnerabilities.
- Supply-chain compromise that also compromises a pinned upstream artifact before its hash is recorded.
- Secure Boot; current image is not signed/enrolled.
- Hardware-backed non-exportable keys, tamper resistance or a trusted device display.
- Bitcoin multisig/Taproot/PSBT v2 and general EVM smart-contract/token signing.
- Mainnet use.

## Mainnet readiness gate

Do not enable mainnet merely by changing constants. Mainnet requires, at minimum:

1. successful full Buildroot image builds on clean hosts;
2. real UEFI boot tests on representative hardware;
3. independent reproducibility comparison;
4. parser fuzzing and independent transaction test vectors;
5. recovery rehearsal;
6. secure release/signing process;
7. third-party security review;
8. incident/disclosure process.

Until those gates are met: **testnet research only**.
