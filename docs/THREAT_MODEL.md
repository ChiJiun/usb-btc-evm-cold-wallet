# Threat model / 威脅模型

## Assets
BIP39 mnemonic, optional BIP39 passphrase, derived secp256k1 private keys, encrypted vault.

## Trust boundary
An offline, trusted physical computer boots from verified media. The networked computer is untrusted and only prepares transaction payloads / broadcasts signatures. The USB transport can contain attacker-controlled payloads.

## Assumptions
- Offline host hardware, its firmware, OS image, Python interpreter and dependencies are trustworthy.
- User separately verifies recipient, amount, network, fees and change address.
- Mnemonic has backup independent of USB, and any BIP39 passphrase can be reliably recovered.
- Neither project sources nor GitHub contain live user secrets.

## Controls present
- AAD-bound AES-256-GCM encrypted vault, scrypt KDF, create-only permission-restricted file.
- BIP84 testnet addresses and strict PSBT recipient / fee / input ownership policy.
- EVM Sepolia chainId 11155111, EIP-1559 only; reject calldata, unfamiliar fields and native transfer mismatch.
- No RPC, no broadcast, no mainnet path; signed transactions only cross air gap.
- Fixed upstream cryptographic primitives and CI tests with known compromised public test vectors.

## Live USB boot and storage controls (#7)
- Buildroot x86_64 UEFI image boots its root filesystem from RAM; the kernel configuration is checked after Kconfig resolution for `# CONFIG_NET is not set` and disables internal ATA/NVMe/MMC/VirtIO block storage.
- The boot audit refuses to unlock if `/proc/net` exists, swap is active, or an unexpected writable persistent mount is detected. The boot audit verifies the RAM-backed root and exact vault source and flags.
- GPT and FAT labels, deterministic partition GUIDs and GPT CRC checks identify a unique USB-A boot/vault pair on the same physical device. Duplicate or mismatched USB media fail closed.
- Encrypted `COLD_VAULT` is mounted with `rw,noexec,nodev,nosuid,sync`. The separate `TX_TRANSFER` USB-B is untrusted; its source and mount permissions must be verified before processing transaction files.
- Image sources and target wheel hashes are pinned. Two clean Buildroot builds and SHA-256 comparison, then QEMU/OVMF UEFI boot with no NIC and required `USB_WALLET_UEFI_AUDIT_OK` marker, have been exercised in CI for the tested head. See PR #7 and Issue #43 for real-device release acceptance.
- No hardware-backed Secure Element, firmware attestation or enrolled Secure Boot is provided. Standard USB storage is not immutable against a malicious online host. Real USB, firmware, persistence and full BTC/Sepolia transactions remain separate release checks (Issue #43).

## Out of scope / NOT mitigated
- Infected host/USB firmware/bootloader; physical theft during unlock.
- Hidden OS swap, cold boot attacks, DMA, malware in binaries or Python interpreter.
- RAM zeroization (Python immutable strings are not easily zeroizable). Issue #20 only limits key lifetime by idle/absolute timeout and bounded transaction count; it cannot guarantee secret wiping.\n- OS kernel crash dumps / ptrace or privileged debugging; the GUI disables *process-local* core files with RLIMIT_CORE=0, while OS-level kernel kdump, hibernation and swap must still be disabled by verified boot and runtime audits.\n- Failed-unlock backoff is local to the running process and resets on process restart; scrypt remains the main offline password-guessing cost.
- USB transport payload parsers being exploitable. PSBT strictness needs independent audit.
- Sophisticated physical side channels, hardware anti-tamper, Secure Element or device confirmation screen.
- Full Bitcoin policy support, multisig, script wallets, all EVM chain transactions and token approvals.
- Secure randomness/entropy verification on every Linux device; hardening against RNG compromise.

## Mainnet readiness gate
Require formal security review, fuzzing, independent test vectors, hardened read-only boot image, secure offline recovery ceremony, integrity-checked releases, incident handling and thorough operator docs. Until then, the project is a **development-stage cold wallet product validated on test networks**, with no approval for mainnet funds.
