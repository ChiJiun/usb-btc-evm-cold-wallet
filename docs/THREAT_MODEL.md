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

## Out of scope / NOT mitigated
- Infected host/USB firmware/bootloader; physical theft during unlock.
- Hidden OS swap, cold boot attacks, DMA, malware in binaries or Python interpreter.
- RAM zeroization (Python immutable strings are not easily zeroizable). Issue #20 only limits key lifetime by idle/absolute timeout and bounded transaction count; it cannot guarantee secret wiping.\n- OS kernel crash dumps / ptrace or privileged debugging; the GUI disables *process-local* core files with RLIMIT_CORE=0, while OS-level kernel kdump, hibernation and swap must still be disabled by verified boot and runtime audits.\n- Failed-unlock backoff is local to the running process and resets on process restart; scrypt remains the main offline password-guessing cost.
- USB transport payload parsers being exploitable. PSBT strictness needs independent audit.
- Sophisticated physical side channels, hardware anti-tamper, Secure Element or device confirmation screen.
- Full Bitcoin policy support, multisig, script wallets, all EVM chain transactions and token approvals.
- Secure randomness/entropy verification on every Linux device; hardening against RNG compromise.

## Mainnet readiness gate
Require formal security review, fuzzing, independent test vectors, hardened read-only boot image, secure offline recovery ceremony, integrity-checked releases, incident handling and thorough operator docs. Until then: **testnet research only**.
