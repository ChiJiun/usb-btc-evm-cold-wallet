# Threat model / 威脅模型

## Assets
BIP39 mnemonic, optional BIP39 passphrase, derived secp256k1 private keys, encrypted vault.

## Trust boundary
An offline, trusted physical computer boots from verified media. The networked computer is untrusted and only prepares transaction payloads / broadcasts signatures. The USB transport can contain attacker-controlled payloads.

## Assumptions
- Offline host hardware, its firmware, OS image, Python interpreter and dependencies are trustworthy.
- User separately verifies recipient, amount, network, fees and change address.
- Mnemonic has backup independent of USB, and any BIP39 passphrase can be reliably recovered.
- Neither project sources, build caches, CI, releases nor GitHub contain live user secrets.
- The operator physically disconnects networking before unlocking a wallet; software air-gap controls are defense in depth, not a replacement for that step.

## Controls present
- AAD-bound AES-256-GCM encrypted vault, scrypt KDF, create-only permission-restricted file.
- BIP84 testnet addresses and strict PSBT recipient / fee / input ownership policy.
- EVM Sepolia chainId 11155111, EIP-1559 only; reject calldata, unfamiliar fields and native transfer mismatch.
- No RPC, no broadcast, no mainnet path; signed transactions only cross air gap.
- Fixed upstream cryptographic primitives and tests with known compromised public test vectors.
- Debian Live base ISO is pinned by SHA-256 and authenticated through Debian's signed checksum metadata plus a pinned Debian CD signing-key fingerprint.
- Runtime Python dependency closure is locked to exact artifacts and SHA-256 values; package setup code is not executed during image assembly.
- Live image masks network services and swap, forces non-loopback interfaces down, applies nftables DROP policies for inet/ARP, disables DNS, adds `nopersistence`, and blocks wallet startup until the boot audit passes.
- Core dumps are disabled; the boot medium must be read-only and the writable live overlay is RAM-backed.

## Out of scope / NOT mitigated
- Infected host/USB firmware/bootloader; physical theft during unlock.
- Cold boot attacks, DMA, malicious firmware/kernel, or malware in the authenticated-but-not-independently-audited OS/Python supply chain. Active swap is explicitly prohibited and audited, but RAM itself remains in scope for physical attacks.
- RAM zeroization (Python immutable strings are not easily zeroizable).
- USB transport payload parsers being exploitable. PSBT strictness needs independent audit.
- Sophisticated physical side channels, hardware anti-tamper, Secure Element or device confirmation screen.
- Full Bitcoin policy support, multisig, script wallets, all EVM chain transactions and token approvals.
- Secure randomness/entropy verification on every Linux device; hardening against RNG compromise.

## Mainnet readiness gate
Require formal security review, fuzzing, independent test vectors, byte-identical independent image rebuilds, physical boot tests on representative x86_64 hardware, secure offline recovery ceremony, integrity-checked releases, incident handling and thorough operator docs. Until then: **testnet research only**.
