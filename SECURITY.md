# Security policy

**EXPERIMENTAL. TESTNET ONLY. NOT AUDITED. Do not use with real assets.**

This repository is a research prototype and cannot claim any equivalent of commercial hardware wallet protection.

- Do not generate or import a valuable production mnemonic into a networked PC, VPS, VM, GitHub Actions, cloud container, image build cache, or release artifact.
- A cold wallet requires a **trusted physically offline host**. No software flag can prove that the host hardware is clean.
- Never submit mnemonic, BIP39 passphrase, encrypted vault, recovered private keys or device debug dumps in Issues, PRs or logs.
- For a suspected vulnerability, disclose details privately to the repository owner using GitHub's private vulnerability reporting if available. Do not post exploits with live wallet secrets.
- The test mnemonic in `tests/` is intentionally public and compromised.
- Run the security regression tests and review any dependency changes before adopting new code.
- The Live image authenticates a pinned Debian base ISO, hash-locks runtime Python artifacts, disables persistence/swap/networking in software, and gates the wallet launcher on a boot audit. These controls still do **not** make an untrusted computer trustworthy.
- Hardware wallet-grade protections (screen, secure element, MCU-enforced non-exportability) are **not** present.
- Our signing policy explicitly rejects BTC mainnet and EVM mainnet, unknown outputs, unknown EVM transaction fields and arbitrary contract calls.

**In-scope for later review:** transaction malleability, BIP32 path deception, PSBT parser denial-of-service, fee policy, memory handling, vault KDF parameter validation, USB malware, supply-chain attacks, malicious input JSON, recovery correctness.

Contact: open a minimally detailed issue for coordination, without publishing a live exploit or secret.
