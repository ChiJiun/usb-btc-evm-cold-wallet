# USB BTC + EVM Cold Wallet (Research Prototype)

[繁體中文（預設）](README.md) | **English**

> [!WARNING]
> **Experimental · Testnets only · Not independently audited · Do not use with real funds.**
>
> This repository is **not a bootable USB image** and is not equivalent to Ledger, Trezor, YubiKey, or a Secure Element. It provides an offline signing core and CLI intended to run inside a **trusted, physically disconnected Linux Live environment**. A regular USB flash drive cannot protect keys independently of the host computer.

## What is this project?

An open-source proof of concept for creating a **Bitcoin testnet + Ethereum Sepolia air-gapped signer** using an ordinary USB drive and a separate offline computer.

The trust boundary matters more than the drive itself:

- **Offline computer:** generates/decrypts a BIP39 wallet, independently reviews transaction details, and signs. It must never connect to the internet while handling private material.
- **Online computer:** holds only public watch-only information, prepares unsigned requests, and broadcasts signed transactions using a wallet or node.
- **Transfer USB (USB-B):** moves *public data and unsigned/signed transactions*, never a mnemonic, private key, passphrase, or encrypted vault.

```text
 Online computer (no private key)       Offline computer / Live USB
 ┌──────────────────────────────┐        ┌──────────────────────────────┐
 │ Watch-only wallet / node     │        │ Encrypted vault + BIP39 seed │
 │ Prepare BTC PSBT / EVM tx    │ ─────► │ Independently review intent  │
 │                              │ USB-B  │ Explicit human confirmation  │
 │ Verify result and broadcast  │ ◄───── │ Sign without any network     │
 └──────────────────────────────┘        └──────────────────────────────┘
```

**Receiving funds** only requires public receiving addresses. **Sending funds** requires the offline signer to approve and sign each transaction.

## Current functionality (`main`, v0.1.0)

| Component | Implemented scope |
| --- | --- |
| Wallet derivation | One offline-generated 24-word BIP39 mnemonic; optional BIP39 passphrase; BIP32 paths |
| Encrypted vault | Scrypt + AES-256-GCM; private file permissions (`0600`); refuses to overwrite existing vault |
| Bitcoin | **Testnet only**; BIP84 native SegWit P2WPKH; conservative PSBT v0 and SIGHASH_ALL validation; explicit recipient, amount, change and fee review; no RBF/locktime semantics |
| EVM | **Sepolia only**; EIP-1559 type-2 **native ETH transfers**; chain ID, recipient, value and gas checks; signed raw transaction re-decoding and sender recovery |
| Public watch-only output | Bitcoin testnet addresses and account `tpub`; Sepolia account address |
| Safety boundaries | Signer has **no RPC or broadcast code**, no mainnet signing, no arbitrary contract calls or blind signing, and no private-key export |
| CI | Python 3.12/3.13 tests; hash-locked dependencies; pip-audit; Gitleaks; dependency review checks; reproducible wheel verification |

**Not included in the current `main` release:** mainnet, ERC-20, EIP-712, WalletConnect, Taproot, multisig, PSBT v2, QR transport, trusted hardware screen/buttons, a ready-to-flash bootable ISO, full Bitcoin address discovery, and an independent security audit.

> [!NOTE]
> New features are being developed in separate pull requests. In particular, the Online Companion in [PR #26](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/26) is **not part of `main` while that PR remains unmerged**. This README describes `main`, not unmerged features.

## Development and tests (connected computers)

Development is safe on a networked machine **only with public, known-compromised test vectors**. **Never** create or import a production mnemonic on a VM, Devspace, CI, cloud service, WSL, or other connected computer.

Requirements: Python 3.12+.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"

pytest
usb-cold-wallet --help
```

These automated tests do **not** prove the security of a real offline host or USB installation.

## Offline setup (trusted, physically disconnected computer only)

Read [the USB setup guide](docs/USB_SETUP.md) before proceeding. The following is a **manual research workflow**, not an installer or a secure boot guarantee.

1. Verify an official Linux Live image and prepare **USB-A** as the offline boot medium. Flashing a boot medium erases its contents.
2. Prepare a separate trusted package source or wheelhouse **before** disconnecting the computer; verify package versions, integrity, and platform compatibility.
3. Fully power off and physically disconnect the offline host from Ethernet, Wi-Fi, Bluetooth, and other network paths. Boot the Live environment without mounting untrusted storage.
4. Keep the encrypted vault on dedicated **offline-only media**. Reserve **USB-B** exclusively for transaction exchange files.
5. Generate the wallet **only on this offline host** and independently back up the mnemonic and any optional BIP39 passphrase.

Example commands (run only on the appropriately isolated host; commands below do not establish isolation):

```bash
# Prepare dependencies on a connected development host:
python -m pip download -d wheelhouse -e ".[dev]"

# Install from a previously verified wheelhouse on the offline host:
python -m pip install --no-index --find-links wheelhouse -e ".[dev]"

# Create a vault OFFLINE. Never run this command on a connected host.
usb-cold-wallet --vault /offline/wallet.vault init \
  --offline-ack --i-have-paper-backup

# Display PUBLIC watch-only information:
usb-cold-wallet --vault /offline/wallet.vault addresses --count 3
```

Do not treat the `--offline-ack` flag as proof that the computer is actually air-gapped. Verify the OS and hardware setup separately.

## Signing transactions

The online computer prepares a request; **the offline signer verifies recipient and amount against an independently trusted source**. It must never approve a transfer merely because the online computer describes it as safe.

### Send native ETH on Sepolia

Create an **unsigned** type-2 transaction JSON on the online computer, then carry it to the offline host on USB-B.

```bash
usb-cold-wallet --vault /offline/wallet.vault sign-evm \
  --tx /transport/sepolia-unsigned.json \
  --to 0x000000000000000000000000000000000000dEaD \
  --wei 1000000000000 \
  --out /transport/sepolia-signed.json
```

The recipient and amount flags are **independently checked expectations**. The signer reviews the raw request and asks for explicit confirmation. Transfer the signed result back to the online computer for separate broadcast.

### Send BTC on Bitcoin testnet

The unsigned PSBT must contain the expected BIP32 key origins and UTXO information. A change output must use an independently verified internal BIP84 change index.

```bash
usb-cold-wallet --vault /offline/wallet.vault sign-btc \
  --psbt /transport/unsigned.psbt \
  --to tb1qREPLACE_WITH_INDEPENDENTLY_VERIFIED_ADDRESS \
  --sats 50000 --max-fee-sats 2000 --change-index 0 \
  --out /transport/signed.json
```

Omit `--change-index` when there is no change output. Move the signed result back to the online system and finalize/broadcast it separately through compatible wallet/node software. **The offline CLI intentionally never broadcasts.**

## Security model and limitations

- A plain USB is **storage, not a hardware security module**. It provides no isolated hardware confirmation screen, Secure Element, or independently enforced non-exportability.
- Decrypting the encrypted vault puts the seed and derived keys **in the offline host's RAM**. Compromised firmware, OS, peripherals, swap, crash dumps, or physical memory attacks can expose secrets.
- The vault encryption password is **not a substitute** for an offline, independently verified paper/metal recovery backup of the BIP39 mnemonic and optional passphrase.
- Malicious online software or USB-B may change transaction data. Integrity hashes alone do **not** authenticate the sender or authorize a signature.
- An ordinary Linux Live OS may persist sensitive data unless its storage, swap, logging, and mounting behavior are separately audited.
- Source code, dependencies, packaging, threat model, and real-device behavior **have not undergone an independent security audit**. Testnet success does not make the implementation safe for mainnet.

**Never place a mnemonic, passphrase, private key, decrypted vault, or encrypted wallet vault on the transport USB or upload it to a public issue, pull request, or log.**

See the [security policy](SECURITY.md) and [threat model](docs/THREAT_MODEL.md).

## Repository structure

| File | Purpose |
| --- | --- |
| `src/usb_cold_wallet/vault.py` | BIP39 wallet vault encryption / decryption |
| `src/usb_cold_wallet/keys.py` | BIP32 derivation via upstream `embit` |
| `src/usb_cold_wallet/btc.py` | Conservative Bitcoin testnet PSBT review and signing |
| `src/usb_cold_wallet/evm.py` | Sepolia native ETH review and signing via `eth-account` |
| `src/usb_cold_wallet/cli.py` | Offline command-line review, human approval, and file exchange |
| `tests/` | Public-vector, deterministic, and rejection tests |
| `docs/` | Setup, threat model, test vectors, supply-chain security, and references |

The project does **not** reimplement elliptic-curve cryptography, Keccak, PSBT serialization, or AES. See [upstream references](docs/OPEN_SOURCE_REFERENCES.md).

## Development roadmap

1. Reproducible offline dependency provisioning and verified, isolated boot environment.
2. Independent Bitcoin Core/Sparrow and EVM vectors, parser mutation/fuzz testing, and external security review.
3. Reproducible read-only Live USB image, network isolation, and secure transaction transport (file / QR).
4. Better transaction-review UI, secure recovery rehearsals, and release gates before any mainnet consideration.
5. Optional dedicated hardware with its own trusted display, buttons, and secure boot.

For planned usability improvements, follow [Issue #12](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/12).

## Documentation

[USB setup](docs/USB_SETUP.md) · [Security policy](SECURITY.md) · [Threat model](docs/THREAT_MODEL.md) · [EVM test vectors](docs/EVM_TEST_VECTORS.md) · [CI / supply-chain security](docs/CI_SECURITY.md) · [Open-source references](docs/OPEN_SOURCE_REFERENCES.md)

## License

MIT. The original source code is provided as a research prototype; upstream projects are cited for architecture and reference, not copied as proprietary vendor firmware.
