# USB BTC + EVM Cold Wallet

[繁體中文（default）](README.md) | **English**

**One USB drive, two operating environments.** Use the portable Windows Companion to view accounts, receive funds, and prepare transactions. When you want to send funds, reboot into the USB's dedicated offline operating system to review and sign. Return to Windows to verify and broadcast.

This is an open-source, self-built **Bitcoin + EVM cold-wallet** project combining ordinary USB storage, a minimal Linux Live OS, and an air-gapped signing core. The goal is a practical daily workflow with no wallet installation on the everyday PC and no private-key signing in the online environment.

> This README describes the intended experience once the full product is integrated. See [Project status](#project-status) for what is available today.

## How one USB drive works

| Environment | Purpose | When you use it |
| --- | --- | --- |
| **Windows Portable Companion** | Watch-only accounts, balances, Bitcoin PSBT/EVM transaction preparation, signed-result verification, broadcasting and status tracking | Receiving, viewing assets, preparing a payment |
| **USB Offline Signer OS** | Boot from USB, unlock the encrypted wallet, independently parse and display transaction details, explicitly approve and sign | Sending funds |

The drive also carries an **encrypted wallet vault** and a **transaction exchange partition** to move unsigned requests and signed results between the two environments. Windows works with public account and transaction data; the offline OS handles private keys.

The dedicated signer is built on a minimal custom **Buildroot Linux Live OS**. It boots into a focused signing interface with networking and swap disabled by design.

## Everyday workflow

### 1. Set up a wallet

1. Prepare the cold-wallet USB and boot it from the computer's UEFI boot menu.
2. In the offline wallet interface, generate a wallet or recover one from a paper BIP39 mnemonic.
3. Set a vault password and record and verify the recovery phrase offline.
4. Export **public Bitcoin and EVM account information** to the Windows Companion for watch-only access.

Routine receiving and balance checks do not require unlocking the offline wallet again.

### 2. Receive and view funds

Insert the USB in Windows and launch its **Portable Companion** directly to:

- View Bitcoin and EVM accounts, balances, and transaction history.
- Copy receiving addresses or show receiving QR codes.
- Manage public addresses, saved recipients, and pending requests.

**Receiving funds does not require booting the Offline Signer.** Public account data is sufficient to receive payments and monitor chain state.

### 3. Send BTC or EVM

The planned single-computer, single-USB flow:

\`\`\`text
Windows: launch Companion from USB
    │
    ├─ Choose BTC / EVM, recipient and amount
    ├─ Review network fees and prepare an unsigned request
    └─ Save the request to the USB exchange partition
    │
    ▼
Reboot → boot the USB Offline Signer OS
    │
    ├─ Unlock the encrypted vault
    ├─ Independently parse the original transaction
    ├─ Check full address, amount, change / gas and fees
    └─ Explicitly approve → sign → save result to USB
    │
    ▼
Reboot → return to Windows
    │
    ├─ Companion imports the signed result
    ├─ Verifies the account, chain and fields against the request
    └─ Click "Broadcast" → show TxID / Tx Hash and status
\`\`\`

For **Bitcoin**, the online side prepares a watch-only PSBT; the signer checks UTXOs, recipient, change and fees before signing. The online side finalizes and broadcasts.

For **EVM**, the online side builds a transaction; the signer checks chain ID, recipient, value, nonce, gas and supported transaction semantics. The online side verifies the signed transaction before broadcast.

The normal workflow does not require editing JSON, running CLI commands, or copying raw transaction bytes.

## Two-computer air-gapped mode

With a dedicated offline computer, the USB can remain attached to that computer. Transactions can move by QR without rebooting for each signature.

\`\`\`text
Online computer / Companion                  Offline computer / USB Signer
Prepare BTC / EVM request      ── QR ──►    Scan, independently review
Verify signature & broadcast   ◄─ QR ───    Explicitly approve and sign
\`\`\`

Supported design paths include animated QR transport, a separate transfer USB when cameras are unavailable, and optional MetaMask integration using public accounts and a QR signing bridge.

Single-USB cross-boot mode prioritizes portability and a zero-install Windows experience. Two-computer QR mode keeps the signing host physically offline throughout the workflow. Both share the same transaction parser, approval rules, and signing core.

## Features and architecture

- **Bitcoin + EVM:** PSBT workflows, EVM transaction handling, and watch-only account management, with transaction types expanded incrementally.
- **Offline wallet storage:** BIP39/BIP32 keys, encrypted vault, paper recovery and recovery rehearsal.
- **Independent transaction review:** Full recipient addresses, amounts, network and fees derived from original requests; explicit approval for every signature.
- **Transaction policies:** Verified address book, fee limits, additional confirmation and rejection rules for unsupported contract operations.
- **Simple interfaces:** Windows Portable Companion and dedicated offline GUI, including Traditional Chinese.
- **Verifiable images:** Buildroot Live USB, pinned dependencies, reproducible builds, and QEMU/OVMF boot checks.

\`\`\`text
                     Cold-wallet USB
          ┌──────────────────────────┐
          │ UEFI / Buildroot Live OS │ → offline signing interface
          │ Encrypted Vault          │ → wallet keys and settings
          │ Transaction Exchange     │ → unsigned / signed data
          │ Windows Portable App     │ → online wallet companion
          └──────────────────────────┘
\`\`\`

Private-key signing and network broadcasting run in separate environments. An ordinary USB drive still depends on the integrity of the offline host and boot image. See the [threat model](docs/THREAT_MODEL.md).

## Project status

This document presents the **planned fully integrated product experience**, not a claim that all components are currently available.

The current \`main\` branch is a **v0.1.0 research prototype** with an offline CLI signing core for Bitcoin testnet PSBT v0 and Ethereum Sepolia EIP-1559 native transfers, an encrypted vault, public account export, and CI security checks. The bootable Live USB, Windows Portable Companion, signing GUI, QR transport, MetaMask integration, and cross-boot workflow are being integrated and verified in feature branches. Physical end-to-end validation is still pending.

Development currently targets **Bitcoin testnet and Ethereum Sepolia**. Mainnet or real-asset use requires separate security review and release acceptance.

Track progress: [Issues](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues) · [Pull requests](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pulls) · [Product UX #12](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/12) · [Single-USB cross-boot #37](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/37)

## Development and documentation

The current offline signing core requires Python 3.12+ for development.

\`\`\`bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
usb-cold-wallet --help
\`\`\`

[USB setup and operation](docs/USB_SETUP.md) · [Security policy](SECURITY.md) · [Threat model](docs/THREAT_MODEL.md) · [CI and supply chain](docs/CI_SECURITY.md) · [Open-source references](docs/OPEN_SOURCE_REFERENCES.md)

## License

Original project code is released under the **MIT License**. Third-party packages and components retain their respective licenses.
