# USB BTC + EVM Cold Wallet

[繁體中文（default）](README.md) | **English**

**One USB drive, two operating environments.** Use the portable Windows Companion to view accounts, receive funds, and prepare transactions. When you want to send funds, reboot into the USB's dedicated offline operating system to review and sign. Return to Windows to verify and broadcast.

This is an open-source project aimed at delivering a **practical, fully usable Bitcoin + EVM cold wallet** using ordinary USB storage, a minimal Linux Live OS, and an air-gapped signing core. The intended daily workflow requires no wallet installation on the everyday PC and never signs with private keys in the online environment.

**Validation strategy:** End-to-end development and hardware acceptance testing use Bitcoin testnet and Ethereum Sepolia to avoid risking real funds. These networks are the testing environment, not the long-term product definition. Mainnet/real-asset release requires separate hardware, threat-model, supply-chain, and independent security review.

> This README describes the intended experience once the full product is integrated. See [Project status](#project-status) for what is available today.

## From an empty USB: first-time setup

Prepare **a USB drive you can erase (16 GB or more recommended)**, a computer that supports **x86_64 UEFI USB boot**, and a separate paper backup for the recovery phrase. You can download and flash the image from a connected Windows PC; wallet creation and recovery take place in the offline USB operating system.

### A. Full-product setup (intended user experience)

1. **Get the image:** Download the appropriate `.img` and its published SHA-256 verification data from the project's [GitHub Releases](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/releases). Until a complete release image is available, use the **development build** below instead.
2. **Verify the download:** On Windows, calculate its checksum in PowerShell and compare it with the project's official release value:
   ~~~powershell
   Get-FileHash -Algorithm SHA256 .\usb-cold-wallet.img
   ~~~
3. **Flash the empty drive:** In a graphical flashing application such as balenaEtcher or Raspberry Pi Imager, select `usb-cold-wallet.img`, confirm the physical USB drive by name and capacity, then flash and verify. **Flashing erases the selected device; reflashing an existing wallet USB can also erase its vault.**
4. **Boot from USB:** Safely eject the drive, restart the computer, and select it in the UEFI boot menu. After the Offline Signer runs its startup checks, choose to create a wallet or recover from a mnemonic.
5. **Initialize the wallet:** Set a vault password, handwrite and verify the 24-word BIP39 recovery phrase offline, and store that backup separately from the USB. The encrypted vault resides on the drive.
6. **Set up the Windows Companion:** Export BTC/EVM public account data, shut down the offline system, return to Windows, and open the Portable Companion from the Windows-accessible USB partition. Import the public account data to view balances and prepare transactions.
7. **Test the full flow:** Use a small Bitcoin testnet or Sepolia transaction to rehearse prepare → boot USB and sign → return to Windows, verify and broadcast.

After setup, daily account viewing uses the Windows Companion; only spending requires rebooting into the USB signer. The complete planned release places the **Live OS, encrypted vault, transaction exchange area, and Windows portable app** on a single USB, with no separate Python/Node installation.

### B. Development build available today

The current `main` branch does not include the complete single-USB image yet. The Buildroot image builder is in the [PR #9](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/9) feature branch. On a **Linux x86_64 build host**, follow the [Buildroot prerequisites](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/blob/feat/issue-1-reproducible-live-usb/docs/BUILD.md) and run:

~~~bash
git clone https://github.com/ChiJiun/usb-btc-evm-cold-wallet.git
cd usb-btc-evm-cold-wallet
git switch feat/issue-1-reproducible-live-usb

make prepare-sources
make image
make verify
make reproducibility-check
cd build/output/images
sha256sum -c usb-cold-wallet.img.sha256
~~~

After successful verification, flash `build/output/images/usb-cold-wallet.img` to an empty USB using a graphical flasher, boot it via UEFI, and follow the [feature branch USB guide](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/blob/feat/issue-1-reproducible-live-usb/docs/USB_SETUP.md) to create a test wallet and use its signing menu.

**This development image currently uses two USB drives.** The signer USB contains `USBCOLD_EFI` and `COLD_VAULT` partitions; a separate FAT32 USB labeled `TX_TRANSFER` carries requests and responses. It **does not yet bundle the Windows Portable Companion or the same-USB exchange partition**. A [separate Windows x64 no-install test build](docs/WINDOWS_PORTABLE_COMPANION.md) is available, with manual JSON transfer. The unified single-USB flow becomes available after [Issue #37](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/37) is implemented and verified.

## How one USB drive works

| Environment | Purpose | When you use it |
| --- | --- | --- |
| **Windows Portable Companion** | Watch-only accounts, balances, Bitcoin PSBT/EVM transaction preparation, signed-result verification, broadcasting and status tracking | Receiving, viewing assets, preparing a payment |
| **USB Offline Signer OS** | Boot from USB, unlock the encrypted wallet, independently parse and display transaction details, explicitly approve and sign | Sending funds |

The drive also carries an **encrypted wallet vault** and a **transaction exchange partition** to move unsigned requests and signed results between the two environments. Windows works with public account and transaction data; the offline OS handles private keys.

The dedicated signer is built on a minimal custom **Buildroot Linux Live OS**. It boots into a focused signing interface with networking and swap disabled by design.

## Everyday workflow

### 1. Set up a wallet

1. Follow the [empty-USB setup](#from-an-empty-usb-first-time-setup) to flash the drive, then start the offline OS from the UEFI boot menu.
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

```text
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
```

For **Bitcoin**, the online side prepares a watch-only PSBT; the signer checks UTXOs, recipient, change and fees before signing. The online side finalizes and broadcasts.

For **EVM**, the online side builds a transaction; the signer checks chain ID, recipient, value, nonce, gas and supported transaction semantics. The online side verifies the signed transaction before broadcast.

The normal workflow does not require editing JSON, running CLI commands, or copying raw transaction bytes.

## Two-computer air-gapped mode

With a dedicated offline computer, the USB can remain attached to that computer. Transactions can move by QR without rebooting for each signature.

```text
Online computer / Companion                  Offline computer / USB Signer
Prepare BTC / EVM request      ── QR ──►    Scan, independently review
Verify signature & broadcast   ◄─ QR ───    Explicitly approve and sign
```

Supported design paths include animated QR transport, a separate transfer USB when cameras are unavailable, and optional MetaMask integration using public accounts and a QR signing bridge.

Single-USB cross-boot mode prioritizes portability and a zero-install Windows experience. Two-computer QR mode keeps the signing host physically offline throughout the workflow. Both share the same transaction parser, approval rules, and signing core.

## Features and architecture

- **Bitcoin + EVM:** PSBT workflows, EVM transaction handling, and watch-only account management, with transaction types expanded incrementally.
- **Offline wallet storage:** BIP39/BIP32 keys, encrypted vault, paper recovery and recovery rehearsal.
- **Independent transaction review:** Full recipient addresses, amounts, network and fees derived from original requests; explicit approval for every signature.
- **Transaction policies:** Verified address book, fee limits, additional confirmation and rejection rules for unsupported contract operations.
- **Simple interfaces:** Windows Portable Companion and dedicated offline GUI, including Traditional Chinese.
- **Verifiable images:** Buildroot Live USB, pinned dependencies, reproducible builds, and QEMU/OVMF boot checks.

```text
                     Cold-wallet USB
          ┌──────────────────────────┐
          │ UEFI / Buildroot Live OS │ → offline signing interface
          │ Encrypted Vault          │ → wallet keys and settings
          │ Transaction Exchange     │ → unsigned / signed data
          │ Windows Portable App     │ → online wallet companion
          └──────────────────────────┘
```

Private-key signing and network broadcasting run in separate environments. An ordinary USB drive still depends on the integrity of the offline host and boot image. See the [threat model](docs/THREAT_MODEL.md).

**MetaMask, WalletConnect and dApp integrations are optional.** The first-party Windows Companion and offline USB signing interface must independently cover balance and address viewing, transaction creation, clear review, signing, broadcasting, and status tracking. The essential wallet workflow cannot depend on installing MetaMask or using a CLI/hand-edited JSON.

## Project status

This document presents the **planned fully integrated product experience**, not a claim that all components are currently available.

The current `main` branch is a **v0.1.0 development version that has not passed full product release acceptance** with an offline CLI signing core for Bitcoin testnet PSBT v0 and Ethereum Sepolia EIP-1559 native transfers, an encrypted vault, public account export, and CI security checks. The bootable Live USB, Windows Portable Companion, signing GUI, QR transport, MetaMask integration, and cross-boot workflow are being integrated and verified in feature branches. Physical end-to-end validation is still pending.

The [PR #9 Live USB development image](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/9) still uses a **signer USB plus a separate transaction-transfer USB**; the setup instructions above explain this distinction from the planned single-USB product.

Development currently targets **Bitcoin testnet and Ethereum Sepolia**. Mainnet or real-asset use requires separate security review and release acceptance.

Track progress: [Issues](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues) · [Pull requests](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pulls) · [Product UX #12](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/12) · [Single-USB cross-boot #37](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/37)

## Development and documentation

The current offline signing core requires Python 3.12+ for development.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
usb-cold-wallet --help
```

[USB setup and operation](docs/USB_SETUP.md) · [Paper recovery and USB exchange](docs/RECOVERY_AND_USB_EXCHANGE.md) · [Security policy](SECURITY.md) · [Threat model](docs/THREAT_MODEL.md) · [CI and supply chain](docs/CI_SECURITY.md) · [Open-source references](docs/OPEN_SOURCE_REFERENCES.md)

## License

Original project code is released under the **MIT License**. Third-party packages and components retain their respective licenses.
