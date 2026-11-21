# USB BTC + EVM Cold Wallet

[繁體中文（default）](README.md) | **English**

**One USB drive, two operating environments.** Use the portable Windows Companion to view accounts, receive funds, and prepare transactions. When you want to send funds, reboot into the USB's dedicated offline operating system to review and sign. Return to Windows to verify and broadcast.

This is an open-source project aimed at delivering a **practical, fully usable Bitcoin + EVM cold wallet** using ordinary USB storage, a minimal Linux Live OS, and an air-gapped signing core. The intended daily workflow requires no wallet installation on the everyday PC and never signs with private keys in the online environment.

**Bitcoin and Ethereum mainnet transactions are mandatory final-product capabilities.** Bitcoin testnet and Ethereum Sepolia serve development/Beta acceptance only; hardware, threat-model, supply-chain and independent security review are required before mainnet activation. **Do not use the current version with real assets.** See [#12](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/12), [#48](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/48), and [#47](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/47).

> This README describes the intended experience once the full product is integrated. See [Project status](#project-status) for what is available today.

## Final product goals and release phases

| Phase | Scope | Acceptance |
| --- | --- | --- |
| **Beta (testnets)** | Single USB, zero-install first-party Windows Companion, offline GUI, initialization/paper recovery and full BTC testnet/Sepolia cross-boot transactions | Real USB/UEFI, failure and transaction E2E; [#37](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/37), [#43](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/43), [#24](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/24) |
| **v1.0 mainnet core** | **Bitcoin mainnet BIP84/PSBT** and **Ethereum mainnet EIP-1559 ETH** transfers; strict chain/account/address/policy separation | Independent security review, minimal-value physical-device mainnet E2E, trusted release; [#48](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/48), [#47](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/47) |
| **ERC-20 and advanced transactions** | Reviewed token `transfer` with offline contract/decimals/amount/gas verification; later restricted `approve`/revoke, EIP-712/Permit and contract methods | ERC-20 is a final product goal; inclusion in v1.0 depends on acceptance. Unknown methods and blind signing remain denied; [#3](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/3), [#21](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/21) |
| **Optional integrations** | First-party WalletConnect/dApp and optional MetaMask native QR (Snap only as alternative) | Independently accepted and not a core wallet blocker; [#23](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/23), [#22](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/22) |

**First-party Windows Companion and Offline GUI are the primary interfaces.** Single-USB cross-boot is the main UX; two-device QR is another continuously air-gapped mode. Secrets remain offline, and every signature requires independent parsing and human approval.

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

The `main` branch has no fully integrated, physically accepted single-USB release image. Buildroot boot, isolation and image construction remain under [PR #7](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/7); use its current branch/CI instructions, **not obsolete PR #9 commands or QEMU results as proof of hardware acceptance**. The current development design uses a signer USB plus a separate exchange USB. Single-USB exchange and Windows integration remain [#37](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/37). The standalone Windows executable in [PR #50](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/50) passed real GitHub Windows-runner startup/API smoke but remains under review and is not bundled with the single-USB image.

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

**WalletConnect/dApp is an important long-term first-party Companion capability; MetaMask native QR is optional, with Snap as an alternative.** Core BTC/ETH transfers depend on neither integration and must require no CLI or manual JSON.

## Project status

This document presents the **planned fully integrated product experience**, not a claim that all components are currently available.

The `main` branch contains **testnet development code**, not a fully accepted USB wallet:

| Module | Merged code | Integration/acceptance still pending |
| --- | --- | --- |
| **Signing core** | BTC testnet BIP84/PSBT v0, Sepolia EIP-1559, encrypted vault and security tests | BTC/ETH mainnet, ERC-20 and advanced contracts disabled |
| **Online Companion** | BTC/Sepolia watch-only, transaction preparation, signed-result verification and manual broadcast ([PR #26](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/26)) | Windows EXE [PR #50](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/50) under review; no single-USB integration |
| **Offline GUI/policy/session** | Review/signing GUI, policy and attended lock/session modules ([PR #40](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/40), [PR #28](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/28), [PR #29](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/29)) | Real USB boot-to-GUI and failure acceptance |
| **USB/QR** | Paper recovery, USB exchange, QR and integration tests ([PR #11](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/11), [PR #27](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/27), [PR #42](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/42), [PR #49](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/49)) | Physical single-USB cross-boot, two-camera E2E, standard UR interoperability |
| **Live USB/MetaMask** | Buildroot development branch; MetaMask native QR adapter merged in [PR #31](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/31) | Live USB [PR #7](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/7) and optional Snap [PR #30](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/30) open; physical acceptance pending |

**Green CI does not imply physical USB safety or mainnet readiness.** Beta/RC/v1.0 releases follow evidence-based gates in [Release Roadmap #47](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/47) and [#24](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/24).

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
