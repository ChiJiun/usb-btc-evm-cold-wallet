# USB BTC + EVM Cold Wallet (prototype)

> **Research prototype / 測試網限定 / 未經安全審計 / 勿存放真實資產。**
>
> **目前不是可直接開機的 USB 映像。** 這個 repository 提供可在**已隔離網路的 Linux Live USB 環境**執行的錢包核心與 CLI。真正的冷儲存安全性取決於啟動環境、實體隔離、原始碼及相依套件供應鏈的完整性。它不是 YubiKey，也沒有 Secure Element。

[English security summary](SECURITY.md) · [USB 製作步驟](docs/USB_SETUP.md) · [Online Companion 操作指南](docs/ONLINE_COMPANION.md) · [威脅模型](docs/THREAT_MODEL.md) · [EVM 測試向量](docs/EVM_TEST_VECTORS.md) · [CI / 供應鏈安全](docs/CI_SECURITY.md) · [開源專案參考](docs/OPEN_SOURCE_REFERENCES.md)

## Goals / 目標

一般 USB 隨身碟 + 現有電腦即可執行，**不需要特殊硬體**。一台實體離線電腦負責解密錢包、核對交易、簽署；連網電腦只持有公鑰資料、準備未簽署交易並廣播簽署結果。

```
連網電腦（無私鑰）  --[ PSBT / type-2 tx JSON ]-->  離線 Live USB
連網電腦（只接收簽署結果） <--[ 簽署 PSBT / raw tx ]-- 離線 Live USB
```

## Current MVP (v0.1.0)

| Feature | Scope |
|---|---|
| One BIP39 master seed | 24-word generated offline, optional BIP39 passphrase for derivation |
| Encrypted USB vault | Scrypt + AES-256-GCM, mode 0600, reject existing file |
| Bitcoin | **testnet only**, native SegWit P2WPKH BIP84, strict PSBT v0 / SIGHASH_ALL, explicit recipient / amount / fee checks, no RBF/locktime semantics |
| EVM | **Sepolia only**, type-2 EIP-1559 native ETH transfers, explicit chainId / recipient / amount / gas checks, signed raw transaction re-decoding + sender recovery |
| Public outputs | BTC testnet receiving addresses and account tpub; EVM Sepolia address |
| Safety | No RPC, no broadcast functions, no blind contract calls, no mainnet signing, no private key output |
| CI | GitHub Actions: Python 3.12/3.13 pytest, hash-locked dependencies, pip-audit, Gitleaks, dependency review and reproducible-wheel check |

Not yet supported: mainnet, ERC-20, EIP-712, WalletConnect, Taproot, multisig, PSBT v2, QR transport, hardware button/screen confirmation, bootable ISO builder, address discovery beyond first 100 BIP84 inputs, independent audits.

## Online Companion — Issue #17, Phase 1 (testnet only)

A **separate, network-connected** `usb-cold-companion` process now provides a local loopback browser UI for **public watch-only data**, Sepolia native ETH transfer preparation, safe USB-B exchange, independently verified signed-transaction return, **explicit** broadcast and RPC status checking. No private key, seed or vault is imported. The **offline signer itself remains networkless**.

```bash
usb-cold-companion --rpc-url https://YOUR-SEPOLIA-RPC --open-browser
```

- Import public `addresses` JSON from the original signer or `watch-only` envelope from pending #5.
- Build EIP-1559 test ETH transfers without hand-crafting JSON or looking up nonce/gas manually.
- Download envelope for the #5 signer (or plain JSON for the original signer), then sign on trusted offline hardware; the cold-side CLI remains until #19.
- Upload signed file to verify raw transaction fields and recovered signer, then click to broadcast. The online tool **never auto-signs or silently resends**.
- BTC testnet BIP84: public tpub and master fingerprint support; fetch confirmed UTXOs from configurable Esplora, create bounded PSBT v0 with verified non-witness prevouts and change, validate cold-signed PSBT signatures and unsigned-field equality, and explicitly broadcast the finalized testnet transaction. Old watch-only exports without master fingerprint remain read-only and must be re-exported for spending.

Read [the operator guide and limitations](docs/ONLINE_COMPANION.md) before testing.

## Development & automated tests (safe on connected VM)

Testing uses the **publicly known, compromised BIP39 test vector** only. Never generate/import a production mnemonic on Devspace, GitHub Actions, WSL, or a networked host.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
usb-cold-wallet --help
```

## Live USB quick start (ONLY on trusted physically disconnected computer)

Full steps: [docs/USB_SETUP.md](docs/USB_SETUP.md). For legitimate cold storage, **do not run `init` on an internet-connected machine**.

```bash
# Prepare packages online and transfer to offline verified Linux using a transport USB:
python -m pip download -d wheelhouse -e ".[dev]"
# In offline Live Linux with a local source checkout / prebuilt wheelhouse:
python -m pip install --no-index --find-links wheelhouse -e ".[dev]"

# Wallet bootstrap ON OFFLINE HOST ONLY:
usb-cold-wallet --vault /path/on/offline-media/wallet.vault init --offline-ack --i-have-paper-backup

# Print PUBLIC info for your networked watch-only wallet:
usb-cold-wallet --vault /path/on/offline-media/wallet.vault addresses --count 3

# Sepolia: unsigned JSON must already be created on online machine and independently checked
usb-cold-wallet --vault /path/on/offline-media/wallet.vault sign-evm \
  --tx /transport/sepolia-unsigned.json \
  --to 0x000000000000000000000000000000000000dEaD \
  --wei 1000000000000 \
  --out /transport/sepolia-signed.json

# Bitcoin testnet: unsigned PSBT must contain BIP32 derivation paths;
# --change-index is an internal BIP84 change address index if a change output exists.
usb-cold-wallet --vault /path/on/offline-media/wallet.vault sign-btc \
  --psbt /transport/unsigned.psbt \
  --to tb1qREPLACE_WITH_INDEPENDENTLY_VERIFIED_ADDRESS \
  --sats 50000 --max-fee-sats 2000 --change-index 0 \
  --out /transport/signed.json
```

**Never copy encrypted vault or mnemonic to the transport USB used with online computers.** Only move public watch-only output and signed transactions. The offline signer deliberately has **no** broadcast function; the separate online companion can broadcast **verified EVM Sepolia and Bitcoin testnet** signed transactions, or you can use another networked wallet/node.

## Security limitations

- The passphrase decrypts the seed **into RAM on the offline PC**. The seed is not protected from the host OS, firmware, malicious peripherals, or physical RAM attacks.
- The encrypted vault does **not** replace a separate and verified paper/metal BIP39 recovery backup. The software does not yet implement a secure restore/check workflow.
- A USB flash drive is a storage device and cannot protect a private key independently like a microcontroller with trusted screen.
- A compromised online system can prepare malformed transaction payloads; limited output policy checks reduce some risk but are **not a substitute for security review**.
- The initial source, test coverage, dependency integrity, operational hardening and packaging have not been independently reviewed.

## Architecture

- `vault.py`: BIP39 encrypted vault
- `keys.py`: BIP32 derivation via upstream `embit`
- `btc.py`: conservative P2WPKH PSBT review + signing
- `evm.py`: Sepolia type-2 native transfer review + signing using `eth-account`, plus strict RLP re-decoding of signed bytes
- `cli.py`: offline interactive approval and file-based air-gap exchange
- `companion_core.py`: ONLINE watch-only importer, bounded Sepolia RPC, unsigned request builder, strict signed raw tx matching, explicit broadcast/status
- `companion_btc.py`: ONLINE Bitcoin testnet Esplora UTXO discovery, PSBT v0 creation, change management, signed-PSBT verification/finalization, explicit broadcast/status
- `companion_web.py` and `companion_static/`: local-only browser UI (not bundled into Live USB image by default)
- `tests/`: deterministic known-vector and rejection tests

We intentionally **do not implement cryptographic curves, SHA3/Keccak, PSBT serialization or AES ourselves**. [Upstream references](docs/OPEN_SOURCE_REFERENCES.md) explain the libraries and analogous open-source designs.

## Development roadmap

1. Independent reproducible offline Linux wheelhouse workflow for Live USB provisioning (CI dependency hashes and reproducible project wheel are now enforced).
2. Extend external EVM and Bitcoin Core/Sparrow vectors, mutation tests/fuzzing, and deeper PSBT input/output verification and security review.
3. Build tested, reproducible read-only Live USB image with network disabled; encrypted persistence and QR/file transport.
4. Better on-device UI for recipient/fee review, wallet recovery rehearsal and full mainnet readiness criteria.
5. Optional hardware device version with independent screen/buttons and secure boot.

License: MIT. New original code; links to upstream projects for architecture, not copied vendor firmware.
