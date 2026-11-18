# USB BTC + EVM Cold Wallet

> **Research prototype · testnet only · not independently audited · do not store real assets.**
>
> This project turns a normal x86_64 USB flash drive into a **bootable air-gapped signing environment**. The USB is still ordinary storage, not a YubiKey/Secure Element: the cryptographic operations run on the offline PC after boot.

[English security summary](SECURITY.md) · [USB 製作與使用](docs/USB_SETUP.md) · [Buildroot 建置](docs/BUILD.md) · [Threat model](docs/THREAT_MODEL.md) · [CI / 供應鏈安全](docs/CI_SECURITY.md) · [Open-source references](docs/OPEN_SOURCE_REFERENCES.md)

## Architecture

```
ONLINE COMPUTER                         OFFLINE COMPUTER
(no private keys)                      boots USB-A
┌────────────────────┐                 ┌──────────────────────────────┐
│ watch-only wallet  │                 │ Buildroot RAM-only rootfs    │
│ creates unsigned   │                 │ Linux CONFIG_NET=n           │
│ PSBT / tx JSON     │                 │                              │
└─────────┬──────────┘                 │ usb-wallet-console           │
          │                            │   ├─ BTC testnet PSBT signer │
          │ USB-B: TX_TRANSFER         │   └─ Sepolia tx signer       │
          ├───────────────────────────▶│                              │
          │                            │ USB-A partition 2:           │
          │                            │ COLD_VAULT (encrypted file)  │
          │ signed PSBT / raw tx       │                              │
          ◀────────────────────────────┤                              │
          │                            └──────────────────────────────┘
┌─────────▼──────────┐
│ broadcasts signed │
│ transaction only  │
└────────────────────┘
```

USB-A is the boot/cold-storage device and should never be used as transaction transport. USB-B is a separate FAT-formatted transfer device labelled `TX_TRANSFER` and must never contain a mnemonic or encrypted vault.

## Current implementation

| Area | Status |
|---|---|
| BIP39 / BIP32 master wallet | 24-word generated offline; optional BIP39 passphrase |
| Encrypted vault | scrypt + AES-256-GCM; mode 0600; existing files are not overwritten |
| Bitcoin | **testnet only**, BIP84 P2WPKH, strict PSBT v0 / SIGHASH_ALL, explicit recipient / amount / fee checks, no RBF/locktime semantics |
| EVM | **Sepolia only**, EIP-1559 native ETH transfers, explicit chainId / recipient / amount / gas checks |
| Offline console | Implemented; no normal login/getty presented |
| Live USB image | Buildroot external tree implemented for x86_64 UEFI |
| Root filesystem | Initramfs/RAM-only; no persistent Linux root partition |
| Networking | Kernel `CONFIG_NET` explicitly disabled + BusyBox networking applets rejected |
| Internal disks | ATA/NVMe/MMC/VirtIO block drivers are not enabled in production config |
| Persistent wallet storage | Dedicated `COLD_VAULT` partition on boot USB |
| Transaction transport | Separate `TX_TRANSFER` USB, mounted `noexec,nodev,nosuid,sync` after source validation |
| Dependency integrity | Buildroot release PGP manifest + SHA-256 verified; target Python artifacts hash-pinned |
| Reproducibility controls | `BR2_REPRODUCIBLE`, fixed epoch/GPT UUIDs, invariant FAT metadata, two-clean-build checker |
| Startup audit | Fail-closed network/swap/RAM-root/persistence checks before wallet operations |
| Image checks | GPT structure/UUID/readonly flag, kernel config, target binaries, networking tools, SHA-256 |
| CI | Python 3.12/3.13 pytest, hash-locked dependencies, pip-audit, Gitleaks, dependency review, reproducible project wheel, plus Live USB build/reproducibility/UEFI smoke workflow |
| Mainnet / ERC-20 / EIP-712 | **disabled** |
| Independent audit | Not done |

The image build pipeline is implemented. Automated x86_64 Buildroot, reproducibility and UEFI smoke checks must pass before this branch is merged. Physical-hardware validation is still recommended before treating the project as anything beyond a testnet research prototype.

## Host-side tests

Tests use a public, already-compromised BIP39 test vector. Never import a real wallet into Devspace, CI, WSL, VPS, or another networked development machine.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
```

## Build the bootable image

Use a Linux build host with standard Buildroot prerequisites.

```bash
# While the build host is online:
make prepare-sources

# Optionally disconnect the BUILD HOST after the source cache is complete.
make image

# Output:
# build/output/images/usb-cold-wallet.img
# build/output/images/usb-cold-wallet.img.sha256
make verify

# Two clean builds at the same output path must match bit-for-bit:
make reproducibility-check
```

The target wheelhouse is not resolved dynamically during the image build. Exact CPython 3.14 x86_64 wheels are pinned in `infra/wheelhouse-requirements.txt` and verified against `infra/wheelhouse.sha256`. Buildroot itself is pinned in `infra/buildroot.env`.

See [docs/BUILD.md](docs/BUILD.md) for host prerequisites and verification details.

## Operator flow

1. Flash `usb-cold-wallet.img` to USB-A. This erases the target USB.
2. Power off the signing PC and physically disconnect Ethernet; disable Wi-Fi/Bluetooth in firmware when possible.
3. Boot USB-A in UEFI mode. The image does not compile a Linux network stack.
4. Create the testnet wallet from the console. Write the 24-word mnemonic on paper and confirm it; the encrypted vault is written only to the verified `COLD_VAULT` partition.
5. Export only public addresses/tpub information to the online side.
6. Prepare an unsigned PSBT or Sepolia transaction online and place it on a separate USB-B labelled `TX_TRANSFER`.
7. Insert USB-B into the offline PC. The appliance validates the transfer-device source and mount flags, then independently verifies recipient/amount/fee before signing.
8. Take only the signed output back online for broadcast.
9. Power the signing PC off after use.

Full procedure: [docs/USB_SETUP.md](docs/USB_SETUP.md).

## Security properties and limitations

- Ordinary USB flash storage **cannot make keys non-exportable**. While unlocked, the seed and derived keys exist in the offline PC's RAM.
- No kernel network stack significantly reduces remote attack surface, but does not protect against compromised firmware, malicious USB controllers, DMA/physical attacks, or a tampered build chain.
- The boot/root filesystem uses deterministic-build controls and a two-clean-build hash checker.
- The boot USB contains an empty writable `COLD_VAULT` partition. Reflashing the whole image destroys that partition; the external BIP39 recovery backup remains mandatory.
- The transfer USB is untrusted input. Transaction parsers and policy checks still require fuzzing and independent audit.
- There is currently no Secure Boot signing/enrollment flow.
- Mainnet signing, contract calldata and blind signing remain disabled.

## Roadmap

1. Maintain the reproducible offline Linux wheelhouse and Live USB verification pipeline.
2. Continue independent transaction vectors, mutation/property fuzzing and parser/security review.
3. Complete physical-hardware validation of the read-only Live USB and removable-media workflow.
4. Improve on-device review UI, recovery rehearsal and mainnet readiness criteria.
5. Optionally build a hardware-device version with independent screen/buttons and secure boot.

## Project layout

- `src/usb_cold_wallet/` — vault, key derivation, BTC/EVM signing, appliance console
- `buildroot-external/` — Buildroot defconfig, kernel config, rootfs overlay and image layout
- `infra/` — Buildroot/Python artifact version and SHA-256 locks
- `scripts/` — fetch, target installation, build and static image/UEFI verification
- `requirements/` — hash-locked CI dependency set
- `tests/` — deterministic unit and security-invariant tests
- `docs/` — build, USB operation, CI security, threat model and design references

We intentionally **do not implement ECDSA/secp256k1, Keccak, AES or PSBT serialization ourselves**. The project uses established upstream libraries and pins the artifacts used in the appliance build.

License: MIT.
