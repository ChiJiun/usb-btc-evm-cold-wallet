# Open-source design references and source licensing

This is an original MIT-licensed wallet application with reviewed dependencies. The framebuffer POC additionally derives **bitmap data only** from one pinned Public Domain font file documented below; no wallet/signing implementation is copied from the referenced projects. Check exact-path licenses and provenance before any future source copy.

| Project | Role / applicability | Important caveat |
|---|---|---|
| [ArcSign](https://github.com/arcsignio/arcsign) | USB-focused BTC + 7 EVM chain UX, Go signing core, Tauri/React design, Apache-2.0 | Key data encrypted *on USB* is not automatically equivalent to an air-gapped signing CPU; verify host memory/data flows |
| [AirGap Vault](https://github.com/airgap-it/airgap-vault) | Split signing/watching model, offline QR protocol | Targets spare phones rather than PC live USB |
| [Specter-DIY](https://github.com/cryptoadvance/specter-diy) | **MIT / direct-copy candidate**: Python PSBT/descriptor, removable-media and crypto-psbt QR workflow | Embedded target differs; reuse bounded host/transport patterns, not its whole runtime |
| [SignerOS](https://github.com/signeros/signeros) | Small stateless bootable live USB and Bitcoin PSBT workflows | **Design/reference only for now**: GUI subtree has MIT license, but reviewed `scripts/` / `buildroot-external/` files do not yet have a verified covering license |
| [Electrum](https://electrum.readthedocs.io/en/latest/coldstorage.html) | Cold/watching-only BTC wallet interaction | Not an EVM wallet |
| [Trezor firmware](https://github.com/trezor/trezor-firmware) | HD wallet verification, transaction UI and embedded security | Firmware targets specific hardware and licensing must be reviewed |
| [embit](https://github.com/diybitcoinhardware/embit) | **Dependency**: PSBT / Bitcoin BIP39, BIP32, BIP84 | Review library security / change history |
| [eth-account](https://github.com/ethereum/eth-account) | **Dependency**: EVM address generation and transaction signing | Does not create a trusted hardware boundary |
| [cryptography](https://github.com/pyca/cryptography) | **Dependency**: scrypt, AES-GCM | Host OS compromise remains out of scope |

Prefer protocol-compatible libraries over writing your own ECDSA, secp256k1, Keccak, AES or BIP32. Upstream license notices remain required when distributing upstream packages or source.

## Verified reuse evidence in current repository (2026-11-22)

These are **real dependency integrations confirmed from repository source/configuration**, not evidence of copied source code:

| Local evidence | Dependency / pinned input | Classification | Do not reinvent |
| --- | --- | --- | --- |
| `pyproject.toml`; `src/usb_cold_wallet/btc.py`; `src/usb_cold_wallet/companion_btc.py`; `src/usb_cold_wallet/keys.py`; `infra/embit.env` | `embit==0.8.0` | Dependency | PSBT parsing, BIP32/BIP39 derivation and Bitcoin primitives; keep local validation |
| `pyproject.toml`; `src/usb_cold_wallet/evm.py`; `src/usb_cold_wallet/companion_core.py` | `eth-account==0.14.0` | Dependency | Ethereum signing / transaction encoding; keep local chain/account/policy validation |
| `qr-transport/package.json`; `qr-transport/package-lock.json`; `qr-transport/src/typed_registry.mjs`; `qr-transport/src/ur_transport.mjs` | `@blockchaincommons/uniform-resources==1.0.0-beta.5`, `@blockchaincommons/dcbor==1.0.0-beta.5` | Dependency | UR/CBOR machinery |
| `qr-metamask/package.json`; `qr-metamask/package-lock.json`; `qr-metamask/src/adapter.mjs` | `@keystonehq/bc-ur-registry==0.8.1`, `@keystonehq/bc-ur-registry-eth==0.23.1`, `@ngraveio/bc-ur==1.1.13` | Dependency | Ethereum typed UR and QR registry |
| `infra/buildroot.env`; `scripts/fetch_buildroot.sh`; `scripts/configure_buildroot.sh` | Buildroot `2026.08.2`, archive SHA-256 pinned in `infra/buildroot.env` | Pinned build input / dependency | Live OS build system |\n| `scripts/generate_framebuffer_font.py`; `buildroot-external/package/usb-wallet-app/usb-wallet-app.mk` | `dhepper/font8x8@8e279d2d864e79128e96188a6b9526cfa3fbfef9`, exact path `font8x8_basic.h` | Copied/derived data: exact file header and upstream README state **Public Domain** | 1024 bytes of 8x8 Basic Latin bitmap data only; rows are bit-reversed and vertically doubled into deterministic PSF2; 0 executable source LOC copied |

**Source-copy status:** no wallet/signing source-copy from Specter-DIY, AirGap, BlueWallet, Keystone or SignerOS is present in this inspection. PR #79 copies only the 1024-byte bitmap table from the exact Public Domain `dhepper/font8x8` path above and transforms it into PSF2 at build time. The other projects remain Candidate/Reference sources unless a PR records the exact upstream commit, copied path/lines, path-level license coverage, required notices and local test evidence. `scripts/fetch_sources.sh` prepares authenticated build inputs; it is not evidence that wallet source was ported.

## Concrete upstream porting procedure

For an issue, locate the relevant row in `docs/USB_MVP_ACCELERATION_PLAN.md` (upstream commit and issue mapping), then inspect the **actual file/function** at that commit. A commit existing upstream is only provenance evidence; it does not prove a particular file is legally or technically suitable to copy. Record the exact path/function, file-level or covering license evidence, SPDX/header/NOTICE/copyright requirements, transitive dependencies and existing local equivalent. Prefer the smallest legal copy-and-adapt patch over a fresh rewrite where it genuinely saves effort.

Before copying, compare exact behavior and integration boundaries. A copied implementation must retain required attribution and pass local negative/security tests. If the upstream path is not yet licensed/verified, use it only as a reference. For SignerOS Buildroot/scripts, Trezor GPL components and Reown Community License code, do not directly copy without an explicit license review.

PRs must distinguish **copied/adapted source LOC**, **third-party dependency LOC**, and **newly authored LOC**. Include exact upstream commit and path; claiming 'reused upstream' without a traceable file or dependency is insufficient.

Research snapshot: November 2026. No audit or security endorsement of any referenced repository is implied.


## Fast-track copy policy

For the physical-USB MVP, prefer code that is both technically close and clearly reusable:

- **Candidate only until path-level clearance:** Specter-DIY, AirGap, BlueWallet and Blockchain Commons source. Repository-level license metadata is insufficient; pin the exact commit **and** verify the exact source path, headers/SPDX, NOTICE/copyright and dependencies before copying.
- **Reference-only until cleared:** SignerOS Buildroot/scripts; Trezor GPL firmware modules; Reown/WalletConnect Community License code. Do not copy GPL/LGPL/community/custom-license code into this MIT repository merely because the API or architecture is useful.
- **Do not replace already-hardened local core:** BTC PSBT signer, Sepolia native signer, vault/policy, canonical request/response binding and existing generic UR transport. Reuse upstream code only where it removes an actual remaining gap.

See [USB_MVP_ACCELERATION_PLAN.md](USB_MVP_ACCELERATION_PLAN.md) for the critical path and exact physical-validation scope.
