# Open-source design references and source licensing

This is an original MIT-licensed CLI with dependencies; **no code copied or vendored** from the projects listed here. Check upstream licenses and provenance before copying or linking any future source.

| Project | Role / applicability | Important caveat |
|---|---|---|
| [ArcSign](https://github.com/arcsignio/arcsign) | USB-focused BTC + 7 EVM chain UX, Go signing core, Tauri/React design, Apache-2.0 | Key data encrypted *on USB* is not automatically equivalent to an air-gapped signing CPU; verify host memory/data flows |
| [AirGap Vault](https://github.com/airgap-it/airgap-vault) | Split signing/watching model, offline QR protocol | Targets spare phones rather than PC live USB |
| [SignerOS](https://github.com/signeros/signeros) | Small stateless bootable live USB and Bitcoin PSBT workflows | Bitcoin-only at time of review; verify OS/build and license |
| [Electrum](https://electrum.readthedocs.io/en/latest/coldstorage.html) | Cold/watching-only BTC wallet interaction | Not an EVM wallet |
| [Trezor firmware](https://github.com/trezor/trezor-firmware) | HD wallet verification, transaction UI and embedded security | Firmware targets specific hardware and licensing must be reviewed |
| [embit](https://github.com/diybitcoinhardware/embit) | **Dependency**: PSBT / Bitcoin BIP39, BIP32, BIP84 | Review library security / change history |
| [eth-account](https://github.com/ethereum/eth-account) | **Dependency**: EVM address generation and transaction signing | Does not create a trusted hardware boundary |
| [cryptography](https://github.com/pyca/cryptography) | **Dependency**: scrypt, AES-GCM | Host OS compromise remains out of scope |

Prefer protocol-compatible libraries over writing your own ECDSA, secp256k1, Keccak, AES or BIP32. Upstream license notices remain required when distributing upstream packages or source.

Research snapshot: November 2026. No audit or security endorsement of any referenced repository is implied.
