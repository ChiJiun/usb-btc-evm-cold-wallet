# Online Companion (Issue #17, Phase 1+2)

> **Experimental Sepolia / Bitcoin testnet-only research prototype. No audit; do not use with real funds.**
> This program is intentionally **ONLINE** and handles **public information only**. It does not import, create, recover or export a mnemonic, vault or private key.
>
> **Phase 1+2 status:** Sepolia native ETH transfer UI/JSON-RPC/request/export/signed-tx verification/broadcast/status is implemented and tested with a local fake RPC. Bitcoin testnet BIP84 **confirmed UTXO discovery, PSBT v0 construction, offline signer result verification/finalization, explicit broadcast and status** are now implemented against a **fake Esplora** in automated tests. This is NOT a real-world Bitcoin / Sepolia spending verification. MetaMask/Snaps/WalletConnect and QR transport are separate issues (#22, #23, #18). The Offline GUI is #19, not part of this phase.

## Boundary between the two machines

| Connected Online Companion | Trusted physically offline USB Signer |
|---|---|
| Public watch-only BTC tpub / EVM Sepolia address | BIP39 seed and encrypted vault |
| Sepolia JSON-RPC / Bitcoin testnet Esplora: balance, nonce / UTXO, gas / fees | No RPC, no broadcasting |
| EIP-1559 **unsigned** transaction or Bitcoin PSBT v0 | Strictly re-check transaction and human-approved recipient / amount / fees / change |
| Download `evm-request` or `btc-request` envelope via USB-B | Read request and produce `evm-signed` or `btc-signed` envelope |
| Independently decode **signed raw transaction**, recover sender, compare *all* fields | Never export private material |
| On a separate explicit click, broadcast raw signed tx and query status | No network connection |

Do **not** plug the private-key-bearing USB-A or its vault into the online computer. An ordinary USB does not have a Secure Element or its own trusted display. A malicious online computer can change the request and recalculate the exchange checksum; **only the offline human review is authorization**. USB-B must carry data files only, not programs to execute.

## Release packaging boundary — offline image must exclude Online Companion

This repository's default development wheel includes both the online UI and
the offline signer for integration testing. **Do not install the default wheel
in the trusted offline Live USB image.** Before creating the appliance, build
a separate network-free wheel from a verified development wheel:

```bash
python -m build --no-isolation --wheel --outdir dist
python scripts/build_offline_wheel.py dist/*.whl dist/offline
```

The offline-only wheel retains the reviewed signing modules and the
`usb-cold-wallet` command; it excludes `companion_core.py`,
`companion_btc.py`, `companion_web.py`, bundled browser assets, and
`usb-cold-companion`. The builder uses a strict allowlist of cold-side
Python modules: any newly added wallet module fails the release build until
explicitly security reviewed. It regenerates and verifies the wheel RECORD.

The test suite validates wheel filtering and rejects unreviewed modules.
In GitHub Actions, it also builds the actual Python wheel and installs the
sanitized offline output into a temporary test directory, asserting that no
online module, browser asset or companion command exists. The separate
Live USB builder (#7) must **install only this verified offline wheel** and
check the image contents before an offline boot image can be accepted;
this appliance-level requirement is not yet implemented in #7. Online RPC,
Esplora, HTTP server, and web assets are never valid cold-side runtime
dependencies.

The Online Companion's `pack_envelope` / `unpack_envelope` now use the
same #11 strict validators as the offline signer. A SHA-256 exchange digest
is an integrity check, **never permission to sign or broadcast**.

## 1. Prepare a public watch-only export

On a **trusted physically isolated** signer, after creating a test-only wallet:

```bash
usb-cold-wallet --vault /offline/wallet.vault addresses --count 3 > /transport/watch-only.json
```

The merged #11 USB exchange interface provides integrity-only envelope export:

```bash
usb-cold-wallet --vault /offline/wallet.vault export-watch-only \
  --count 3 --out /transport/watch-only.json
```

The browser accepts **either** the original public JSON or #5's `watch-only` envelope. It checks Sepolia chainId = 11155111, EVM derivation path and address checksum, and independently derives the visible Bitcoin testnet receiving addresses from the public account tpub. This does **not** prove the file came from your specific offline wallet; compare the full address on both machines before funding.

A Bitcoin testnet tpub is non-secret public key data, but disclosing it impacts privacy.

## 2. Start the online UI

On the **ONLINE** computer only:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
usb-cold-companion --rpc-url https://YOUR-SEPOLIA-RPC \
  --btc-esplora https://blockstream.info/testnet/api \
  --open-browser
```

Open `http://127.0.0.1:8765` if it does not launch automatically. Use an HTTPS Sepolia endpoint or a localhost HTTP node. The endpoint is selected **on the command line**, not from an untrusted browser request. Avoid credential-containing RPC URLs (shell history / process listing can disclose keys). Prefer a personal localhost node or a non-secret/public HTTPS endpoint for testing. The UI displays only the endpoint origin, not query parameters.

The BTC Esplora URL must be HTTPS or a localhost HTTP node; requests use bounded responses, no redirects and no automatic re-send. The default public explorer can see your wallet's queried addresses, which **reduces privacy**. For meaningful wallet privacy, run an independently verified local Electrs/Esplora service.

The app only binds `127.0.0.1`, uses an ephemeral local API token, rejects non-local Host/Origin on writes, prevents cross-origin API access, has a restrictive CSP, and does not store the watch-only account/session in browser persistent storage. The pending transaction is **volatile**: restarting the server clears it. It is not a multiuser, remote/cloud-hosted wallet.

## 3. Spend **test** ETH

1. Import `watch-only.json` using the browser's file picker.
2. Click **更新餘額與預估費用**. The UI checks the RPC's `eth_chainId` and shows balance, pending nonce and gas estimates.
3. Enter full recipient address, ETH amount, and optional max fee (Gwei); click **建立並核對交易**. The server prepares a type-2 **Sepolia** native transfer with `gas=21000`, no calldata or access list, shows recipient, amount, nonce, maximum fee, maximum spend and a SHA-256 digest. It rejects insufficient balance and implausible fee quotes.
4. Download `evm-request` envelope (**#5 offline signer**) or **舊版 JSON** (current `main` signer). Copy the data file to transport USB-B. This version does **not** implement QR.
5. On your **physically offline** Signer, independently check full recipient and amount, unlock, review, and sign. For #5 signer:
   ```bash
   usb-cold-wallet --vault /offline/wallet.vault sign-evm \
     --request /transport/sepolia-unsigned-REQUEST_ID.json \
     --to 0xYOUR_INDEPENDENTLY_VERIFIED_RECIPIENT \
     --wei EXACT_AMOUNT_IN_WEI \
     --out /transport/sepolia-signed.json
   ```
   For the current `main` signer use `--tx /transport/sepolia-legacy-REQUEST_ID.json` instead of `--request`. **Do not trust the online display as your only source for recipient/amount.** This CLI step remains until the future #19 offline GUI.
6. Copy signed output on USB-B to the online computer; choose **驗證離線簽章** in Companion. It supports the #5 `evm-signed` envelope **and** the legacy signed JSON. The Companion parses the raw EIP-1559 transaction, recovers the signer, and compares **chainId, sender, nonce, recipient, value, gas, both fee caps, calldata, access list, and tx hash** with the still-pending session. Only an exact match moves to `verified`.
7. Explicitly click **確認廣播已驗證的交易**. It rechecks the network and pending nonce, submits the **unchanged** raw signed tx with `eth_sendRawTransaction` and checks the returned hash. It will never auto-sign, auto-fee-bump, or auto-resend on timeout.
8. Click **查詢鏈上狀態**. This displays RPC-observed pending / included-success / reverted / not-found, with a warning on detected suspected reorg. Inclusion alone is not economic finality; do not confuse a single receipt with many confirmations.

**Local request ID and SHA-256 digest:** These are kept in the online session; the existing #5 v1 cold-signer reply does not echo a requestId. The Companion therefore binds the response by **recovering the sender and comparing every actual signed transaction field**, not by trusting a claim in the returned metadata. Adding a versioned cold-side request/response ID with digest echo requires coordinated #5 protocol changes; it is not silently claimed here.

## 4. Bitcoin testnet BIP84 transfer (new Phase 2)

1. From the offline signer (updated source), export **public** watch-only data as shown in §1. The Bitcoin section now includes public `master_fingerprint`, required to generate correct BIP32 derivation paths. **Older exports without it remain read-only.** This fingerprint and the tpub do not prove their own authenticity; compare BTC receive addresses and fingerprint against the trusted offline machine.
2. In Online Companion, choose **查詢 BTC 已確認餘額**. The configured Bitcoin testnet Esplora API queries confirmed UTXOs for the *exported* receiving address count and up to 20 internal change addresses. This is **limited discovery**, not a full wallet history synchronizer. Public Esplora sees your queried addresses.
3. Enter a **Bitcoin testnet native SegWit P2WPKH address**, BTC amount, optional fee rate (sat/vB), and maximum absolute miner fee (sats). The Companion selects up to 20 confirmed UTXOs, fetches their **original raw transactions** and independently verifies outpoint TXID/index, input value and script. It uses a conservative fee estimate, detects previously used change addresses from Esplora's chain+mem pool counters, sets no RBF / no locktime and builds BIP174 PSBT v0 with witness and non-witness prevouts plus BIP84 master fingerprint/path.
4. Download **BTC PSBT 交換檔** for the pending #5 CLI (`btc-request` envelope) or **舊版 PSBT** for current main CLI (`--psbt` argument). Copy only the data file to USB-B and take it to physically offline computer.
5. Independently verify the complete recipient, amount, maximum miner fee and **actual change index** in the Offline Signer. Example (for #5's signer):
   ```bash
   usb-cold-wallet --vault /offline/wallet.vault sign-btc \
     --request /transport/bitcoin-testnet-unsigned-REQUEST_ID.json \
     --to tb1qINDEPENDENTLY_VERIFIED_DESTINATION \
     --sats EXACT_SATOSHIS --max-fee-sats MAX_SATS \
     --change-index CHANGE_INDEX \
     --out /transport/bitcoin-testnet-signed.json
   ```
   For legacy main signer use `--psbt /transport/bitcoin-testnet-legacy-REQUEST_ID.psbt` rather than `--request`. If no change output, **omit** `--change-index`. Both signers must review/sign independently, and the hardened #2 branch imposes stronger independent PSBT validation. Do not sign anything based only on the connected PC's display.
6. Bring the signed JSON / #5 `btc-signed` envelope back to Online Companion and choose **驗證簽署 PSBT**. The Companion independently verifies each ECDSA signature, its sighash type, **all** PSBT unsigned fields and metadata against the original, and finalizes only the expected P2WPKH witnesses. Optional hardened-signer `finalized_tx_hex` must match the locally built signed transaction exactly.
7. **Explicitly** click **確認廣播 BTC Testnet** to submit the exact, already verified transaction to your configured Esplora. If transmission times out, treat it as ambiguous: **do not automatically resend**. Query the transaction ID and independently inspect the network before rebuilding.
8. Use **查詢 BTC 交易狀態** for mempool / confirmed / possible reorganization status. A public explorer is not a trusted consensus source, and a reported confirmation does not mean irreversibility.

Constraints: BIP84 testnet P2WPKH single-recipient payments only; maximum 20 inputs, two outputs, 20 change addresses, confirmed UTXOs only, absolute fee ceiling 50,000 sats, fee rate ceiling 250 sat/vB, no RBF or arbitrary scripts, no mainnet. Coin selection, current fee quote, change-address history and UTXO status depend on an **untrusted** Esplora. Multiple devices/wallet apps sharing the same xpub could produce change address reuse or spend conflicts; never trust the online scanner to be exhaustive. An offline signer cannot prove a UTXO is currently unspent. A full descriptor, master fingerprint attestation, robust gap-limit discovery, Bitcoin Core/Sparrow cross-reference fixtures and hardware acceptance are still future security requirements.

## 5. Limits / follow-ups

- **Bitcoin:** BIP84 P2WPKH **testnet only**, PSBT v0, 1–20 inputs, 1 recipient and optional change, transaction version 2/locktime 0/no RBF. Only confirmed UTXOs are considered, and raw previous transactions are checked against Esplora's claimed TXIDs, scripts and values. The new watch-only export includes a *public* `master_fingerprint`; older exports can still be viewed but **cannot create PSBT** until they are re-exported. This metadata does not independently authenticate the tpub: compare with the offline device. Current discovery scans the number of exported receiving addresses plus 20 change addresses; it is **not a complete account-history/gap-limit wallet**, cannot safely spend every possible BIP84 account UTXO, and may reuse an address if Esplora lies about its history. See the BTC section above. Independent Bitcoin Core/Sparrow end-to-end fixtures and extended descriptor discovery remain security work before broader release.
- **EVM:** Sepolia native ETH only. Unknown contract data, ERC-20, ERC-721, approvals, EIP-712, `personal_sign`, `eth_sign`, mainnet and arbitrary chain switching are unsupported. These must not be passed through via blind signing.
- **Session / persistence:** if the online Companion crashes or restarts after broadcasting, it loses the current transaction state; the transaction could already be in the network. Verify using the previously displayed/recorded Tx Hash before building a replacement. A returned RPC error or `not_found` does not prove the tx was never accepted.
- **RPC trust:** the online endpoint can lie about balance, nonce, gas quote, simulation or receipts. The offline signer knows none of this state and must independently check transaction policy. Showing an explorer result does not authenticate its contents.
- **Deployment:** run the Online Companion only on your own desktop, not as a public service, remote VM web server, browser extension, or shared server. Use a disposable known-compromised test vector in automated tests only.
- **Hardware sign-off:** no real physical offline setup or chain transaction was performed in CI/Devspace. The automated tests use fake RPC and publicly compromised mnemonic, not production funds.

## Developer tests

```bash
pytest -q
python -m compileall -q src tests
python -m build --wheel --no-isolation
```

See #17, #18, #19, #24 for the remaining product/security gates.