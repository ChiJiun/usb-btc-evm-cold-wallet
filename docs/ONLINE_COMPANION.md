# Online Companion (Issue #17, Phase 1)

> **Experimental Sepolia / Bitcoin testnet-only research prototype. No audit; do not use with real funds.**
> This program is intentionally **ONLINE** and handles **public information only**. It does not import, create, recover or export a mnemonic, vault or private key.
>
> **Phase 1 status:** Sepolia native ETH transfer UI/JSON-RPC/request/export/signed-tx verification/broadcast/status is implemented and tested with a local fake RPC. BTC watch-only public address validation/display is implemented. Full BTC UTXO sync, PSBT builder/finalizer and BTC broadcast are **NOT YET implemented**; MetaMask/Snaps/WalletConnect and QR transport are separate issues (#22, #23, #18). The Offline GUI is #19, not part of this phase.

## Boundary between the two machines

| Connected Online Companion | Trusted physically offline USB Signer |
|---|---|
| Public watch-only BTC tpub / EVM Sepolia address | BIP39 seed and encrypted vault |
| Sepolia JSON-RPC, balance / nonce / gas | No RPC, no broadcasting |
| EIP-1559 **unsigned** transaction | Strictly re-check transaction and human-approved recipient / amount |
| Download `evm-request` envelope, USB-B transfer | Read request and produce `evm-signed` envelope |
| Independently decode **signed raw transaction**, recover sender, compare *all* fields | Never export private material |
| On a separate explicit click, broadcast raw signed tx and query status | No network connection |

Do **not** plug the private-key-bearing USB-A or its vault into the online computer. An ordinary USB does not have a Secure Element or its own trusted display. A malicious online computer can change the request and recalculate the exchange checksum; **only the offline human review is authorization**. USB-B must carry data files only, not programs to execute.

## 1. Prepare a public watch-only export

In the current `main` offline signer, on **trusted isolated hardware only**, after creating a test-only wallet:

```bash
usb-cold-wallet --vault /offline/wallet.vault addresses --count 3 > /transport/watch-only.json
```

Issue #5's pending PR adds an integrity-only envelope export:

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
usb-cold-companion --rpc-url https://YOUR-SEPOLIA-RPC --open-browser
```

Open `http://127.0.0.1:8765` if it does not launch automatically. Use an HTTPS Sepolia endpoint or a localhost HTTP node. The endpoint is selected **on the command line**, not from an untrusted browser request. Avoid credential-containing RPC URLs (shell history / process listing can disclose keys). Prefer a personal localhost node or a non-secret/public HTTPS endpoint for testing. The UI displays only the endpoint origin, not query parameters.

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

## 4. Limits / follow-ups

- **Bitcoin:** imported public Bitcoin testnet addresses are validated against the tpub and displayed. Existing #5 export does not provide the master key fingerprint / full descriptor required for robust PSBT construction, and this phase has **no** Bitcoin UTXO sync, fee estimation, PSBT creation/finalization or broadcast. Extend the public wallet export to a descriptor + master fingerprint and add independent test vectors before implementing BTC spending.
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