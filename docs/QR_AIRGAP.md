# QR air-gap transport prototype — Issue #18

**Research only: Bitcoin testnet and Ethereum Sepolia. No real wallet funds.
Not an externally interoperable ERC-4527/crypto-psbt implementation yet.**
This builds the complete generic UR **transport** and a chain-aware signature
binding layer, but registry-specific UR types are a separate remaining task.
**QR transport never grants signing authorization.**

## Implementation

- Browser: `qr-transport/` produces single-frame `ur:bytes` or fountain-coded
  multi-frame Blockchain Commons URs. Decodes through the official
  `@blockchaincommons/uniform-resources` package. Uses `qrcode` for rendering
  and ZXing for the **local** camera.
- Trust boundary: `src/usb_cold_wallet/qr_session.py` defines strict v1
  `SignRequest`/`SignResponse` JSON envelopes with network, account,
  32-hex request ID, full payload digest and response-to-request digest;
  `qr_workflow.py` checks the unlocked wallet, policy and raw signed
  transaction or BTC PSBT signatures.
- `usb-cold-wallet-qr`: standalone CLI. Uses no RPC/broadcast code. On the
  offline computer it verifies the independently recorded SHA-256 of the
  wallet-bound encrypted policy **before vault unlock**, enforces the same
  BTC/EVM policy as the CLI and GUI, displays recipient and actual fees, and
  requires separate typed confirmation for an unverified recipient. Missing,
  expired or mismatched policy, or a value/fee above its caps, always denies signing.
- The QR wrapper is `UR:BYTES` carrying an ASCII-only compact JSON message.
  This is a **standards-based UR framing format**, but is NOT yet the
  `eth-sign-request`/`eth-signature` ERC-4527 CBOR schema or interoperable
  `crypto-psbt` typed payload. Never claim external wallet compatibility.
- Frame limits: QR payload 150 KB, <=512 observed distinct frames, max frame
  3,000 characters, fragment length <=480 bytes and 120-second scan deadline
  **starting with the first received frame**, not at page load.
  Reject malformed, mixed, duplicate-key, unknown-network, incorrect-digest,
  unknown-version and oversize input. Repeated individual frames are ignored;
  a second finished response requires resetting scanner state. File imports
  are bounded, reject symlinks and nonregular files.

## Build the local-only QR display and scanner

On a trusted build environment:

```bash
cd qr-transport
npm ci
npm test
npm run build
```

Move the complete, trusted, hashed `dist/` directory to the receiving host.
On each physically isolated host, serve **locally only** (not on external
network interfaces):

```bash
cd qr-transport/dist
python3 -m http.server --bind 127.0.0.1 8765
```

Visit `http://127.0.0.1:8765`. Browser camera permission works on
`localhost` / `127.0.0.1` secure context on supported browsers.
The built page has a restrictive CSP; no remote APIs, scripts or fonts.
Use **only a trusted camera attached directly to the offline machine**.
Camera functionality is not tested on physical hardware in Devspace.

The browser only displays and scans; it never imports a vault, invokes a
signer, signs transactions or broadcasts to a chain.

**Lossless wei support:** The browser requires a JavaScript engine with
`JSON.parse` reviver `context.source` (Node 22+/current Chromium-based browsers).
If unsupported, numeric requests fail closed rather than silently rounding
amounts above `Number.MAX_SAFE_INTEGER`. Import the original JSON as text,
and export exact integer tokens without `JSON.stringify` on rounded Numbers.
The CI interoperability test exercises Python `prepare-evm` → browser UR
encode/decode → offline Python signing → browser UR → Python verification at
0.01 ETH, 1 ETH, and values just over 2^53 wei.

## Example: Sepolia QR roundtrip

On the online watch-only host:

```bash
usb-cold-wallet-qr prepare-evm \
  --tx unsigned-sepolia.json \
  --account 0xYOUR_WATCH_ONLY_SEPOLIA_ACCOUNT \
  --to 0xYOUR_INDEPENDENTLY_VERIFIED_RECIPIENT \
  --wei 1000000000000 \
  --out sepolia-request.json
```

Import `sepolia-request.json` into the online QR page, point the trusted
**offline** camera at the online display. When the offline page completes,
download the restored unsigned JSON. The offline host must independently
review the **recipient and amount** (not simply copy them from the QR):

```bash
usb-cold-wallet-qr offline-sign --offline-ack \
  --vault /offline/wallet.vault \
  --request /offline/scanned-request.json \
  --to 0xYOUR_INDEPENDENTLY_VERIFIED_RECIPIENT \
  --amount 1000000000000 \
  --expected-policy-sha256 CURRENT_INDEPENDENT_POLICY_SHA256 \
  --out /offline/signed-response.json
```

Import signed response JSON into the **offline** QR page. Scan it with the
online camera, download it and validate it against the original stored
request:

```bash
usb-cold-wallet-qr verify-evm \
  --request sepolia-request.json --response signed-response.json
```

Verification checks Sepolia chain ID, full unsigned nonce/gas/fee/value,
recipient, empty calldata/access list, signature recovery, transaction hash,
maximum fee/total and the full decoded signed-transaction metadata against raw
signed bytes and account binding. This **does not broadcast**. External wallet/node code must
separately handle broadcast, nonce freshness and finality.

## Bitcoin testnet

```bash
usb-cold-wallet-qr prepare-btc \
  --psbt unsigned.psbt \
  --fingerprint YOUR_FIRST_8_HEX_MASTER_FINGERPRINT \
  --to tb1YOUR_INDEPENDENTLY_VERIFIED_TESTNET_RECIPIENT \
  --sats 50000 --max-fee-sats 1500 --change-index 0 \
  --out btc-request.json
```

Transfer the JSON by QR. Offline `offline-sign` requires identical
independently reviewed `--to`, `--amount 50000`, `--max-fee-sats 1500`,
`--change-index 0` and `--expected-policy-sha256` from a trusted independent
record. Any excess Bitcoin miner fee is denied by the shared policy. Return
signed JSON by QR and run
`usb-cold-wallet-qr verify-btc --request btc-request.json
--response btc-response.json` on the online host. This checks that the
unsigned transaction remained unchanged, P2WPKH witness UTXOs and all
ECDSA/SIGHASH_ALL signatures match, output amount/recipient and fee policy.
It also strictly parses the submitted finalized raw transaction, checks its
base transaction byte-for-byte against the unsigned PSBT, and matches every
input witness to the independently verified signed PSBT.
It does **not** assert UTXOs are unspent or perform full consensus
script validation; prefer Bitcoin Core validation before broadcast.

## Failure / cancel / USB-B fallback

- Scanner start error (camera denied/absent), timeout or malformed fragments:
  stop camera, press **重新掃描** to reset, and retry; **no automatic signing**.
- Online verification must correlate the original requestId and digest.
  A cancelled or expired `QRSession` refuses results; the same session
  can consume its response only once. Replaying in a new independent
  process still needs chain nonce / UTXO checks and manual approval.
- USB-B exchange from merged #11 and the Online Companion from merged #26
  remain supported. The QR signer uses the same fail-closed #28 offline
  policy decision as the CLI and GUI; this PR does **not** alter the existing
  `sign-evm --tx` or `sign-btc --psbt` fallback paths.
- Never scan a QR containing a mnemonic, seed, private key, decrypted vault
  or login/authorization token. Avoid QR/HID virtual keyboard bridges.
- BadUSB, malicious video firmware, OS malware, malicious QR encoding,
  side-channel leakage and unlocked seed in RAM remain threats. Data digest
  is not sender authentication.

## Known remaining acceptance gaps

1. Replace private `ur:bytes` JSON body with interoperable **ERC-4527
   `eth-sign-request`/`eth-signature` CBOR** and Blockchain Commons
   **`crypto-psbt`** types; test against independently implemented wallets.
2. Integrate GUI state with the Issue #13 Online Companion / Issue #15
   Offline GUI, and add actual QR rendering/scan controls for those apps.
3. Validate both physical computers and cameras, conduct malicious QR
   camera/decoder fuzzing with instrumentation, review memory and decoder
   allocations, and ensure builds include the pinned QR package wheel/bundle.
4. Integrate Issue #5 USB envelope and Issue #2/#3 signer hardening after their
   PRs merge, then run combined CI, QEMU/UEFI and hardware tests.
5. No automatic broadcast, approval or network use is implemented. Never
   enable mainnet until independent security review and operational testing.
