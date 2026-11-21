# QR air-gap transport prototype — Issue #18

**Research only: Bitcoin testnet and Ethereum Sepolia. No real wallet funds.**
The browser's existing `ur:bytes` path remains the internal v1 JSON envelope
transport. An **independent experimental typed UR codec** now supports
ERC-4527 `eth-sign-request` / `eth-signature` and BCR-2020-006
`crypto-psbt` CBOR layouts, but **has not been wired into the signing GUI or
verified against physical third-party wallet devices**.
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
  offline computer, asks for an independently sourced recipient/amount,
  displays network and fees, demands typed confirmation, and only then signs.
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

## Typed registry codec (experimental; not connected to GUI/signing)

The separate `qr-transport/src/typed_registry.mjs` module implements:

- `ur:eth-sign-request`: integer-key CBOR map with request UUID as tag 37,
  raw unsigned **type-2 EIP-2718** transaction bytes (key 2), sign-data-type
  4 (key 3), Sepolia `chainId=11155111` (key 4), derivation path with hardened
  flags and source fingerprint under tag 304 (key 5), and mandatory 20-byte
  signer address (key 6). This EIP remains **stagnant** upstream.
- `ur:eth-signature`: integer-key map containing the same tagged request UUID
  and exactly 65 **r,s,v** bytes. This standard message **does not carry a
  signed raw transaction**, the original JSON request digest, or a broadcast
  instruction. An online wallet must independently check recovered signer
  and every transaction field before use.
- `ur:crypto-psbt`: **bare CBOR byte string** holding the original PSBT,
  starting `70736274ff`. It is not our JSON envelope, nor a CBOR map. Both
  unsigned and partially signed PSBTs use the same UR type.

`makeTypedUR`, `parseTypedUR`, `encodeTypedFrames`,
`TypedURScanner`, and `bindTypedToPending` are distinct from
`encodeFrames` / `BoundedURScanner`; the latter intentionally accepts
**only** `ur:bytes` and continues to require the internal v1 envelope.
The typed scanner bounds frame size, aggregate scan text, fragment counts and time, and rejects mixed fragment counts; the parsed CBOR tree also has explicit nesting/container limits. The upstream UR/dCBOR decoder still performs initial CBOR materialization, so its internal allocation limit must be verified before accepting arbitrary camera input in production;
the explicit pending-binding function checks request ID, EVM derivation path and fingerprint, trusted BTC testnet account ID/fingerprint, chain, payload digest and expiry. For signed responses it synchronously consumes the mutable pending session after successful independent verification; callers must pass their real authoritative session object, not a copied snapshot. The bare crypto-psbt UR has no chain or account identifier, so account context and PSBT policy must come from the trusted session, not the UR. For an `eth-signature`
response, `bindTypedToPending` additionally **requires**
`verifySignature(parsed,pending) === true`; for signed `crypto-psbt` it
requires `verifySignedPsbt(parsed,pending) === true`. A missing, false,
or asynchronous callback is rejected. The callback must independently
compare the original unsigned transaction/PSBT, signer, chain, outputs,
fee and actual signature before returning true; **this repository has
not yet connected those callbacks to the real GUI/signing workflow.**
**No calling code should sign or broadcast solely because a typed frame
parsed or was bound.** The final signing request must pass the offline
transaction parser, user review, Policy Engine and independent signed
transaction / PSBT verification.
The UR type itself does not authenticate its sender.

Run `cd qr-transport && npm ci --ignore-scripts && npm test && npm run build`.
Node regression tests check the CBOR layout through an independent Python
stdlib oracle and rejection cases. The existing generic Python↔Node
`ur:bytes` flow is preserved and tested separately. Real Keystone /
Blockchain Commons device interoperability and the actual camera GUI wiring
remain pending #18/#56/#24 acceptance; the typed codec is not an
end-to-end wallet integration.

References: [ERC-4527](https://eips.ethereum.org/EIPS/eip-4527)
(CC0, stagnant), [Blockchain Commons PSBT UR guide](https://developer.blockchaincommons.com/ur/psbts/),
[Blockchain Commons dCBOR](https://github.com/BlockchainCommons/bc-dcbor-ts)
and [UR encoder](https://github.com/BlockchainCommons/bc-ur-ts);
both pinned packages are currently beta under BSD-2-Clause-Patent.

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
download the restored unsigned JSON. The offline host must independently review the **recipient, amount, and
current encrypted policy SHA-256** (not simply copy them from the QR). Before
signing, create the wallet-bound `<vault>.policy` with the offline CLI `policy
--action init`; retain its SHA-256 independently on paper. Every QR signature
requires that exact current anchor and the policy encryption passphrase.
Missing, stale, or incorrect policy fails before vault unlock. Unknown
recipients require an extra typed confirmation; BTC/EVM policy caps apply to
QR as well as USB and GUI signing:

```bash
usb-cold-wallet-qr offline-sign --offline-ack \
  --vault /offline/wallet.vault \
  --expected-policy-sha256 INDEPENDENT_CURRENT_POLICY_SHA256 \
  --request /offline/scanned-request.json \
  --to 0xYOUR_INDEPENDENTLY_VERIFIED_RECIPIENT \
  --amount 1000000000000 --out /offline/signed-response.json
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
independently reviewed `--to`, `--amount 50000`, `--max-fee-sats 1500`
and `--change-index 0`, plus `--expected-policy-sha256` from the independent
current policy backup. Return the signed JSON by QR and run
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
- USB-B file exchange from merged Issue #5 remains a supported operational
  fallback. It uses the same mandatory policy SHA-256. QR uses UR:BYTES to
  carry its own app schema; it does not implement ERC-4527/crypto-psbt
  interoperability with external wallets. This PR does **not** alter the existing
  `sign-evm --tx` or `sign-btc --psbt` fallback paths.
- Never scan a QR containing a mnemonic, seed, private key, decrypted vault
  or login/authorization token. Avoid QR/HID virtual keyboard bridges.
- BadUSB, malicious video firmware, OS malware, malicious QR encoding,
  side-channel leakage and unlocked seed in RAM remain threats. Data digest
  is not sender authentication.

## Known remaining acceptance gaps

1. Wire the experimental **ERC-4527 / crypto-psbt CBOR typed codec** into the
   online/offline application adapters with the same immutable request/session
   binding and trusted offline signer policy, then test against independent
   wallets (Keystone/other registry implementation). The internal `ur:bytes`
   envelope remains supported; do not silently reinterpret it as a typed UR.
2. Integrate GUI state with the Issue #13 Online Companion / Issue #15
   Offline GUI, and add actual QR rendering/scan controls for those apps.
3. Validate both physical computers and cameras, conduct malicious QR
   camera/decoder fuzzing with instrumentation, review memory and decoder
   allocations, and ensure builds include the pinned QR package wheel/bundle.
4. Integrate Issue #5 USB envelope and Issue #2/#3 signer hardening after their
   PRs merge, then run combined CI, QEMU/UEFI and hardware tests.
5. No automatic broadcast, approval or network use is implemented. Never
   enable mainnet until independent security review and operational testing.


Typed QR security note: the scanner now validates bytewords, inner fountain-part header and raw CBOR depth/length before upstream FountainDecoder and dCBOR recursive materialization. No camera/GUI integration is enabled.
