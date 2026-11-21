# Single-USB Windows ↔ Offline cross-boot UX

This integration consumes the formal Issue #37 v2 request/response contract and state ownership model. It does not change Buildroot partition layout, mount policy, or release workflows.

## On-wire contract

Every cross-boot transaction uses the canonical v2 fields implemented by `cross_boot.py`:

- 128-bit lowercase `requestId`
- `network`, `account`, `transactionDigest`
- independently derived `intent` (recipient, amount, fee, nonce/UTXOs)
- explicit expiry mode
- signed response binding through `requestEnvelopeDigest` and `signedResultDigest`

The single-USB flow uses the formal restricted `no-trusted-clock` mode because FAT32 timestamps and the offline RTC are not trusted. The UI/state therefore reports `expiryAssurance=unverified`; durable cold replay protection plus the full human review remain mandatory.

The Windows Portable EXE intentionally does not bundle `cross_boot.py`, `btc.py`, `evm.py`, `keys.py`, `vault.py`, or other offline signer modules. `companion_crossboot.py` is a public-only adapter for the exact same v2 wire schema, and integration tests require requests emitted by it to pass the formal `verify_v2_request` API and responses produced by the formal `package_v2_response` / `verify_v2_response` APIs.

## Durable state

Windows uses the formal `PendingRequestStore` transitions:

```text
DRAFT -> EXPORTED -> IMPORTED_VERIFIED -> BROADCAST_REQUESTED -> BROADCASTED
              \-> FAILED
```

The cold side uses the formal `ReplayLedger`:

```text
COLD_REVIEWED -> SIGNED
           \-> FAILED
```

Both are append-only hash-chained journals. They detect visible corruption/reordering but do not claim whole-store rollback resistance without an external monotonic anchor.

Public files live under:

```text
TX_TRANSFER/
└─ .usb-cold-wallet/
   ├─ watch-only.json
   ├─ state/
   │  ├─ online/
   │  └─ cold/
   └─ exchange/
      ├─ request-<requestId>.json
      └─ response-<requestId>.json
```

No seed, mnemonic, private key, Vault plaintext, or signing capability is persisted by the Windows Companion.

## Operator flow

1. Start the Windows Portable Companion.
2. Display/import the public BTC testnet and Sepolia watch-only account.
3. Create a transaction and inspect recipient, amount and maximum fee.
4. Press **儲存待簽交易至單 USB**.
5. Close Companion completely.
6. Reboot and choose the same USB from the UEFI boot menu.
7. In Offline GUI press **單 USB：自動載入唯一待簽 Request**.
8. Unlock the Vault. The GUI verifies the formal v2 request against the actual signing account.
9. Review the existing canonical pages. BTC displays UTXOs, full recipient/change and fee. Sepolia displays chain/account, full address, value, nonce, gas and maximum fee.
10. Acknowledge every page, enter the SignerSession challenge, then explicitly sign.
11. Immediately before signing, the cold `ReplayLedger` rejects reused `requestId` or a transaction digest already reviewed under another ID.
12. Export writes `response-<requestId>.json` create-only and then records `SIGNED`. If power is lost after the completed response is published but before the ledger update, re-export verifies the existing response and safely completes the ledger transition.
13. Shut down the offline system and boot Windows.
14. Companion restores `EXPORTED`, discovers the response, verifies v2 binding, re-runs the existing EVM raw transaction / BTC PSBT verifier, and advances to `IMPORTED_VERIFIED`.
15. Broadcast remains an explicit button. Successful send advances to `BROADCASTED`; there is no background or automatic broadcast.

Normal operation requires no Python, Node, CLI, MetaMask, or manual JSON editing.

## Failure recovery

- Missing or multiple `TX_TRANSFER` Windows volumes fail closed.
- Multiple active requests, filename/requestId mismatch, malformed or modified v2 envelopes, account/network mismatch, changed recipient/amount/fee/nonce/UTXO, replay, and stale signatures fail closed.
- Explicit cancel records `FAILED` and removes only that request's exchange files.
- Immediately before network I/O, Broadcast durably records `BROADCAST_REQUESTED` with the exact txid. A timeout/crash leaves that reservation in place; restart reconstructs a `broadcast_unknown` session for **status lookup only** and cannot resend it.
- Completed response + interrupted cold ledger update is recoverable without signing again.
- SignerSession still provides auto-lock, idle timeout, per-transaction challenge, cancellation, exception locking and attended-session signature quota.
- Full addresses and values use scrollable character-wrapped read-only fields rather than truncated labels.

## Automated evidence

The integration suite uses only the public BIP39 `abandon ... about` test vector and mock network/filesystem data. It covers:

- adapter request accepted by the formal v2 verifier;
- formal Sepolia response across simulated Windows restart;
- malicious changed-recipient signed result rejection even after attacker recomputes public envelope hashes;
- BTC PSBT v2 round-trip across simulated restart;
- formal online journal transition and explicit cancel cleanup;
- restart auto-import of a valid response with zero automatic broadcasts;
- successful explicit broadcast followed by restart with duplicate broadcast blocked;
- ambiguous broadcast restart recovery as status-only;
- browser UI export controls with no broadcast side effect;
- SignerSession lock clearing the active single-USB binding;
- formal Agent #37 state/replay/corruption tests.

## Physical acceptance still pending

This PR does not change Buildroot disk layout or single-USB mount policy. The physical one-stick Windows → UEFI Offline GUI → Windows gate remains dependent on the separate Issue #37 partition/runtime integration. Real-device acceptance must still cover Windows 10/11 volume discovery, actual GPT/FAT behavior, UEFI boot, GUI startup, unplug/power-loss behavior, two real reboots, and BTC testnet/Sepolia test transactions. No real seed is required or permitted.
