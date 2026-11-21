# Single-USB Windows ↔ Offline cross-boot UX

This integration completes the software-side single-USB flow for Issues #17, #19, #20 and #37 without changing Buildroot partition layout, mount policy, the release workflow, or the canonical transaction protocol.

## Protocol boundary

The request and response bytes remain the existing versioned `usb-cold-wallet-exchange` envelopes from `exchange.py` / `companion_envelope.py`. No second signer protocol is introduced.

The current v1 envelope does not contain a request ID. Until the coordinated Issue #37 protocol upgrade lands, the Windows Companion binds its random 128-bit local Request ID to:

- the immutable canonical request and its digest;
- the persisted watch-only account/network;
- the exact `request-<RequestID>.json` / `response-<RequestID>.json` filenames;
- and, most importantly, a full re-parse and cryptographic verification of the signed EVM transaction or BTC PSBT against the original request.

The filename/request ID is correlation metadata, not authentication. A signed response is never accepted because its filename matches.

## Normal operation

1. Start the zero-install Windows Companion from the USB.
2. Import/display the public watch-only BTC testnet / Sepolia account.
3. Create a transaction and inspect recipient, amount and maximum fee.
4. Press **儲存待簽交易至單 USB**.
5. Close the Companion completely.
6. Reboot and select this USB from the machine's UEFI boot menu.
7. In the Offline GUI press **單 USB：自動載入唯一待簽 Request**.
8. Unlock the Vault and encrypted offline policy.
9. Review every canonical page. BTC shows inputs, recipient/change outputs and fee. Sepolia shows chain/account, full recipient, value, nonce, gas and fee.
10. Acknowledge each page, type the SignerSession challenge and press the explicit sign button.
11. The GUI writes `response-<RequestID>.json` into the exchange directory.
12. Shut down the offline system and boot Windows again.
13. Launch Companion. It restores the public Pending Request and re-verifies the signed bytes. It never broadcasts during restore.
14. Inspect the verified transaction and press **Broadcast** manually.
15. Use the status button for pending/confirmed/failed or ambiguous broadcast recovery.

No normal step requires Python, Node, CLI, MetaMask or manual JSON editing.

## Persistent public state

The Windows side stores public state in:

```text
TX_TRANSFER/
└─ .usb-cold-wallet/
   ├─ pending-state.json
   └─ exchange/
      ├─ request-<32-lowercase-hex-RequestID>.json
      └─ response-<same-RequestID>.json
```

`pending-state.json` is bounded, checksummed and replaced after an fsync of the completed file. It contains no seed, mnemonic, private key, Vault plaintext or signing capability.

On restart, the Companion validates the state schema/checksum, validates the watch-only export, reconstructs the canonical request and re-runs the existing signed-response verifier before restoring a verified/broadcast state.

## Fail-closed recovery

The software refuses:

- zero or multiple usable `TX_TRANSFER` Windows volumes;
- multiple pending request files;
- response filenames that do not exactly match the active Request ID;
- multiple response candidates;
- malformed, oversized or checksum-modified persisted state;
- malformed or modified canonical request envelopes;
- signed EVM transactions with changed account, chainId, nonce, recipient, value, gas, fee or data;
- signed BTC PSBTs that change UTXOs, outputs, change, fee or signatures;
- duplicate broadcast after a restored `broadcasted` state.

A network timeout leaves the state as `broadcast_unknown`; recovery is status lookup only. There is no automatic resend, re-sign, fee bump or background broadcast.

The Offline GUI keeps the existing SignerSession timeout, auto-lock, challenge, cancellation and exception-lock behavior. USB removal or request-file replacement during an active review invalidates the transport and blocks signing.

## Evidence delivered by this PR

Automated tests use the public BIP39 `abandon ... about` test vector only. The cross-boot suite simulates:

- request persistence across a process/Windows restart;
- response discovery and re-verification after restart;
- malicious changed-recipient response rejection;
- ambiguous/stale request and response rejection;
- persisted-state tamper rejection;
- duplicate-broadcast prevention after restart;
- SignerSession lock clearing the single-USB request binding.

The UI itself still uses the canonical `review.py` / `policy.py` review model. Long addresses and values are rendered in scrollable, character-wrapped read-only text controls rather than truncated labels.

## Still requires physical acceptance

This PR intentionally does not modify Buildroot disk layout or mount policy. The current cold runtime still rejects `TX_TRANSFER` when it shares the same physical parent disk as the boot/Vault device. Therefore physical one-stick Windows → UEFI Offline GUI → Windows acceptance remains blocked until the dedicated Issue #37 partition/runtime integration lands.

The remaining real-device gate must verify Windows 10/11 volume discovery, actual GPT/FAT behavior, UEFI boot, Offline GUI startup, unplug/power-loss handling, two real reboots, and BTC testnet/Sepolia test transactions. No real seed is required or permitted for that validation.
