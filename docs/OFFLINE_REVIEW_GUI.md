# Offline transaction-review GUI

> **TESTNET research only. Do not use real assets.**

Issue #19 adds a local Tk/ttk review surface on top of the existing offline
signing backend. The GUI is intentionally not a WebView: it contains no browser,
JavaScript runtime, RPC client, remote content, plugin loader, or online
simulation.

## Trust boundary

The online computer, QR payload and TX_TRANSFER USB-B are all untrusted.

The offline flow is:

```
verified boot/runtime audit
        |
        v
unlock encrypted vault in RAM
        |
        +--------------------+
        |                    |
  USB-B envelope        QR-decoded text
        |                    |
        +---- exchange.decode/read ----+
                                       |
                              strict envelope schema
                              bounded JSON + SHA-256
                                       |
                                       v
                           offline canonical review
                         /                         \
                EVM backend policy           BTC backend policy
                         \                         /
                          +---- ReviewPlan -------+
                                full values
                                field sources
                                request digest
                                review digest
                                       |
                              one page at a time
                              explicit checkbox/page
                              typed final challenge
                                       |
                              re-review same payload
                                       |
                              existing signer backend
                                       |
                        signed exchange envelope
                          /                   \
                     USB-B                QR adapter (#18)
```

The GUI never trusts an Online-provided human-readable summary. For EVM it
derives chain ID, recipient, value, nonce, gas and fee fields from the raw
transaction object and then calls `review_evm_transaction`. For Bitcoin it
parses the PSBT with the signer backend, identifies wallet change from the
offline BIP84 root, derives the sole non-change recipient, and then calls
`review_btc_psbt`.

## Digest binding

Every review has two hashes:

- **request SHA-256** — the hash from the verified #5 exchange envelope. It is an
  integrity checksum, **not sender authentication**.
- **review SHA-256** — SHA-256 of the canonical fields rendered from the offline
  parser/policy result, including the signing account and field provenance.

All pages are acknowledged against the current review digest. A changed digest
clears every acknowledgement and the final challenge. Immediately before
signing, the exact in-memory request is reviewed again with the current wallet
root. If the reviewed fields or wallet account differ, signing fails closed.

The final confirmation is deliberately not bound to Enter. The user must:

1. acknowledge every review page separately;
2. type the exact challenge containing transaction type, recipient suffix and
   review-digest prefix;
3. explicitly activate **Confirm signing**.

After the signature is produced, the GUI immediately drops its wallet-root
reference. The signed transaction is public data and may then be exported to
USB-B or passed to a future #18 signed-QR presenter.

## Displayed fields

### Sepolia

- explicit Ethereum Sepolia / chainId 11155111;
- derived signing account;
- full recipient address;
- amount in wei and ETH;
- nonce;
- gas limit;
- max priority fee per gas;
- max fee per gas;
- maximum network fee;
- maximum total spend;
- calldata/access-list state;
- explicit contract-call rejection.

Contract calldata remains rejected by the existing signer. #3 may later add
fully decoded contract methods; the GUI must only expose those after that
backend returns a canonical reviewed representation. Unknown ABI/token labels
must never be treated as trusted display metadata.

### Bitcoin testnet

- testnet signing account tpub;
- every input outpoint, value and derivation information available to the
  backend;
- every output with **full** address, value and recipient/change role;
- detected change index;
- recipient amount;
- total inputs/outputs;
- fee.

BTC and EVM are two sibling choices on the first screen. Neither chain is a step
in the other chain's workflow.

## USB-B and QR

`load_review_file()` uses the bounded, no-symlink USB reader from #5.
`load_review_qr()` accepts text returned by a QR decoder. Both terminate in
the same `exchange.decode_envelope()` verifier and the same
`build_review_plan()` path.

The current #19 code intentionally does **not** add camera libraries to the
offline TCB. A QR reader callback is an adapter point for #18. When no QR adapter
is present, the UI clearly reports that QR is unavailable and keeps USB-B
available. Camera refusal/removal does not produce a review or signature.

## Offline runtime gate

Normal GUI startup requires the #1 boot-audit evidence and checks:

- the boot audit has PASS evidence for network isolation, no swap, RAM-backed
  root, COLD_VAULT and no unexpected writable persistent filesystem;
- no lockdown marker exists;
- `/proc/net` remains absent;
- no swap has become active.

There is one development bypass:

```bash
usb-cold-wallet-gui --public-test-vector-mode \
  --vault /path/to/public-test-only.vault \
  --transfer-dir /path/to/test-transfer
```

That mode only unlocks the repository's known-compromised public BIP39 test
wallet. It rejects any other wallet.

## Session and failure behavior

- default idle timeout: 120 seconds;
- rejecting a transaction locks and discards the current confirmation state;
- losing window focus clears the final typed signing challenge;
- UI callback failure locks wallet state and does not preserve unsigned signing
  confirmation;
- no request, mnemonic, private key or decrypted vault is intentionally written
  to logs or temporary files;
- signed output uses create-only mode and refuses silent overwrite;
- re-signing the same `ReviewSession` is rejected.

## Language and long values

The UI can switch between English and Traditional Chinese. Transaction values
are rendered in read-only wrapping text widgets rather than truncated labels,
so long addresses, tpubs, outpoints and digests remain fully selectable and
visible through the scrollable review surface. The window has a 640×480 minimum
and a resizable scrollable body.

## Verification status

Headless security logic is testable without Tk. Tests cover normal review,
USB/QR equivalence, cancellation, duplicate signing, digest changes, malicious
length/JSON, EVM policy failures, BTC input/output/change/fee display, wallet
switching, output no-overwrite and runtime-audit failure.

The current Devspace VM does not have the system Tkinter module, so actual
keyboard/mouse/rendering behavior has **not** been runtime-tested there. Before
Issue #19 is closed, the GUI still needs:

1. Tk-enabled offline image integration with #1;
2. full source-level integration against #2 and #3 heads;
3. #18 camera/animated-QR adapter integration;
4. physical offline display tests at multiple resolutions in English and
   Traditional Chinese;
5. UI crash / camera removal / power-loss exercises on the actual signer.
