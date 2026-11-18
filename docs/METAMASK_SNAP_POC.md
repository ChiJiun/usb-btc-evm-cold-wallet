# MetaMask USB Cold Signer Snap — Issue #22, Sepolia POC

> **Experimental integration only. DO NOT use mainnet or real funds.** This is
> an Account Management Snap / Keyring API **proof of concept**, not an audited
> wallet, a published/approved Snap, or an end-to-end-verified hardware workflow.

## Scope and architectural boundary

- This Snap **does not accept or derive seeds, mnemonic words, BIP39
  passphrases, private keys, or wallet vaults**. It imports **only a Sepolia
  public address** as an independently registered custom account.
- It never modifies, migrates or re-labels an existing MetaMask hot account.
  Do not create a duplicate cold account using the address of your current
  hot account; instead, derive the address from your dedicated offline wallet
  and independently compare the full address on both machines.
- `src/keyring.ts` implements MetaMask's keyring API with
  `eth_signTransaction` only. No `eth_sign`, `personal_sign`,
  `eth_signTypedData*`, ERC-20, contracts, arbitrary calldata, L1/mainnet,
  access lists, hardware-wallet compatibility spoofing, or private-key export.
- Unsigned Sepolia native EIP-1559 transaction must be explicit and canonical:
  chain 11155111, type 2, exact from/to, value > 0, gas exactly 21000, empty
  calldata/access list, bounded max fee/priority fee and numeric nonce.
- For MetaMask's asynchronous signing flow, `submitRequest` saves one
  in-flight request with an immutable canonical #18 QR v1 envelope, then returns
  `{pending:true, redirect}`. The companion dapp displays this request.
- The completely **offline** USB signer parses the unsigned QR, separately
  verifies the recipient/amount/fee on its trusted display, then signs.
  The response includes an actual raw signed type-2 transaction.
- **Before invoking `keyring_approveRequest`**, the Snap verifies:
  request ID, request digest, account, network, QR data digest, expiration,
  and the *actual signed raw transaction* recovered sender, chain, nonce,
  destination, value, gas, fee caps, calldata and access list. All must match
  the pending request exactly. It returns only the type-2 signature's `v,r,s`
  fields to MetaMask for normal transaction processing/broadcast.
- Cancellation/rejection, wrong account/chain, corrupt QR input, stale nonce,
  mismatch, and expiry are fail-closed; never auto-sign, auto-retry, fee-bump
  or broadcast from the Snap. Pending data is **public, not confidential**.
  A locally stored request ID/digest does **not authenticate** a compromised
  online machine: offline human review remains mandatory.

## Installation / local development

Requires Node.js 20+ and a development build/environment of MetaMask that
supports Account Management Snaps. A normal production MetaMask install or
hardware-wallet connect option **is not guaranteed** to accept this Snap.

The MetaMask docs currently say **new Custom EVM Account Snap allowlisting is
not being accepted**, so do not claim this prototype is officially approved
or publishable without further permission/review. See:
- <https://docs.metamask.io/snaps/reference/entry-points/>
- <https://metamask.github.io/keyring-api/latest/>
- <https://support.metamask.io/configure/snaps/account-management-faq/>
- <https://docs.metamask.io/snaps/features/custom-evm-accounts/>

Build and test:

```sh
cd metamask-snap
npm ci --ignore-scripts
npm run check
npm run build
npm run build:companion
npm audit --omit=dev --audit-level=high
```

The Snap developer server uses `http://localhost:8082` as its local Snap
origin (configured in `snap.config.ts`). In a **separate** terminal run:

```sh
cd metamask-snap
npx mm-snap serve
```

Then on the **same trusted local online desktop**:

```sh
cd metamask-snap/dist-companion
python3 -m http.server --bind 127.0.0.1 8000
```

Open <http://localhost:8000>. The companion permits only local origins
`localhost:8000` or `127.0.0.1:8000`, which are configured in the Snap's
keyring allowed origins. Do not host the page on a remote VM, public domain
or an untrusted/shared computer; do not expose Snap developer endpoints.

**Test flow** (not yet verified in an actual MetaMask browser session):

1. Connect the local Snap from Companion with `wallet_requestSnaps`.
2. Import a **public** Sepolia address exported by the offline wallet.
3. Select/authorize that independent custom account in a compatible MetaMask
   developer build; send a *test-only* native Sepolia ETH transfer. MetaMask
   passes `eth_signTransaction` to the keyring Snap.
4. On Companion, click **讀取待簽交易**, review displayed public fields,
   and download its **#18 QR v1 JSON** using `wallet_invokeSnap`.
5. Feed this JSON to the #18 QR-transport page as a `ur:bytes` object.
   On a **separately isolated offline PC**, the #18 signer must review and
   sign via the offline wallet. The #18 browser QR transport is **not**
   itself a signer. Compare the full recipient/amount/fee using an independent
   source; do not just trust the online QR.
6. Return #18 signed JSON via the QR transport and load it using the
   Companion file input (max 150KB). The companion checks current
   `eth_chainId`, authorized public account, and pending RPC nonce.
   The Snap itself independently verifies signed raw transaction fields.
7. Only after successful verification the Snap notifies MetaMask with the
   requested `v,r,s` components. Check network, transaction hash and
   broadcast/receipt status through MetaMask or independent testnet explorer.

## CI workflow activation

The dedicated Node/Snap workflow template is committed as
[`docs/METAMASK_SNAP_CI_TEMPLATE.yml`](METAMASK_SNAP_CI_TEMPLATE.yml).
The current VM GitHub OAuth credentials do **not** have the `workflow` scope,
so GitHub rejected a push that created `.github/workflows/metamask-snap.yml`.
The template was therefore kept under `docs/` instead of bypassing the
repository's authorization. A repository administrator with the appropriate
workflow permission must review and install the template as
`.github/workflows/metamask-snap.yml`. Until that happens, **GitHub CI does not
run the Node Snap checks** (the existing Python CI is separate). Run the local
`npm` checks above for each change and do not claim CI passed without a run.

## Integration status

- **Implemented and automated-unit-tested:** keyless custom account,
  public-only state, MetaMask asynchronous Keyring API adapter, Sepolia
  type-2 fail-closed validation, v1 #18 QR envelope, signed raw transaction
  binding and recovery, replay/cancel/timeout guards, zh-TW Companion UI.
- **Snap and browser bundles build:** MetaMask Snaps CLI SES eval succeeds,
  TypeScript typecheck and unit tests pass.
- **Not yet verified:** installation into a compatible real MetaMask client,
  full MetaMask native account selection and transaction/broadcast lifecycle,
  physical dual-machine camera/QR workflow, RPC failure/reorg handling at
  end-to-end level, successful transfer of real Sepolia test ETH.
- **Dependencies:** #17 Online Companion and #18 QR transport currently live
  on separate unmerged branches. They are **not** silently copied into this
  PR. The Snap emits the #18 protocol directly, but the physical offline
  signer/GUI (#19) and policy (#21) are external acceptance gates.
- The generic #18 `ur:bytes` JSON transport is **not yet** ERC-4527
  `eth-sign-request` CBOR interoperability. Signed transactions should never
  be treated as an already-broadcast chain transaction.
- Supply chain: `npm audit --omit=dev --audit-level=high` reported **zero
  high or critical** findings at development time, but **moderate transitive
  advisories** remain in the pinned MetaMask toolchain and dependencies
  (including `uuid`). Do not waive this risk for production release.

This POC deliberately does not claim that the Issue #22 acceptance criteria
have all been completed. Keep its PR in Draft pending an actual developer
MetaMask install and air-gapped integration test.
