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

## CI execution

The active [`.github/workflows/metamask-snap.yml`](../.github/workflows/metamask-snap.yml)
runs on Snap-related PR changes using Node.js 24. It installs lockfile-pinned
dependencies with install scripts disabled, runs TypeScript typechecking and
adversarial keyring tests, checks Snap SES compatibility, builds the local
browser Companion, and rejects high/critical production dependency advisories.
The checked-in Snap manifest must match the built bundle: CI rejects builds
that silently change `snap.manifest.json`.

Run [GitHub Actions for this PR](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/workflows/metamask-snap.yml)
and verify `MetaMask Snap / Verify` succeeds on the latest commit. The
old [CI template](METAMASK_SNAP_CI_TEMPLATE.yml) is historical reference only;
do not install a second copy.

The pending QR request ID is derived from the MetaMask request ID **and a
persisted monotonically increasing sequence**. This ensures an old signed QR
response cannot be accepted if a request ID is reused after the bounded
closed-ID cache evicts old entries. Removing or resetting Snap state removes
this counter; the offline signer must still independently authorize each
transaction and should never accept an old response after account/state reset.

## Integration status

- **Implemented and automated-unit-tested:** keyless custom account,
  public-only state, MetaMask asynchronous Keyring API adapter, Sepolia
  type-2 fail-closed validation, v1 #18 QR envelope, signed raw transaction
  binding and recovery, replay/cancel/timeout guards, zh-TW Companion UI.
- **Snap and browser bundles build:** MetaMask Snaps CLI SES eval succeeds;
  20 automated adversarial/recovery tests and TypeScript typecheck pass locally; dedicated CI results must be checked on the latest commit. Production Companion Chromium tests are additionally required in Snap CI.
- **Not yet verified:** installation into a compatible real MetaMask client,
  full MetaMask native account selection and transaction/broadcast lifecycle,
  physical dual-machine camera/QR workflow, RPC failure/reorg handling at
  end-to-end level, successful transfer of real Sepolia test ETH.
- **Dependencies:** #17 Online Companion, #18 QR transport and #19 offline
  GUI core are merged into `main`. This optional Snap POC still lacks real
  MetaMask browser E2E and optical camera/presenter wiring; #21 policy and
  physical offline hardware remain separate acceptance gates.
- The generic #18 `ur:bytes` JSON transport is **not yet** ERC-4527
  `eth-sign-request` CBOR interoperability. Signed transactions should never
  be treated as an already-broadcast chain transaction.
- Supply chain: `npm audit --omit=dev --audit-level=high` reported **zero
  high or critical** findings at development time, but **moderate transitive
  advisories** remain in the pinned MetaMask toolchain and dependencies
  (in the upstream MetaMask toolchain). Pinned Vite is 7.3.8 and the
  transitive vulnerable uuid@9 is overridden to uuid@11.1.1, with typecheck,
  SES build, and tests required; do not waive remaining findings for release.

This POC deliberately does not claim that the Issue #22 acceptance criteria
have all been completed. Keep its PR in Draft pending an actual developer
MetaMask install and air-gapped integration test.


## 終止事件失敗恢復（Draft 修復，尚待真實 MetaMask 驗收）

本 Snap 在核准或拒絕交易時，會先把唯一的已驗證結果或拒絕狀態記錄到持久化 outbox，再嘗試向 MetaMask 發送終止事件。任何 `save` 失敗都不能直接變成已確認發送；`emit` 失敗後，重新啟動 Snap 仍會保留 **相同 request ID／狀態／v,r,s**，不得帶入新的簽章資料，也不接受新的交易請求覆蓋。

本機 Companion 的「失敗後的事件恢復」區提供：

1. **重送相同事件**：手動重新發送原本持久化的核准／拒絕事件，不重新簽章，也不重新解碼一個新的 QR 回覆。MetaMask 可能已收到前一次事件，因此重送可能是重複通知；不做背景自動重試。
2. **確認後清除**：只有在已確認 MetaMask 中該筆請求**完成或已取消**，才用此功能清除不確定的 outbox 狀態。保留 closed request ID 的重播保護，不會廣播或簽署交易。
3. 在 event 狀態未處理前，新交易繼續 fail closed；恢復完成後才可發起新 request。普通 `keyring_approveRequest` 與 `keyring_rejectRequest` 不得對已持久化的終止事件再次 emit；一律使用明確的恢復介面。MetaMask 事件 API 與 Snap 持久化之間無共同原子交易，因此**無法保證精確一次通知**。

已加入持久化失敗、事件傳送失敗、Snap 重啟後重送及「已送出但最終儲存失敗」情境的故障注入測試。建立／刪除帳戶也使用持久化通知 outbox：先儲存新的帳戶集合與固定的 AccountCreated/AccountDeleted 事件，再標記 attempted、發送通知並清除。save/emit/清理失敗可於 Snap 重啟後在 Companion「帳戶通知失敗恢復」頁面手動重送，或核對 MetaMask 帳戶集合後清除；不自動重試，仍無法保證 exactly-once。已加入故障注入與重啟測試。此工作仍是 **Draft POC**，實體 MetaMask 擴充功能完整 E2E 尚未驗收。
