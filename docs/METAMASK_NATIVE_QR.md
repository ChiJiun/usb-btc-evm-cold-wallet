# MetaMask 原生 QR 冷錢包整合（Keystone / BC-UR）

> **Sepolia 測試網專用、未經安全審計、不可存放真實資產。**
> 本整合使用 MetaMask **既有的 QR Hardware Wallet Keyring**，不需要
> 申請或發佈 Custom EVM Account Snap allowlist，也不需要將 USB 私鑰匯入 MetaMask。
>
> **已實測**：實際 npm 發布的 `@metamask/eth-qr-keyring@3.0.2`
> 透過 `crypto-hdkey` 配對，並用其 `signTransaction` 呼叫產生的
> `eth-sign-request` 與本專案產生的 `eth-signature` 完成無網路交易簽署往返。
> **尚未實測**：真實 MetaMask 擴充功能攝影機、兩台實體電腦及鏈上廣播。

## 為什麼不需要新的 Snap

MetaMask 原生的 **QR Hardware Wallet Device** 整合已認識以下
[Blockchain Commons UR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md)
型別。使用的是 Keystone 開源 registry 的 CBOR/UR 實作，不是自行定義的
`ur:bytes` 私有 JSON：

| 方向 | 標準 UR 類型 | 實作 |
| --- | --- | --- |
| 離線裝置 → MetaMask 公開帳戶配對 | `ur:crypto-hdkey` | `@keystonehq/bc-ur-registry` |
| MetaMask → 離線待簽交易 | `ur:eth-sign-request` | `@keystonehq/bc-ur-registry-eth` |
| 離線 → MetaMask 已簽結果 | `ur:eth-signature` | `@keystonehq/bc-ur-registry-eth` |
| QR 分幀、重組 | BC-UR v2 fountain | `@ngraveio/bc-ur` |
| 攝影機掃描、QR 渲染 | QR code | `@zxing/browser`, `qrcode` |
| 上游相容性測試 | MetaMask 本身的 QR Keyring | `@metamask/eth-qr-keyring`（測試相依） |

上游參考：

- MetaMask QR Keyring：<https://www.npmjs.com/package/@metamask/eth-qr-keyring>（ISC）
- Keystone UR Registry：<https://github.com/KeystoneHQ/ur-registry>（Apache-2.0 / ETH registry ISC）
- Ethereum QR 規格：<https://github.com/KeystoneHQ/Keystone-developer-hub/blob/main/integration/ethereum.md>
- `@ngraveio/bc-ur`（MIT）
- AirGap MetaMask pairing guide：<https://support.airgap.it/guides/metamask/>

套件透過鎖定版號的 npm dependencies 匯入，沒有直接複製未授權上游
原始碼。供應鏈仍需獨立安全審查與離線打包檢驗。

## 交易流程

```text
【可信、實體斷網的 USB 冷錢包主機】             【連網 MetaMask】
  解密 Vault / BIP32 衍生公開 xpub
    └─ export-keystone-public
             │
        開啟本地 QR 頁面
             │ ur:crypto-hdkey（只包含公開資料）
             └──────────────────────────────→ Connect Hardware Wallet → QR-based
                                              選 index 0 地址
                                              Send Sepolia 測試 ETH
        攝影機掃描 UR ←──────────────────────── ur:eth-sign-request
             │
       驗證 chainId=11155111、路徑、xfp、
       nonce、金額、gas=21000、收款地址及 data=0x
             │
       下載 unsigned.json（精確整數 Wei）
             │
       usb-cold-wallet sign-evm
          人工獨立核對收款地址 + Wei
          在實體離線端輸入包含收款地址尾碼及 Wei 的確認字串
             │
         signed.json
             │
       驗證簽章恢復地址、所有原始欄位及
       requestId 綁定，產生 eth-signature QR
             └──────────────────────────────→ Get Signature → MetaMask 驗簽／廣播
```

**永遠不要把 Vault、助記詞或 BIP39 Passphrase 傳入瀏覽器，** 包括離線
瀏覽器。只把 `public-evm.json`、`unsigned.json` 與 `signed.json`
提供給 QR 頁面。自製 USB 隨身碟沒有 Secure Element 或受信任硬體螢幕。

## 使用步驟

1. 在可信且物理斷網的 USB 冷錢包主機，從**已有的測試錢包**匯出純公開資料：

   ```sh
   usb-cold-wallet --vault /offline/wallet.vault \
     export-keystone-public --out /offline/public-evm.json
   ```

   此命令會要求在離線終端明確確認 `EXPORT PUBLIC EVM ACCOUNT`；
   輸出的擴充公鑰與 chain code 可推導同帳戶其他公開地址，
   應避免將檔案放上公開網站。

2. **在可信建置環境**準備靜態前端（建置機應沒有私鑰／Vault）：

   ```sh
   cd qr-metamask
   npm ci --ignore-scripts
   npm run check
   ```

   將完整且驗證過的 `dist/` 打包轉移到離線主機；避免在離線主機
   直接從不受信任的網路下載 npm 套件。離線主機只需可信的 Python
   靜態 HTTP server，不需要 Node.js：

   ```sh
   cd /trusted/qr-metamask-dist
   python3 -m http.server --bind 127.0.0.1 8011
   ```

3. 在離線主機開啟 `http://127.0.0.1:8011`，匯入
   `public-evm.json`，點選「產生 MetaMask 配對 QR」。
   MetaMask 擴充功能的 **Connect Hardware Wallet → QR-based** 掃描。
   MetaMask 的 QR Keyring 會列出多個從公開 xpub 衍生的地址；
   **本版只能簽 `m/44'/60'/0'/0/0`（第一個、index 0）地址，
   不能選其他地址接收資金或簽署。** 比對顯示的完整地址。

4. MetaMask 上切換 **Sepolia**，對 index 0 帳戶進行原生測試 ETH
   轉帳。MetaMask 顯示待簽 QR 時，在離線頁面開啟攝影機掃描
   `ur:eth-sign-request`，按「下載 unsigned.json」。

5. 在同一台物理離線主機，用從可信獨立管道確認的收款地址與
   **完整十進位 Wei** 執行：

   ```sh
   usb-cold-wallet --vault /offline/wallet.vault sign-evm \
     --tx /offline/sepolia-unsigned-REQUEST_ID.json \
     --to 0xINDEPENDENTLY_VERIFIED_RECIPIENT \
     --wei INTEGER_WEI \
     --expected-policy-sha256 INDEPENDENT_64_HEX_SHA256 \
     --out /offline/sepolia-signed.json
   ```

   簽名前須依 [離線政策設定](OFFLINE_POLICY.md) 建立 `<vault>.policy`，
   並從獨立紙本或可信離線紀錄提供目前政策的完整 SHA-256。
   缺少政策或驗證值會拒簽。CLI 會顯示 Sepolia、完整收款地址、完整 Wei 與費用，並要求人工輸入
   `SEPOLIA <收款地址後 8 碼> <完整十進位 Wei>`（以 CLI 實際顯示為準）。
   不支援沒有本機確認的自動簽章、不支援 mainnet／EIP-712／ERC-20／盲簽。

6. 將 `sepolia-signed.json` 匯入離線 QR 頁面，按「檢查後產生
   eth-signature QR」。當所有交易欄位及簽章恢復地址都符合本次
   `eth-sign-request`，頁面顯示標準 `ur:eth-signature`。
   回到 MetaMask「Get Signature」掃描，確認交易廣播及
   Sepolia 鏈上的 transaction hash。

## 強制安全限制

- **只支援 Sepolia、EIP-1559 type 2、原生 ETH 轉帳**，gas 恰為
  21,000、沒有 calldata/accessList、費用上限 1000 Gwei；
  不接受任意其他 chain ID、路徑、root fingerprint 或簽章類型。
- 只接受請求的 UUID requestId 與對應的簽章。未簽交易的原始
  byte serialization、收款地址、Nonce、Wei、gas、fee caps 均
  必須與已簽交易相符；不採用只看「QR checksum」的做法。
- 顯示器／鏡頭／作業系統仍可能遭到供應鏈與惡意 QR 攻擊；QR
  本身不驗證請求來源，人工離線核對是不可移除的安全邊界。
- 鏡頭僅掃描登入本機的 `localhost` QR 頁面，不使用雲端網站，
  也不透過此處呼叫任何 RPC。線上 MetaMask 處理費用估計、交易
  廣播和狀態；其鏈上資料可受到惡意 RPC 影響。
- 攝影機啟動需等權限回應；按停止／取消後若先前的啟動請求才完成，
  會立即關閉遲到的攝影機控制物件，過期掃描回呼不能接受交易。
- QR 動畫採序列化渲染與 session generation；取消或新交易會使尚未完成的 QR 編碼失效，舊簽章 QR 不會重新顯示。
- MetaMask 帳戶列舉會呈現更多公開衍生地址，**不代表它們目前
  能簽署**。只有 index 0 經過本版完整測試；其他地址切勿入金。
- 目前一般 CI 已要求跑 Node 24 MetaMask QR Keyring／Python 跨語言簽署測試、
  Vite build 和 production dependency audit；實機 camera/browser、
  獨立離線 OS、RPC 斷線/nonce stale/reorg 仍須另外驗收。

## 開發驗證

```sh
cd qr-metamask
npm ci --ignore-scripts
npm test
npm run build
npx playwright install --with-deps --only-shell chromium  # CI 或專用測試機
npm run test:browser  # 以 Chromium 載入實際 dist/ 並檢查 CSP/QR/簽章操作
PYTHON_BIN=../.venv/bin/python npm run test:python  # Python 套件已裝在專案虛擬環境
npm audit --omit=dev --audit-level=high
```

JavaScript 相容性測試直接載入 `@metamask/eth-qr-keyring`，
不是自行模擬 MetaMask Keyring 的行為。Python 部分以
`tests/test_keystone_public.py` 檢查 BIP32 公開資料與 CLI 輸出。
`tests/python-integration.mjs` 會以已公開且不安全的測試助記詞，
讓 Python `eth-account` 實際簽署 18 位以上 Wei 的 Sepolia
EIP-1559 交易，再經 Keystone UR 返回上游 MetaMask
`QrKeyring.signTransaction()`，驗證完整 signed raw bytes
一致。Python signed JSON 的大整數在 JS 會失精度，因此這個
測試使用簽章原始 RLP 解碼的 BigInt 建立核對交易，不以
`JSON.parse` 數字欄位作為轉帳金額。

**供應鏈稽核現況（2026-11-21）：** npm audit 生產相依套件為 0 high/critical、2 moderate、3 low；中風險涉及 Keystone Ethereum registry 及傳遞依賴 `uuid`。需留意上游 `elliptic` 安全公告；不得使用可能造成相容性破壞的 `npm audit fix --force` 自動升級。
`.github/workflows/ci.yml` 已將 Node 24 的 native-QR 測試、
實際 Python 跨語言測試、Vite build、Playwright Chromium 瀏覽器 smoke
與 npm audit 納入 `CI / Required` 必要條件；缺少 `qr-metamask/`
的舊分支安全略過該部分。Chromium smoke 以實際 `dist/` 和 CSP
驗證公開帳戶匯入、配對 QR、交易解析、簽章 QR 及取消。
**實體 MetaMask 擴充功能、相機權限與雙機離線操作尚未驗收**；
上游 `vm` polyfill 警告仍存在，瀏覽器 smoke 只證明受測路徑可執行。

依賴的 #18 QR transport 仍使用通用 `ur:bytes`、#19 離線
GUI 尚未併入，此獨立整合是原生 MetaMask 協定 POC。未來可把
`eth-sign-request`／`eth-signature` 的瀏覽器掃描器整合進
#19 GUI，消除下載 JSON 與手動 CLI 的中間步驟，但不能移除
離線使用者的明確確認。
