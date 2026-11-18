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
          在實體離線端輸入 SIGN SEPOLIA
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
     --out /offline/sepolia-signed.json
   ```

   CLI 會要求人工輸入 `SIGN SEPOLIA`。不支援沒有本機確認
   的自動簽章、不支援 mainnet／EIP-712／ERC-20／盲簽。

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
- MetaMask 帳戶列舉會呈現更多公開衍生地址，**不代表它們目前
  能簽署**。只有 index 0 經過本版完整測試；其他地址切勿入金。
- 真正上線前仍需要實機 camera/browser、獨立離線 OS、供應鏈、
  CI 與 RPC 斷線/nonce stale/reorg 的測試。

## 開發驗證

```sh
cd qr-metamask
npm ci --ignore-scripts
npm test
npm run build
PYTHON_BIN=../.venv/bin/python npm run test:python  # Python 套件已裝在專案虛擬環境
npm audit --omit=dev --audit-level=high
```

JavaScript 相容性測試直接載入 `@metamask/eth-qr-keyring`，
不是自行模擬 MetaMask Keyring 的行為。Python 部分以
`tests/test_keystone_public.py` 檢查 BIP32 公開資料與 CLI 輸出。

**供應鏈稽核現況（2026-11-18）：** npm audit 生產相依套件為 0 high/critical、2 moderate、3 low；中風險涉及 Keystone Ethereum registry 及傳遞依賴 `uuid`。Browser bundle 能產生，但 Vite 尚有 `vm` Node 相容性提示，實際 MetaMask+鏡頭的瀏覽器運作尚未實測；不可把編譯成功等同真實瀏覽器驗證。

依賴的 #18 QR transport 仍使用通用 `ur:bytes`、#19 離線
GUI 尚未併入，此獨立整合是原生 MetaMask 協定 POC。未來可把
`eth-sign-request`／`eth-signature` 的瀏覽器掃描器整合進
#19 GUI，消除下載 JSON 與手動 CLI 的中間步驟，但不能移除
離線使用者的明確確認。
