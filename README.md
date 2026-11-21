# USB BTC + EVM 冷錢包

**繁體中文** | [English](README.en.md)

一支 USB，就能將日常交易操作與私鑰簽署分開：平常在 Windows 開啟隨身碟內的 **Online Companion**，查看資產、建立交易；需要轉出資產時，重新開機進入 USB 內的專用離線作業系統，確認交易並簽章，再返回 Windows 廣播。

這是一個以**實際可用的 Bitcoin + EVM 冷錢包產品**為目標的開源專案，以一般 USB、最小化 Live OS 與離線簽章核心組成可攜式錢包。設計重點是：**不必在日常電腦安裝錢包環境，私鑰只在離線簽章系統內使用，收款與轉帳流程保持直覺。**

**正式產品必要能力是 Bitcoin 與 Ethereum 主網收發。** Bitcoin testnet／Ethereum Sepolia 僅供開發及 Beta 驗收，主網須經實機、安全、供應鏈與獨立審查後才能開放。**目前不可用於真實資產。** 見 [#12](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/12)、[#48](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/48) 及 [#47](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/47)。

> 以下介紹完整產品的目標使用方式；目前版本與開發進度見[專案進度](#專案進度)。

## 最終產品目標與發行階段

| 階段 | 交付範圍 | 驗收 |
| --- | --- | --- |
| **Beta（測試網）** | 單 USB、Windows 免安裝自有 Companion、離線 GUI、初始化／紙本恢復、BTC testnet／Sepolia 完整跨開機交易 | 真實 USB／UEFI、故障與交易 E2E；[#37](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/37)、[#43](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/43)、[#24](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/24) |
| **v1.0 主網核心** | **Bitcoin mainnet BIP84／PSBT** 與 **Ethereum mainnet EIP-1559 ETH** 收發；嚴格的鏈別、帳戶、地址、交易政策隔離 | 獨立安全審查、實機最小金額主網 E2E 與可信發行；[#48](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/48)、[#47](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/47) |
| **ERC-20 與進階交易** | 經審查 Token 的 `transfer`（離線驗證合約、decimals、數量及 Gas），後續受限的 `approve`／revoke、EIP-712／Permit、合約互動 | ERC-20 是最終產品目標，是否包含在 v1.0 依驗收決定；未知方法與 blind signing 預設拒簽；[#3](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/3)、[#21](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/21) |
| **後續相容功能** | 自有 Companion 的 WalletConnect／dApp；選用 MetaMask 原生 QR，相較之下 Snap 僅為備選 | 獨立驗收，不阻擋核心冷錢包；[#23](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/23)、[#22](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/22) |

**產品主要入口是自有 Windows Companion 與 Offline GUI。** 單 USB 跨開機為主要 UX；雙機 QR 可作持續離線的其他模式。私鑰只能在離線端解鎖，所有交易都必須重新解析原始資料並逐筆人工確認。

## 從空白 USB 開始：首次製作與設定

準備 **一支可清空的 USB（建議 16 GB 以上）**、一台支援 **x86_64 UEFI USB 開機**的電腦，以及紙本助記詞備份。製作時可以在 Windows 連網下載映像與刷寫工具；建立或復原私鑰時則使用 USB 啟動的離線系統。

### A. 完整產品的製作流程（目標使用體驗）

1. **取得映像**：從本專案的 [GitHub Releases](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/releases) 下載適用的 USB 映像（格式為 `.img`）及發布的 SHA-256 驗證資料。正式完整映像尚未發布時，改用下方 **B. 開發版測試流程**。
2. **檢查下載檔案**：在 Windows PowerShell 計算映像雜湊，與專案正式發布的值比對：
   ~~~powershell
   Get-FileHash -Algorithm SHA256 .\usb-cold-wallet.img
   ~~~
3. **將空白 USB 製作成冷錢包**：使用 balenaEtcher、Raspberry Pi Imager 等圖形刷寫工具，選取 `usb-cold-wallet.img`、核對 USB 的容量及裝置名稱，再刷寫並完成驗證。**刷寫會清除選取裝置的全部資料；重新刷寫已有錢包的 USB 也可能刪除 Vault。**
4. **第一次從 USB 開機**：安全退出 USB，重新啟動電腦，從 UEFI 開機選單選擇這支 USB。進入 Offline Signer 後完成開機檢查；選擇「建立錢包」或「從助記詞復原」。
5. **設定錢包**：設定 Vault 密碼，離線抄寫並複核 24 個 BIP39 助記詞；將備份保存在 USB 之外。這支 USB 的加密儲存區保存錢包資料。
6. **啟用 Windows Companion**：匯出 BTC/EVM 公開帳戶資訊、關機回到 Windows，直接從 USB 的 Windows 可見分割區開啟 Portable Companion，匯入公開帳戶資料，即可查看餘額與建立交易。
7. **完成首次測試**：先以 Bitcoin testnet 或 Sepolia 進行一筆小額測試網交易，演練「建立請求 → USB 開機簽署 → 回 Windows 驗證並廣播」。

完成後，平常只需在 Windows 開啟 Companion；要轉帳時才重新啟動 USB 簽章系統。完整版本預計將 **Live OS、加密 Vault、交易交換區和 Windows Portable App** 封裝在同一支 USB 上，無須自行安裝 Python/Node。

### B. 現階段開發版：從原始碼建置並刷入空白 USB

目前 `main` 尚無完成整合與實機驗收的單 USB 發行映像。Buildroot 開機、安全稽核與映像建置仍在 [PR #7](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/7) 驗證，請參照其最新分支與 CI 文件，**不要把 PR #9 舊版建置指令或模擬器開機結果當成正式實體 USB 驗收**。目前開發映像採系統 USB＋獨立資料交換 USB；單 USB 交換區與 Windows 程式整合仍由 [#37](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/37) 追蹤。[PR #50](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/50) 的 Windows 免安裝 EXE 已通過 GitHub Windows runner 執行測試，但仍在 Review，尚未整合進單 USB 映像。

## 一支 USB 如何運作？

同一支 USB 提供兩個不同的使用環境：

| 使用環境 | 主要用途 | 何時使用 |
| --- | --- | --- |
| **Windows Portable Companion** | 查看公開帳戶與餘額、建立 Bitcoin PSBT / EVM 交易、驗證簽章、廣播與追蹤結果 | 日常收款、查看資產、準備轉帳 |
| **USB Offline Signer OS** | 從 USB 獨立開機、解鎖加密錢包、解析交易、顯示完整明細、經人工確認後簽章 | 只有需要轉出資產時 |

USB 內另外分出**加密錢包儲存區**及**交易交換區**，讓兩個環境交換待簽與已簽資料。Windows 端僅處理公開帳戶和交易資料；離線端負責私鑰與簽名。

離線系統採用自製的 **Buildroot Linux Live OS**，開機後進入專用簽章介面，預設停用網路與交換記憶體，不依賴日常 Windows 的軟體環境。

## 日常操作流程

### 1. 首次建立錢包

1. 先依[空白 USB 製作流程](#從空白-usb-開始首次製作與設定)完成刷寫，再透過 UEFI 開機選單從 USB 啟動離線系統。
2. 進入離線錢包介面，建立新錢包，或使用紙本 BIP39 助記詞復原。
3. 設定加密錢包密碼，離線抄寫並確認助記詞備份。
4. 將 Bitcoin、EVM 的**公開帳戶資料**提供給 Windows Companion，完成只讀帳戶設定。

日後查看資產和收款，不需要再次解鎖離線錢包。

### 2. 收款與查看資產

在 Windows 插入 USB，直接開啟 **Portable Companion**：

- 查看 BTC 與 EVM 帳戶、餘額、交易紀錄。
- 產生並複製收款地址，或顯示收款 QR Code。
- 管理公開地址、常用收款人與待處理交易。

**收款不需要啟動 Offline Signer。** 錢包的公開資訊足以查詢鏈上狀態與提供收款地址。

### 3. 轉出 BTC 或 EVM 資產

完整的單機、單 USB 操作路徑：

```text
Windows：開啟 USB 上的 Companion
    │
    ├─ 選擇 BTC / EVM、收款地址、金額
    ├─ 預覽網路費用並建立待簽交易
    └─ 將交易請求存入 USB 交換區
    │
    ▼
重新開機 → 從 USB 啟動 Offline Signer OS
    │
    ├─ 解鎖加密錢包
    ├─ 離線解析原始交易
    ├─ 核對完整地址、金額、找零／Gas 與費用
    └─ 使用者明確確認 → 簽署 → 存回 USB
    │
    ▼
重新開機 → 返回 Windows
    │
    ├─ Companion 匯入簽署結果
    ├─ 驗證帳戶、鏈別與交易內容是否符合原請求
    └─ 點選「廣播交易」→ 顯示 TxID / Tx Hash 與狀態
```

**Bitcoin** 使用 watch-only 帳戶建立 PSBT，離線端核對 UTXO、收款地址、找零與手續費後簽名；連網端完成交易並廣播。

**EVM** 在連網端建立交易，離線端核對 chainId、收款地址、金額、nonce、Gas 及支援的交易語意；連網端驗證已簽署交易後廣播。

正常操作不需要手動編輯 JSON、輸入 CLI 指令或複製 raw transaction。

## 也能使用雙電腦離線簽署

如果有一台專用離線電腦，冷錢包 USB 可以一直留在那台設備上，不必每筆交易都重新開機。

```text
連網電腦 / Online Companion                離線電腦 / USB Signer
建立 BTC / EVM 交易          ── QR ──►    掃描、解析、核對交易
驗證簽章並廣播交易           ◄─ QR ───    人工確認後簽章
```

支援方向包括：

- **動態 QR Code**：雙向傳遞待簽請求與簽章結果。
- **交易交換 USB**：沒有攝影機時的替代方式。
- **MetaMask 整合**：以公開帳戶搭配 QR 簽章橋接，在相容的交易流程中使用冷端簽名。

單 USB 跨開機模式著重設備最少、Windows 免安裝；雙機 QR 模式著重持續維持實體離線環境。兩種模式共用相同的交易解析、人工核對與簽章核心。

**WalletConnect／dApp 是自有 Companion 的長期重要能力；MetaMask 原生 QR 是選用相容功能，Snap 僅為備選方案。** 核心 BTC／ETH 收發不依賴它們，也不需 CLI／手動 JSON。

## 錢包功能與設計

- **Bitcoin + EVM**：以 Bitcoin PSBT、EVM 交易與公開帳戶管理為核心，逐步擴充支援的交易類型。
- **離線錢包保管**：BIP39/BIP32 金鑰、加密 Vault、紙本助記詞備份與復原演練。
- **獨立交易核對**：冷端直接解析待簽資料，完整顯示收款地址、數量、網路及相關費用；每筆都要人工確認。
- **交易政策**：地址簿、費用上限、額外確認、未知或未支援合約交易的拒簽規則。
- **簡潔操作介面**：Windows Portable Companion 與冷端專用 GUI，支援繁體中文。
- **可重現系統映像**：Buildroot Live USB、固定依賴版本、自動化建置與 QEMU/OVMF 開機檢查。

## 系統架構

```text
                     冷錢包 USB
          ┌──────────────────────────┐
          │ UEFI / Buildroot Live OS │ → 離線簽章介面
          │ 加密 Vault               │ → 助記詞、金鑰與設定
          │ 交易交換區               │ → 待簽請求、簽章結果
          │ Windows Portable App     │ → 連網端交易管理
          └──────────────────────────┘
```

私鑰簽章與交易廣播分處不同執行環境；普通 USB 的安全性仍依賴離線主機及開機映像的可信程度。設計與信任邊界詳見[威脅模型](docs/THREAT_MODEL.md)。

## 專案進度

本 README 描述**規劃完成後的產品流程**，並非宣稱所有功能已在目前版本交付。

目前 `main` 包含**測試網開發程式碼**，未完成正式產品或實體 USB 驗收：

| 模組 | 已合併功能 | 尚待整合／驗收 |
| --- | --- | --- |
| **簽章核心** | BTC testnet BIP84／PSBT v0、Sepolia EIP-1559、加密 Vault 與安全測試 | BTC／ETH 主網、ERC-20、進階合約仍未開放 |
| **Online Companion** | BTC／Sepolia watch-only、交易建立、簽章核對與人工廣播（[PR #26](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/26)） | Windows EXE [PR #50](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/50) 已合併並通過 CI；單 USB 跨開機實機整合尚未完成 |
| **Offline GUI／Policy／Session** | 已合併交易核對與簽章 GUI、政策及鎖定 Session 模組（[PR #40](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/40)、[PR #28](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/28)、[PR #29](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/29)） | 正式 USB 上開機、GUI 操作與故障實測 |
| **USB／QR** | 紙本復原、USB 交換、QR 與整合測試（[PR #11](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/11)、[PR #27](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/27)、[PR #42](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/42)、[PR #49](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/49)） | 單 USB 跨開機與雙機攝影機真實 E2E、標準 UR 互通 |
| **Live USB／MetaMask** | Buildroot 開發分支；MetaMask 原生 QR 程式 [PR #31](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/31) 已合併 | Live USB [PR #7](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/7) 與選用 Snap [PR #30](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/30) 尚未合併；實機驗收未完成 |

**通過 CI 不代表實體 USB 安全或主網交易可用。** Beta／RC／v1.0 依 [Release Roadmap #47](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/47) 和 [#24](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/24) 的證據與發行閘門驗收。

追蹤進度：[所有 Issues](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues) · [PRs](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pulls) · [完整產品體驗 #12](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/12) · [單 USB 跨開機 #37](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/37)

## 開發與文件

目前離線簽章核心的開發環境：Python 3.12+。

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
usb-cold-wallet --help
```

[USB 製作與操作](docs/USB_SETUP.md) · [Windows 免安裝 Companion](docs/WINDOWS_PORTABLE_COMPANION.md) · [紙本復原與 USB 交換安全](docs/RECOVERY_AND_USB_EXCHANGE.md) · [MetaMask 原生 QR 測試網 POC](docs/METAMASK_NATIVE_QR.md) · [MetaMask Snap POC](docs/METAMASK_SNAP_POC.md) · [安全政策](SECURITY.md) · [威脅模型](docs/THREAT_MODEL.md) · [CI 與供應鏈](docs/CI_SECURITY.md) · [開源技術參考](docs/OPEN_SOURCE_REFERENCES.md)

## 授權

專案原創程式碼採 **MIT License**；所使用的第三方依賴與元件遵循各自授權。
