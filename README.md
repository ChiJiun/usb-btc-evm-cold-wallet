# USB BTC + EVM 冷錢包

**繁體中文** | [English](README.en.md)

一支 USB，就能將日常交易操作與私鑰簽署分開：平常在 Windows 開啟隨身碟內的 **Online Companion**，查看資產、建立交易；需要轉出資產時，重新開機進入 USB 內的專用離線作業系統，確認交易並簽章，再返回 Windows 廣播。

這是一個開源的 **Bitcoin + EVM 自製冷錢包**專案，以一般 USB、最小化 Live OS 與離線簽章核心組成可攜式錢包。設計重點是：**不必在平常使用的電腦安裝錢包環境，私鑰只在離線簽章系統內使用，收款與轉帳流程保持直覺。**

> 以下介紹完整產品的目標使用方式；目前版本與開發進度見[專案進度](#專案進度)。

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

1. 將製作好的冷錢包 USB 插入電腦，透過 UEFI/開機選單從 USB 開機。
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

目前 `main` 為 **v0.1.0 研究原型**，已有 Bitcoin testnet PSBT v0 與 Ethereum Sepolia EIP-1559 原生轉帳的**離線 CLI 簽章核心**、加密 Vault、公開帳戶輸出及 CI 安全檢查。可開機 Live USB、Windows Portable Companion、交易 GUI、QR、MetaMask 整合及單 USB 跨開機流程，正在各功能分支整合與驗證；實體硬體 E2E 驗收尚未完成。

目前以 **Bitcoin testnet / Ethereum Sepolia** 進行開發驗證。主網及真實資產使用須待獨立安全審查與完整發行驗收。

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

[USB 製作與操作](docs/USB_SETUP.md) · [安全政策](SECURITY.md) · [威脅模型](docs/THREAT_MODEL.md) · [CI 與供應鏈](docs/CI_SECURITY.md) · [開源技術參考](docs/OPEN_SOURCE_REFERENCES.md)

## 授權

專案原創程式碼採 **MIT License**；所使用的第三方依賴與元件遵循各自授權。
