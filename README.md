# USB BTC + EVM 冷錢包（研究原型）

**繁體中文（預設）** | [English](README.en.md)

> [!WARNING]
> **實驗性專案 · 僅限測試網 · 未經獨立安全審計 · 請勿存放真實資產。**
>
> **本專案目前不是可直接燒錄開機的 USB 映像檔。** 現階段提供的是預計在**可信任、實體斷網的 Linux Live 環境**中執行的離線簽章核心與命令列工具（CLI）。一般 USB 隨身碟不是 Ledger、Trezor、YubiKey，也不具備 Secure Element（安全元件）或獨立的硬體金鑰保護能力。

## 專案簡介

這是一個開源的 **Bitcoin 測試網 + Ethereum Sepolia 離線冷錢包**研究原型，目標是利用一般 USB 隨身碟與獨立的離線電腦，完成交易檢查及私鑰簽署。

此設計的安全核心不是 USB 本身，而是**連網端與簽章端之間的實體隔離（Air Gap）**：

- **離線電腦：** 產生或解密 BIP39 錢包、獨立核對交易資訊、經使用者確認後簽名。處理私鑰期間不得連網。
- **連網電腦：** 僅保留公開的 watch-only 錢包資訊，建立未簽章交易，再透過錢包或節點廣播已簽署交易。
- **資料交換 USB（USB-B）：** 僅傳輸公開資料、未簽署交易及簽章結果，**不能存放助記詞、私鑰、密碼、passphrase 或加密 vault**。

```text
連網電腦（沒有私鑰）                    實體離線電腦／Linux Live USB
┌──────────────────────────────┐        ┌──────────────────────────────┐
│ Watch-only 錢包／區塊鏈節點   │        │ 加密 Vault／BIP39 助記詞    │
│ 建立 BTC PSBT／EVM 交易       │ ─────► │ 獨立解析、核對交易資訊       │
│                              │ USB-B  │ 使用者逐筆人工確認           │
│ 核對簽章結果並廣播交易        │ ◄───── │ 不連網，使用私鑰簽署交易     │
└──────────────────────────────┘        └──────────────────────────────┘
```

**收款**只需要公開收款地址，平常不必啟動冷錢包；**轉出資產**才需要將交易送到離線端，進行獨立核對與簽章。

## 目前支援的功能（測試網研究原型）

| 項目 | 已實作範圍 |
| --- | --- |
| 錢包產生與派生 | 在離線端建立一組 24 字 BIP39 助記詞；支援選用的 BIP39 passphrase 與 BIP32 派生 |
| 加密錢包檔案 | Scrypt + AES-256-GCM；檔案權限 `0600`；拒絕覆寫既有 vault |
| Bitcoin | **僅測試網**；BIP84 原生 SegWit P2WPKH、保守的 PSBT v0／SIGHASH_ALL 驗證、明確核對收款人／金額／找零／手續費；不支援 RBF／Locktime 語意 |
| EVM | **僅 Sepolia 測試網**；EIP-1559 Type 2 **原生 ETH 轉帳**、chainId／收款地址／金額／Gas 檢查、已簽署原始交易重新解碼與發送者地址還原 |
| 公開帳戶資訊 | Bitcoin 測試網收款地址與帳戶 `tpub`；Sepolia EVM 地址；嚴格格式的 watch-only 公開匯出 |
| 紙本復原 | 離線輸入 BIP39 助記詞及選用 passphrase，雙鏈地址比對後建立新 vault；公開測試向量的可拋棄式復原演練 |
| USB 資料交換 | 嚴格 schema、大小限制、重複 JSON 欄位拒絕、SHA-256 完整性校驗；**不能驗證來源身分** |
| 安全限制 | 離線簽章程式**沒有 RPC 或廣播功能**；禁止主網簽章、任意合約呼叫、盲簽及私鑰匯出 |
| 自動化檢查 | GitHub Actions：Python 3.12／3.13 測試、雜湊鎖定相依套件、pip-audit、Gitleaks、dependency review 檢查及可重現 wheel 建置 |

**目前 `main` 尚未支援：** 主網、ERC-20、EIP-712、WalletConnect、Taproot、多簽、PSBT v2、QR 傳輸、可信任的硬體螢幕／按鍵、可直接燒錄的開機 ISO、完整 Bitcoin 地址探索，以及獨立安全審計。

> [!NOTE]
> 部分新功能正在獨立 Pull Request 開發。例如 [PR #26 的 Online Companion](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/26) 在尚未合併前，**不屬於目前 `main` 已提供的功能**。本 README 以 `main` 為準，不將開發中功能當作正式支援。

## 開發環境與自動化測試

**連網電腦或 VM 只適合用來執行公開且已知外洩的測試向量。** 不得在 Devspace、GitHub Actions、WSL、雲端 VM 或任何連網環境建立或匯入真正打算持有資產的助記詞。

環境需求：Python 3.12 或更新版本。

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"

pytest
usb-cold-wallet --help
```

自動化測試通過**不代表**離線硬體、USB 開機環境或實際資產的安全性已經通過驗證。

## 離線環境安裝與準備

開始前請先閱讀 [USB 製作與使用指南](docs/USB_SETUP.md)。以下是**手動研究／測試流程**，不是一鍵安裝程式，更不是安全開機的保證。

1. 驗證官方 Linux Live ISO 的來源及校驗資訊，將其製作成系統 USB（**USB-A**）。燒錄通常會清除 USB-A 原有資料。
2. 在實體斷網前，預先準備經過驗證、版本正確且相容離線主機架構的 Python 套件與原始碼。
3. 完全關機後斷開 Ethernet、Wi-Fi、Bluetooth 與其他網路路徑，再啟動 Linux Live 環境；不要任意掛載不可信儲存裝置。
4. 將加密 vault 放在**離線專用的獨立儲存媒體**，USB-B 只負責資料交換，避免兩者混用。
5. **只在實體離線電腦建立錢包**，並將助記詞及選用的 BIP39 passphrase 另外備份與核對。

示範指令（必須自行確保離線主機已完成實體隔離；指令不會自動建立隔離環境）：

```bash
# 在連網開發電腦預先準備依賴套件
python -m pip download -d wheelhouse -e ".[dev]"

# 在離線 Linux 上使用已驗證的 wheelhouse 安裝
python -m pip install --no-index --find-links wheelhouse -e ".[dev]"

# 僅能在離線主機建立加密 vault；不可在連網電腦執行
usb-cold-wallet --vault /offline/wallet.vault init \
  --offline-ack --i-have-paper-backup

# 輸出可以交給連網端的公開 watch-only 資訊
usb-cold-wallet --vault /offline/wallet.vault addresses --count 3
```

`--offline-ack` 僅是使用者確認旗標，**不代表程式能驗證電腦真的已經斷網**。作業系統與硬體仍需獨立檢查。

## 如何簽署並轉出交易？

連網端負責建立未簽署交易；**離線端必須使用可信任且獨立的資訊來源，核對實際收款地址、金額及費用**，不可只相信連網電腦顯示的交易摘要。

### EVM：Sepolia 原生 ETH 轉帳

先在連網電腦準備 EIP-1559 Type 2 未簽章交易 JSON，建議先封裝成有固定格式的 USB 交換檔。以下 `--tx` 是仍支援的舊格式，會進行大小、JSON 重複欄位與交易內容檢查，但新流程建議使用 `--request`。

```bash
# 連網端：將未簽署 JSON 封裝成交換檔
usb-cold-wallet pack-request --kind evm-request --input unsigned.json --out evm-request.json
# 離線端：將原指令的 --tx 改成 --request（signed.json 會是帶校驗的封套）
usb-cold-wallet --vault /offline/wallet.vault sign-evm \
  --request /transport/evm-request.json \
  --to 0x000000000000000000000000000000000000dEaD \
  --wei 1000000000000 \
  --out /transport/signed.json
```

相容既有純 JSON 輸入的方式：

```bash
usb-cold-wallet --vault /offline/wallet.vault sign-evm \
  --tx /transport/sepolia-unsigned.json \
  --to 0x000000000000000000000000000000000000dEaD \
  --wei 1000000000000 \
  --out /transport/sepolia-signed.json
```

其中 `--to` 與 `--wei` 是**獨立核對的預期收款人與金額**。離線程式會檢查原始交易並要求人工確認。簽署完成後，再將結果透過 USB-B 帶回連網電腦，由外部錢包或 RPC 工具廣播。

### Bitcoin：測試網 BTC 轉帳

連網端先建立含正確 BIP32 派生來源與 UTXO 資訊的未簽署 PSBT。若有找零，必須獨立核對 BIP84 內部找零地址的索引。

```bash
usb-cold-wallet --vault /offline/wallet.vault sign-btc \
  --psbt /transport/unsigned.psbt \
  --to tb1qREPLACE_WITH_INDEPENDENTLY_VERIFIED_ADDRESS \
  --sats 50000 --max-fee-sats 2000 --change-index 0 \
  --out /transport/signed.json
```

若沒有找零輸出，請省略 `--change-index`。上方 `--psbt` 屬相容舊格式；新流程可使用 `pack-request --kind btc-request --input unsigned.psbt --out btc-request.json` 在連網端封裝，離線端改用 `sign-btc --request /transport/btc-request.json`（其餘確認參數不變）。簽好的資料傳回連網環境，再由相容的錢包或節點完成交易及廣播。**離線 CLI 刻意不具備廣播功能。**

## 安全設計與已知限制

- **普通 USB 是儲存媒體，不是硬體安全模組。** 沒有 Secure Element、獨立的可信任確認螢幕，也無法自行強制保證私鑰不可匯出。
- 解密 vault 時，Seed 與派生私鑰會進入**離線電腦的記憶體**；惡意韌體、作業系統、周邊裝置、swap、crash dump 與實體記憶體攻擊仍可能洩漏機密。
- 加密 vault 的密碼**不能取代**經過驗證、保存在裝置之外的 BIP39 助記詞與選用 passphrase 備份。
- 若連網電腦或 USB-B 遭到入侵，交易內容可能被替換。檔案雜湊／Checksum **不等於來源身分認證，更不等於使用者授權簽章**。
- 一般 Linux Live 系統若未額外稽核，可能把機密寫入 swap、日誌、休眠檔或持久化磁碟。
- 原始碼、相依套件、封裝、威脅模型及實體設備運作**尚未接受獨立完整安全審計**；測試網能使用不代表主網可以安全使用。
- 紙本復原功能及公開測試向量演練僅通過程式測試，尚未完成離線硬體及惡意 USB 的實測；請閱讀[復原與 USB 交換指南](docs/RECOVERY_AND_USB_EXCHANGE.md)。

**絕對不要**將助記詞、BIP39 passphrase、私鑰、解密後資料或加密 vault 放上會與連網電腦交換的 USB，也不要上傳到公開 Issue、PR 或日誌。

詳細規範請參閱 [安全政策](SECURITY.md) 與 [威脅模型](docs/THREAT_MODEL.md)。

## 專案結構

| 檔案 | 用途 |
| --- | --- |
| `src/usb_cold_wallet/vault.py` | BIP39 錢包 vault 加解密 |
| `src/usb_cold_wallet/keys.py` | 使用 `embit` 進行 BIP32 金鑰派生 |
| `src/usb_cold_wallet/btc.py` | Bitcoin 測試網 PSBT 檢查與簽署 |
| `src/usb_cold_wallet/evm.py` | 使用 `eth-account` 檢查／簽署 Sepolia 原生 ETH 轉帳 |
| `src/usb_cold_wallet/cli.py` | 離線命令列、人工確認及檔案交換 |
| `src/usb_cold_wallet/exchange.py` | 嚴格大小與 schema 的 USB 交換封套 |
| `src/usb_cold_wallet/recovery.py` | 離線紙本復原與公開測試向量演練 |
| `tests/` | 公開測試向量、確定性測試與拒絕情境測試 |
| `docs/` | USB 指南、威脅模型、測試向量與供應鏈安全文件 |

專案**不自行實作**橢圓曲線密碼學、Keccak、PSBT 序列化或 AES 演算法；相關依賴與設計參考列於 [開源專案參考](docs/OPEN_SOURCE_REFERENCES.md)。

## 開發路線圖

1. 可重現的離線相依套件建置流程，以及經驗證、真正隔離網路的啟動環境。
2. Bitcoin Core／Sparrow 與 EVM 的獨立測試向量、惡意輸入／Fuzz 測試、外部安全審查。
3. 可重現的唯讀 Linux Live USB 映像，以及安全的 USB 檔案／QR 交易傳輸。
4. 更方便的離線交易審查 UI、助記詞復原演練與主網上線前的完整安全驗收。
5. 未來可選擇發展具備獨立可信任螢幕、按鍵及安全開機的專用硬體版本。

簽章流程、操作便利性與熱錢包整合的後續規劃，請參閱 [Issue #12](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/12)。

## 相關文件

[USB 製作指南](docs/USB_SETUP.md) · [紙本復原與 USB 交換指南](docs/RECOVERY_AND_USB_EXCHANGE.md) · [安全政策](SECURITY.md) · [威脅模型](docs/THREAT_MODEL.md) · [EVM 測試向量](docs/EVM_TEST_VECTORS.md) · [CI／供應鏈安全](docs/CI_SECURITY.md) · [開源專案參考](docs/OPEN_SOURCE_REFERENCES.md)

## 授權

採用 **MIT License**。程式碼為本專案自行開發的研究原型；其他開源專案主要作為架構與實作參考，未直接複製封閉原始碼或廠商韌體。
