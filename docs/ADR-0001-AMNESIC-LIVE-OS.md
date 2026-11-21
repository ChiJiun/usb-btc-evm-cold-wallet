# ADR-0001：最小化無痕離線系統與 Vault 持久化邊界（#34）

- 狀態：**Accepted for the testnet architecture; runtime/hardware validation pending**
- 日期：2026-11-21
- 範圍：自製 Buildroot Live USB、離線簽署器、持久化 Vault；不宣稱已完成映像或實體硬體驗收。

## 決策

1. 保留 **Buildroot 最小化 Linux 冷端**，不直接採用 Tails 映像、Tor、Browser 或網路功能。只借鑑無痕、明確持久化及 fail-closed 原則。**未複製 Tails 原始碼**。
2. 開機的 root filesystem 與短期工作檔案以 RAM 為目標；允許持久化的機密僅有離線簽署器控制的**加密 Vault 與加密政策檔**（`policy.py`），不得在磁碟保存明文助記詞、BIP39 passphrase、私鑰或解密後的 Vault。交換媒體中的交易請求與簽章回覆視為不可信輸入；其地址、金額、交易細節與已簽交易雖不含助記詞，**仍會留下隱私與交易歷史**，不能宣稱所有 USB 分割區都無痕。
3. **現階段沿用應用層 scrypt + AES-256-GCM Vault**（`src/usb_cold_wallet/vault.py`）。是否加上 LUKS2 作為分割區級加密，暫列待決：必須先量測開機／解鎖時間、確認復原與 Windows 可見分割區設計，再決定；不得把 app-level Vault 誤稱為 LUKS、全磁碟加密或抗回滾儲存。
4. 一般 USB 的 boot image 與 Windows 可見資料區**可被惡意主機改寫**。目前不具備硬體可信開機根、Secure Element 或 firmware 防竄改能力。映像雜湊只能在獨立可信來源核對時提供完整性佐證，不能阻止惡意 Windows 以替換映像偷取下次解鎖的秘密。
5. 程式與映像驗收分離：Python 單元測試及 QEMU 開機不構成真實 USB 安全保證；實機斷電、拔除、重啟、持久化殘留、裝置冒名測試由 #43 / #24 追蹤，發行 gate 為 #47。

## 威脅與安全控制對照

| 風險或設計點 | 本專案目前有的證據 | 必須於 #1/#7 映像整合驗證 | 不提供的保證 |
| --- | --- | --- | --- |
| 網路外洩 | 現有離線 Python 核心不需 RPC；主線尚未交付經驗收的 Live USB | 核對 **最終** kernel `CONFIG_NET=n`、可載入模組與啟動環境；拒絕網路介面 | 抵禦惡意韌體與外接硬體 |
| 明文殘留 | Vault 與 policy 均有 app-level AES-GCM 加密；#49 已加入 Vault create-only、stage + fsync + no-replace publish。VFAT 沒有原生 UNIX 權限，`0600` 依 mount 的 `fmask`/`dmask` 顯示 | root/tmp/run/var 與交換資料區的 mount/mode、swap/hibernate/kdump、重啟殘留檢查；政策檔更新的同步／回復路徑另行評估 | Python 記憶體完全 zeroization、交換分割區隱藏交易 metadata |
| Vault 裝置來源 | 原始 Vault 加密格式存在 | 按實體 USB 裝置身分驗證 boot + vault 來源；禁止 fallback 到明文或內建磁碟 | 主機韌體提供可信裝置身分 |
| USB 交易輸入 | 有嚴格 envelope 與 BTC/EVM 原始交易解析；#49 已以 Linux loop 掛載的真實 FAT32 驅動驗證 stage + `renameat2(RENAME_NOREPLACE)`、卸載重掛與故障注入 | Buildroot 實際 `ctypes`/glibc、物理 USB 控制器、拒絕 symlink/traversal、斷電與拔除測試仍需 #43 | SHA-256 對來源身分的認證、硬體掉電後永不遺失資料 |
| 供應鏈／更新 | 有依賴鎖定、CI 與可重現建置工作 | 最終 image 的 hash、來源、依賴版本、可重建證據與發行簽署策略 | 對被入侵的建置者或主機自動免疫 |
| 可信開機 | 尚無硬體信任根驗證 | 記錄 Secure Boot 狀態與 image 驗證程序；發行版不得誤稱不可竄改 | 被惡意 Windows 重寫的普通 USB 仍可信 |

## 與現行實作的對照及尚存風險

| 現行程式／來源 | 已存在的設計控制 | 尚未形成的證據或待修復項目 |
| --- | --- | --- |
| PR #7 `buildroot-external/configs/usb_wallet_x86_64_defconfig`、`linux.config` | initramfs 及 `CONFIG_NET=n` 的冷端配置；不捆綁 Tails/Tor/Browser | 需在**最終編譯出的** kernel config、initramfs、可載入 modules 及 QEMU/OVMF 中驗證；在 #7 合併前不能當主線正式能力 |
| PR #7 `S01airgap`、`identify_media.py`、`gui.runtime_audit` | boot/vault GPT 與分割區來源一致性、固定 mount flags、fail-closed lockdown 的設計 | 需要檢查開機時序、交換媒體異常與 runtime mount recheck，重複來源、拔除、隨時換媒體的實體測試屬 #43 |
| `src/usb_cold_wallet/vault.py`（#49） | scrypt/AES-GCM 的加密助記詞容器；新建檔採臨時檔、`fsync`、atomic no-replace，保留已存在檔案 | 沒有 Vault rollback/replay 抵抗；GitHub FAT32 loop filesystem 驗證不等於實體 USB 掉電耐受 |
| `src/usb_cold_wallet/policy.py` | 政策以加密 ciphertext 保存，簽署前須驗證獨立 SHA-256 anchor | `save_profile` 使用 `os.replace`，沒有和 #49 同等的 parent-dir `fsync`／完整掉電恢復驗收；更新後的最新版本與 anchor 需靠可信外部記錄。此項不得稱為已驗收的可靠持久化 |
| `TX_TRANSFER`（單 USB 或獨立交換媒體） | JSON 輸入與已簽回覆受格式／路徑核對；#49 已完成 FAT32 loop-backed 的檔案系統驗證 | 地址、金額、已簽交易等**非助記詞但具隱私敏感性**的資料可持久留存；不保證 secure deletion、實體控制器 flush 或 boot image 完整性 |

**界線**：#49 專屬 VFAT CI 已實際掛載 Linux FAT32 image 並重新掛載驗證，仍沒有在 PR #7 的 Buildroot Python runtime 或真實 USB／物理斷電上執行。上述「已存在」指的是原始碼或 CI 的設計／測試證據，不能替代 #43 的實體驗收。

## 為何暫不強制 LUKS2

應用層加密已保護 Vault 內容的靜態機密性，但檔名、大小、存取時間及其他持久化資料不因此加密。LUKS2 可以提供分割區級保護，卻增加解鎖流程、維護/備份、header 毀損與故障恢復的責任，也不解決 boot image 被篡改的問題。選擇前須有以下可追溯證據：

- 與 app-level Vault 單獨使用比較的威脅模型、解鎖 UX 與耗時；
- 冷端所需 cryptsetup/LUKS2 依賴、容量與可重現映像結果；
- LUKS header 受損、USB 掉電、忘記 passphrase 與紙本 mnemonic 復原行為；
- 單 USB #37 的 Windows 可見交換區與私密資料分割區隔離方案；
- LUKS2 與應用層 Vault 是否雙重加密、備份策略及使用者誤操作風險。

**決策門檻**：上述項目完成並經 Review 才改變持久化格式；當前 PR 不修改加密參數、格式、分割區或開機程式。

## 上游來源與授權界線

| 來源 | 本案用途 | 是否移植程式碼 |
| --- | --- | --- |
| [Tails](https://tails.net/) | 無痕 Live OS 與明確持久化的架構參考 | **否** |
| [Buildroot](https://buildroot.org/) | 自製最小 Linux 映像建置工具 | 經發行版來源與其個別授權安裝，尚須 release SBOM/NOTICE |
| [Linux kernel](https://kernel.org/) / [BusyBox](https://busybox.net/) | 冷端 runtime 與隔離控制 | 依個別上游授權散布，不能視為專案 MIT 原始碼 |
| [cryptsetup](https://gitlab.com/cryptsetup/cryptsetup) | **候選** LUKS2 實作 | 尚未採用或複製 |
| [cryptography](https://github.com/pyca/cryptography) | 現有 scrypt/AES-GCM Python 依賴 | 使用相依套件，非複製上游原始碼 |

正式發行時建立實際使用的 upstream tag/commit、license/SPDX、copyright/NOTICE 與變更清單；此表是規劃，不可當作已完成逐檔授權稽核。

## 下一步與追蹤

- **#1 / PR #7**：將選定映像、掛載/隔離及 QEMU fail-closed 證據對齊本 ADR。#7 正在驗證時不修改該分支。
- **#37 / PR #49（已合併）**：已驗證 Linux FAT32 loop-backed 檔案系統的 atomic no-replace 與卸載／重新掛載；Windows 掛載、實體 USB 寫入／拔除及掉電行為仍由 #43 驗收。
- **#43 / #24**：在實體設備完成網路、swap、持久化、裝置冒名、斷電與復原驗收。
- **#47**：發行版本註明普通 USB／共用 Windows 主機的殘留風險與不受保護的開機完整性。
- **#34 結案**：ADR/來源清單完成後仍需冷端映像實際對照與 runtime regression；剩餘硬體證據可明確移交 #43/#24，不重複強制每個功能 Issue 自行做實機 E2E。
