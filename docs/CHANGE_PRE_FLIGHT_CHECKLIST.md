# 所有程式碼變更的防呆與驗證清單

適用於所有 Agent、所有程式碼、測試、設定、CI、文件修改。目標是在 Push 前以低成本發現常見錯誤；不得取代安全 Review、CI、QEMU 或實體 USB 驗收。

## 每次變更必做

1. **同步與確認範圍**：讀最新 main、自己的 Branch HEAD、相關 Issue、PR、Review Threads、既有 API 與測試。不得改其他 Agent Branch；不得沿用舊 SHA 的 PASS。
2. **檢查影響面**：找定義、呼叫端、序列化格式、Runtime imports、安裝清單、設定與測試。優先沿用現有核心，避免平行實作。
3. **先驗證失敗案例**：正常流程、邊界值、錯誤輸入、缺檔、例外、權限、取消、重試；安全敏感功能加測 Replay、錯鏈／帳戶、回滾、斷電。
4. **先做便宜檢查**：Python `python -m compileall -q src scripts tests`；Shell `sh -n`／`bash -n`（依 shebang）；Node `node --check` 與專案既有 Type Check／Lint；YAML 檢查縮排、表達式、事件、`needs`。
5. **改測試就先跑該測試**：執行改動模組對應的最小 pytest／Node Test，再擴大範圍。未執行或失敗就記錄 NOT VERIFIED，不能宣稱 PASS。
6. **檢查提交內容**：`git diff --check`、`git diff`、`git status`；排除機密、暫存檔、非預期格式化、無關 Refactor 與依賴漂移。
7. **一次提交同根因修正**：程式、測試、文件與設定一起處理，避免逐行 Push 重跑昂貴 Actions。CI 失敗先取**最新 HEAD** 的失敗 Job Logs，定位根因後再修。
8. **驗收**：最新 HEAD 的必要 CI、Required Gate、Review 與安全驗收證據完整；QEMU 與實體 USB 分開標示。沒有證據不標 PASS。

## 按變更類型追加檢查

| 類型 | 常見失誤與預防 |
| --- | --- |
| Python／Backend | Import 循環、漏裝依賴、Python 3.12／3.13 差異、公開 API 改名、錯誤被吞、序列化變更；執行相關 pytest |
| 測試 | 斷言依賴 YAML 註解／空白／順序、Fixture 污染、Mock 掩蓋真實路徑、只修測試不修產品；測正反案例 |
| CLI／Shell／Build | Shebang、未引用路徑、Exit Code、pipefail、工作目錄、缺少系統工具；語法檢查與失敗注入 |
| CI／GitHub Actions | YAML 表達式、`needs`、skipped 被當 PASS、Draft→Ready、舊 SHA、重複 Workflow、未鎖 Action SHA、Cache 污染；先跑 `python -m pytest -q tests/test_ci_checks.py` |
| Buildroot／Live USB | `CONFIG_NET=n`、離線模組 Allowlist、Runtime imports、Framebuffer／Input、GPT Read-only Bit、Mount Policy；核對 raw image、QEMU/OVMF，GUI 要實際畫面證據 |
| Vault／Signer／Policy | 私鑰或敏感 Log、簽章與畫面不一致、錯鏈／帳戶／digest、Replay Ledger 回滾、普通 USB 假冒可信 Anchor；缺 Anchor 時 fail closed |
| BTC／EVM／跨開機 | PSBT、整數精度、Fee／Nonce／Chain ID、Request／Response 綁定、USB 拔除／替換、RPC 故障；公開向量、獨立 Oracle、負向測試 |
| Windows／Node／瀏覽器 | Lockfile、`npm ci`、Bundle、CSP、BigInt、Windows 路徑；既有 Test、Build、瀏覽器 E2E |
| FAT32／檔案系統 | 非原子寫入、Rename、同步落盤、截斷、有效舊檔回滾、掛載與權限；真實 VFAT 與故障注入 |
| 依賴／供應鏈 | 版本／Hash／簽章未鎖、License、來源 Provenance、快取重用舊編譯產物、Secret；Lockfile、Audit、掃描 |
| 文件／設定 | 指令不存在、連結錯、設定與實作不符、驗收狀態過時；核對檔案與指令，避免不必要完整 Buildroot |

## 重複故障記錄格式

記錄：症狀、Run URL、HEAD SHA、根因、修正 Commit、最小重現命令、回歸測試、最新驗證結果、可防止再次發生的自動檢查。未實際驗證不得標 PASS。

CI 專屬案例見 [CI_PERFORMANCE_AUDIT.md](CI_PERFORMANCE_AUDIT.md)，安全門檻見 [CI_SECURITY.md](CI_SECURITY.md)。
