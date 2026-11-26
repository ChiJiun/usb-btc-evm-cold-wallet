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
| CI／GitHub Actions | YAML 表達式、`needs`、skipped 被當 PASS、依 Draft 狀態分流、concurrency 誤取消 main、舊 SHA、重複 Workflow、未鎖 Action SHA、Cache 污染；先跑 `python -m pytest -q tests/test_ci_checks.py`，整批修改一次 Push（逐檔 Push 會讓每次 Run 被取消） |
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

## 隱含狀態機與形式化驗證（TLA+）

本節是新增的開發與安全審查方法；目前不代表已建立模型、執行 TLC 或新增 Required CI。既有安全、測試網、QEMU、實體 USB 與 Release Gate 全部保留。

### 依變更風險選擇驗證

- 文件、純外觀等不改變安全行為的變更：既有最小預檢即可；不強制 TLA+。
- 一般功能：依影響面執行單元、整合、負向與 property-based/stateful tests。
- 涉及簽署授權、跨開機、持久化、並行、媒體信任、復原、發布授權的變更：優先盤點狀態機、定義安全不變量，對適合的狀態機建立或更新 TLA+ 模型並執行 TLC；無模型或工具時明列缺口，不宣稱形式化驗證通過。不得因此跳過既有必要 Gate。

### 狀態機盤點與建模優先順序

以下是待核對實際 source 的候選範圍與目標性質，不是已驗證的實作行為。

| 優先 | 範圍 | 候選安全不變量 |
| --- | --- | --- |
| P0 | Signer / Review / Policy | 簽署必須綁定同一份已人工確認的交易 digest、chain、account 與有效 session；取消、鎖定、替換交易後舊授權失效 |
| P0 | Replay Ledger / 跨開機交易 / Vault | 已消耗授權不可因重啟或可回滾媒體恢復；缺可信獨立 anchor 時 fail closed；中斷不得產生未授權的可用簽署結果 |
| P0 | USB discovery / mount / runtime | 未確認媒體身分及 parent/partition 綁定不得使用；拔除、替換、重複識別、初始化逾時須安全處理；LOCKDOWN 不允許敏感操作 |
| P1 | Windows companion / FAT32 exchange | Request/response 與 wallet、network、digest 綁定；重試、截斷、斷電、舊檔回滾不得繞過驗證；未驗證回應不得廣播 |
| P1 | GUI / session lifecycle | 畫面與簽署資料一致；輸入事件、取消、auto-lock、重入、裝置拔插不得沿用舊確認 |
| P1 | Release / CI | 驗證證據與 exact source、artifact bytes、tag、run 綁定；舊證據、失敗或跳過的必要檢查不得授權發布 |

相關規格先讀 [THREAT_MODEL.md](THREAT_MODEL.md)、[OFFLINE_POLICY.md](OFFLINE_POLICY.md)、[FAST_SIGNER_SESSION.md](FAST_SIGNER_SESSION.md)、[RECOVERY_AND_USB_EXCHANGE.md](RECOVERY_AND_USB_EXCHANGE.md)、[WINDOWS_PORTABLE_COMPANION.md](WINDOWS_PORTABLE_COMPANION.md)、[OFFLINE_REVIEW_GUI.md](OFFLINE_REVIEW_GUI.md)、[CI_SECURITY.md](CI_SECURITY.md)、[RELEASE_VERIFICATION.md](RELEASE_VERIFICATION.md)。

### Agent 執行流程

1. 以 exact source SHA 盤點所有候選隱含狀態機：enum、flags、guards、例外、事件、檔案/DB 狀態、跨程序與跨開機副作用。記錄已掃描範圍、未分析路徑、狀態、轉換、信任邊界及 source path/symbol；不得宣稱自動掃描保證完整。
2. 對照需求與 threat model 定義 safety invariants、liveness properties、fairness 及環境假設。分別建模現有行為與預期規格，避免直接把待驗證的安全性寫成假設。
3. 建立 TLA+ Init/Next 與有限 TLC configuration；將 volatile/durable state 分離，允許 adversarial event ordering、crash/restart、retry、取消、媒體替換、舊資料回滾及適用的並行交錯。不得假設 FAT32 rename/flush 具有未實測的斷電持久性。
4. 在開發主機或隔離 CI 執行 pinned TLC，限制 CPU/RAM/時間與模型範圍；不在離線 signer image 安裝 Java/TLC，不使用真實私鑰、助記詞或主網資產。先小模型，再擴大交易數、事件與交互依賴；檢查非空洞性及合理的正常完成路徑。
5. 保存 counterexample trace，逐步對應實際 source，區分模型錯誤、抽象假陽性、實作缺陷及未能重現的問題。對確認的 bug 建立 regression test，修正前重現失敗、修正後通過，再重跑模型與相關實作測試。
6. 模型、configuration、invariants、source mapping 與假設納入版本控制（建議未來使用 `formal/`）；相關程式碼、依賴、規格或工具版本變更須重新評估證據。不得為了通過 TLC 擅自放寬 invariant 或移除 adversarial transition。

### 證據與限制

PR 記錄 source SHA、模型/config digest、工具版本、執行命令、有限範圍、狀態數、耗時、結果、反例與 regression test、剩餘缺口。結果區分 PASS / FAIL / INCONCLUSIVE / NOT_REQUIRED；逾時、缺工具、資源不足或未執行不能算 PASS。NOT_REQUIRED 須有影響面理由。已知且可重現的安全缺陷未修正前不得宣稱安全驗收完成。

TLC 通過只表示指定有限模型及假設下未發現所檢查性質的反例；不證明 Python/Node/Shell 實作、密碼學、UEFI/USB 硬體、實際 FAT32 持久化或 airgap 正確。仍須獨立 oracle、負向測試、QEMU/OVMF、雙 clean build 與實體驗收。初期優先做 P0 小型 POC，確認反例可映射至實作後，再另開 PR 導入自動化 gate；本文件不修改 CI 或發布條件。

參考：[TLA+ tools](https://lamport.org/tla/tools.html)；跨專案策略見 [AgentDock #70](https://github.com/ChiJiun/agentdock/issues/70)。
