# CI 與儲存庫安全控制

`.github/workflows/ci.yml` 是主要驗證流程。分流程式為
`scripts/ci_checks.py`，固定合併門檻為 `CI / Required`。

## 驗證範圍

| 變更或觸發條件 | 必要驗證 |
| --- | --- |
| 純文件（README.en、`SECURITY.md`、docs） | 變更分類、完整歷史 Secret scan、Required |
| README.md | 以上檢查，以及一次 wheel build 與 Python package metadata 驗證 |
| Python／其他程式碼、QR Transport JS／MetaMask QR JS | Python 3.12/3.13 pytest、可重現 wheel 雙次建置、QR Transport Node 24 單元測試／bundle build／Python↔QR 互通、選用 MetaMask QR Node 24／Keyring／Chromium CSP／Python 簽章互通、Required |
| 依賴 manifest、lockfile、任何 `.github/workflows/*.yml/.yaml` | 上述程式碼驗證，另執行 Python `pip-audit`；PR 必須通過實際 GitHub Dependency Review |
| npm manifest／lockfile 或 CI workflow 變更 | 額外執行全部 tracked npm 專案的 production `npm ci --ignore-scripts`、`npm audit --omit=dev --audit-level=high` |
| 每日 schedule（02:20 UTC） | Secret scan、Python `pip-audit`、所有 npm lockfile 的 production 及 dev/build dependency audit；QR 建置等其他昂貴檢查不執行 |
| workflow_dispatch | 完整驗證（包含 QR Transport、Python/Node 稽核） |

QR Transport 與選用 MetaMask Native QR 的功能驗證在程式碼變更時不能被跳過，且
`CI / Required` 必須確認兩個 QR job 都實際成功。純文件及每日依賴稽核時兩者可跳過，
但對 QR 修改、CI workflow 及依賴修改，缺少 lockfile、失敗或被取消均不得放行。
MetaMask Native QR 的 Chromium 測試包含正式 bundle、CSP、交易 JSON 下載、簽章回覆與頁面恢復失效；
實體 MetaMask Extension／雙機相機／Sepolia 廣播仍屬獨立產品驗收。
QR 的建置工作還額外
對 **dev/build dependencies** 執行 `npm audit --audit-level=high`；
Node 排程稽核則先分別檢查 production 相依，再針對**完整 lockfile（含 dev/build dependencies）** 執行 `npm audit --audit-level=high`，避免每日不跑 QR bundle 時遺漏建置工具的新增漏洞。完整 Node 稽核目前
使用 npm lockfile；雖然 pnpm/yarn 依賴檔會觸發檢查，尚未支援
pnpm/yarn 的獨立 audit，沒有可用 npm lockfile 時會拒絕通過。

## Dependency Review 的失敗政策

PR 變更依賴／workflow 時，`Dependency Review` 必須真正執行。
CI **直接呼叫** pinned `actions/dependency-review-action`，其使用
`GET /dependency-graph/compare/{basehead}` 比較依賴變更；
任務失敗、被跳過或取消都不能通過 `CI / Required`。
不再使用額外的 SBOM export API 作為前置檢查：GitHub 已在
2026-11-13 停用同步 `GET /dependency-graph/sbom`，而非同步
SBOM export 也不是 Dependency Review 使用的端點。
把 SBOM 匯出失敗當成 Dependency Review 失敗會造成錯誤阻擋。

若實際 Dependency Review 因 Graph／權限回傳 403／404，
需檢查儲存庫 Settings → Advanced Security / Code security →
Dependency Graph 及 GitHub Actions token 權限。不可用
`pip-audit` 或 `npm audit` 取代 workflow Actions／manifest
依賴變更的差異審查。

## Lockfile 與受保護分支

`requirements/ci.lock` 是 Python 的 hash-locked 依賴樹，依賴更新
須重新產生並審查雜湊差異。第三方 Actions 釘選完整 commit SHA，
checkout 不持續保存憑證。

保護 `main`：要求 PR、`CI / Required` 成功、先同步預設分支、
解決 Review 討論串，禁止 force push 與刪除主要分支。Gitleaks
獨立掃描完整歷史，另建議啟用 GitHub Secret scanning / Push
protection。

## 多 Agent 開發與 Branch Policy

### 目前查證狀態（2026-11-21）

以下「實際」指透過 GitHub Repository metadata 或版本庫原始碼確認；**無法從檔案內容推論 Branch Protection / Ruleset 已啟用**。

| 項目 | 目前實際狀態 | 目標政策 |
| --- | --- | --- |
| Default branch | `main` | 維持 `main` |
| Squash merge | 允許 | **唯一允許的 merge method** |
| Merge commit | 仍允許 | 關閉 |
| Rebase merge | 仍允許 | 關閉 |
| Auto merge | 關閉 | 先維持關閉；CI 和 Review 門檻驗證完成後再評估 |
| Branch Protection / Ruleset | 未取得可確認的完整管理設定 | 對 `main` 強制以下規則 |
| Required status check | Repository workflow 具備 `CI / Required`，是否列為 Branch required check 尚未確認 | 將 `CI / Required` 設為 required |
| Merge Queue | 目前 `ci.yml` 沒有 `merge_group` trigger | **暫不啟用**；必須先有合併佇列的 workflow/Required CI 驗證 |

### `main` 保護設定（需 Repository Admin 套用並驗證）

1. **Require a pull request before merging**：所有程式、安全、CI、依賴、文件變更預設都走 PR；禁止直接 push 到 `main`。先前經明確授權的 README 直接推送僅屬歷史例外，新政策啟用後不再保留此旁路。
2. **Require status checks to pass**：至少將固定的 `CI / Required` 列為 required；選擇執行中的最新 commit／合併結果，檢查內容由 `scripts/ci_checks.py` 依路徑 fail-closed 決定。不得拿較舊 SHA 的成功紀錄替代。對尚未接入 Required 的獨立工作流程，需另列 required check 或補入 aggregate gate 才可視為必測。
3. **Require conversation resolution**：所有阻擋性 review thread 必須解決；不能只回覆「會後續處理」就合併安全問題。若明確移至後續 Issue，必須說明非阻擋理由。
4. **Require linear history**，並且僅保留 **Allow squash merging**；關閉 **Allow merge commits** 及 **Allow rebase merging**。每個 PR 在 `main` 生成一筆有意義的 Squash Commit，標題包含功能及 Issue/PR 關聯。
5. **禁止 force push、刪除 `main` 與一般 bypass**；管理員是否也受限制須以實際 Ruleset/Protection 配置驗證。舊已合併 Commit 不重寫。
6. **Review approval**：工作流程要求與開發 Agent **不同的審查者**完成獨立 Review。若有可用的獨立 GitHub 審查帳號，再將至少 1 個 approval 設成強制條件；單人儲存庫不應設定成無人能批准、因此永遠無法合併的狀態。同一 GitHub 身分下多個 AI Agent 的留言，不能假裝已滿足 GitHub 的獨立 approval。
7. **Dismiss stale approvals / require latest push approval**：多 Agent 協作時建議啟用，但先確認是否會阻擋唯一的可用審查者。設定後，每次更新 Head 都要重新評估受影響區域。
8. **Automatically delete head branches**：合併後刪除專用 PR branch；在刪分支／worktree 前確認沒有其他 Agent 正在使用、沒有未提交修改或依賴該分支的其他 PR。

### 多 Agent 並行實作與合併流程

- **一個 Issue／可獨立驗收的變更範圍，對應一個 Agent 專屬 branch 和 PR**。命名例如 `feat/issue-48-mainnet`、`fix/issue-43-boot-origin`。不同 Agent 不應同時 push 同一個 feature branch；共用 worktree 會增加資料遺失及競態風險。
- 開發中可反覆 commit、修復 CI 與 Review；**完成後才 Squash Merge**，不需要為了讓 `main` 乾淨而改寫活躍／已被 Review 的 branch commit 歷史。
- PR 內容需有目的、依賴關係、實作範圍、風險、測試命令與結果、驗收缺口。Draft 及完整 E2E 未驗證的安全關鍵功能不可直接合併成「已完成產品」。
- 合併前以**最新 PR HEAD** 完成 Review、Required CI、討論串處理及與最新 `main` 的整合檢查。兩個 PR 若改到同一檔案或 API，先確認相容，再依序合併；不得把一個 PR 的綠燈視為另一個 PR 更新後仍然有效。
- 對 Live USB 這類耗時工作採分層驗證：快速檢查供修正迭代，完整映像／可重現性／QEMU／實體 USB gate 根據安全影響維持真正必要的驗收；**不得為加速而默默跳過 Release 安全條件**。
- 合併後核對 `main` 的 squash commit、PR 狀態、相關 Issue 是否真的達成驗收；自動清理分支不代表刪除後續實機測試或安全 Review Issue。

### Merge Queue 的啟用條件

多個 PR 經常同時準備合併、且 Required CI 因 `main` 快速前進而反覆重跑時，再評估 Merge Queue。正式啟用之前必須：

- 在主 CI 加入 `merge_group` 事件，讓佇列產生的合併候選 SHA 真正執行 `CI / Required`，且修正路徑選擇器對 merge-group SHA 的處理，不得誤判為文件修改而跳過測試。
- 以測試 PR 驗證合併佇列遇到測試失敗會拒絕合併、成功時才可進入 `main`；同時確認取消、競態與 Live USB 重跑成本。
- 確認 GitHub 方案、Ruleset/Branch Protection 支援與實際管理設定後才開啟。現階段**不宣稱 Merge Queue 已部署**。

**管理設定路徑**：GitHub 儲存庫 `Settings → General → Pull Requests` 設定 merge methods；`Settings → Rules → Rulesets`（或 `Branches → Branch protection rules`）建立 `main` 的保護規則；`Settings → General → Pull Requests` 可設定合併後自動刪分支。設定後使用非管理員身分的測試 PR 驗證：直接 push 被拒、缺 CI／未解決 Review 不可合併、Squash 為唯一可選合併方式。**文件政策不能替代 GitHub 伺服器端強制規則**。

`live-usb-pr-close.yml` 在 PR 關閉時取消可確認屬於該 PR 的過時 Live USB 自動建置。優先採用 GitHub run 上唯一的 `pull_requests` 關聯；若 PR 關閉後該關聯被 GitHub 清空，則再透過 GitHub REST Pulls API（涵蓋已關閉 PR）交叉驗證來源儲存庫、來源分支、完整 head SHA 和**唯一的 PR 號碼**，且只取消 head SHA 相符的自動 `pull_request` 工作；來源不唯一、查詢失敗或版本不符均跳過，絕不只憑分支名稱猜測。這項功能是安全優先的 best-effort 取消，不能保證所有過往 Commit 的 run 都能取消。

這項 workflow 與每日排程在合併至 `main` 後才會生效；真正的 PR close 與 schedule 事件仍需完成合併後驗收。
