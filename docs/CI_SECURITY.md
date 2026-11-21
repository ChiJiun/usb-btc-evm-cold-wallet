# CI 與儲存庫安全控制

`.github/workflows/ci.yml` 是主要驗證流程。分流程式為
`scripts/ci_checks.py`，固定合併門檻為 `CI / Required`。

## 驗證範圍

| 變更或觸發條件 | 必要驗證 |
| --- | --- |
| 純文件（README.en、`SECURITY.md`、docs） | 變更分類、完整歷史 Secret scan、Required |
| README.md | 以上檢查，以及一次 wheel build 與 Python package metadata 驗證 |
| Python／其他程式碼、QR Transport JS | Python 3.12/3.13 pytest、可重現 wheel 雙次建置、QR Transport Node 24 單元測試／bundle build／Python↔QR 互通測試、Required |
| 依賴 manifest、lockfile、任何 `.github/workflows/*.yml/.yaml` | 上述程式碼驗證，另執行 Python `pip-audit`；PR 必須通過實際 GitHub Dependency Review |
| npm manifest／lockfile 或 CI workflow 變更 | 額外執行全部 tracked npm 專案的 production `npm ci --ignore-scripts`、`npm audit --omit=dev --audit-level=high` |
| 每日 schedule（02:20 UTC） | Secret scan、Python `pip-audit`、所有 npm lockfile 的 production 及 dev/build dependency audit；QR 建置等其他昂貴檢查不執行 |
| workflow_dispatch | 完整驗證（包含 QR Transport、Python/Node 稽核） |

QR Transport 的功能驗證在程式碼變更時不能被跳過，且
`CI / Required` 必須確認 QR job 實際成功。QR 的建置工作還額外
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

`live-usb-pr-close.yml` 在 PR 關閉時取消可確認屬於該 PR 的過時 Live USB 自動建置。優先採用 GitHub run 上唯一的 `pull_requests` 關聯；若 PR 關閉後該關聯被 GitHub 清空，則再透過 GitHub REST Pulls API（涵蓋已關閉 PR）交叉驗證來源儲存庫、來源分支、完整 head SHA 和**唯一的 PR 號碼**，且只取消 head SHA 相符的自動 `pull_request` 工作；來源不唯一、查詢失敗或版本不符均跳過，絕不只憑分支名稱猜測。這項功能是安全優先的 best-effort 取消，不能保證所有過往 Commit 的 run 都能取消。

這項 workflow 與每日排程在合併至 `main` 後才會生效；真正的 PR close 與 schedule 事件仍需完成合併後驗收。
