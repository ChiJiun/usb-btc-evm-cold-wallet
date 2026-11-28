# CI 效能稽核與最終架構（2026-11-22，Issue #87／PR #88）

## 量測資料與限制

以 `gh api repos/{owner}/{repo}/actions/runs`（分頁列舉 1,440 次 Run）與各 Run 的 Jobs／Steps API 取得資料：

- 最近 45 次已完成（success/failure）的 `CI` Run 的全部 Job 排隊與執行時間；
- 20 次成功的舊獨立 `Live USB image verification` Run；
- 最近 300 次 `CI` Run 的結論分佈。

Runner 分鐘數以「每個 Job 無條件進位到分鐘」估算（公開 repo 標準 Runner 不計費，此數字代表佔用量）。p90 只對樣本數足夠的項目提供。

## 量測結果（變更前，main = `fa66ecf`）

| 項目 | 實測 |
| --- | --- |
| 含 Live USB 的 CI wall-clock | 69.0–74.7 分鐘（n=8）；`build-and-reproduce` 中位數 72.4 分鐘 |
| 其中「兩次 Clean Build」單一 Step | 70.6 分鐘（例：[#44993550698](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44993550698)）；來源下載 1.5 分鐘、apt 0.4 分鐘、QEMU 0.1 分鐘、封裝（xz -9e）0.3 分鐘 |
| 舊獨立 Live USB Workflow | 中位數 72.7、p90 115.7 分鐘（n=20） |
| 其他所有 Job | 每個 ≤ 1.8 分鐘；不含 Live USB 的 CI wall-clock 1.5–2.5 分鐘 |
| 排隊時間 | 所有 Job 中位數 0.0–0.1、最大 0.1 分鐘（不是瓶頸） |
| Runner 分鐘 | 含 Live USB 94–97；不含 16–25 |
| 首次建置失敗回饋 | 第一次 Clean Build 失敗約 35–37 分鐘（[#44997387192](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44997387192)） |
| 取消比例 | 最近 300 次 CI：250 取消、33 成功、15 失敗 |

**Critical Path**：`changes`（0.1）→ `live_usb`（72）→ `required`（0.1）。其他 Job 全部與 `live_usb` 平行且遠短於它，因此 Merge 時間只由 Live USB 與「重跑次數」決定。Lead Time 的第二大來源是逐檔 Push 造成的取消與重跑（83% 的 Run 被取消）。

## 量測結果（變更後，PR #88 HEAD `749db83`，n=1）

來源：[#45005164267](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/45005164267)。只有一筆樣本，且兩個建置都未命中來源快取（第一次執行），不足以計算 p50／p90。

| 項目 | 實測 |
| --- | --- |
| 含 Live USB 的 CI wall-clock | 53.6 分鐘（變更前 69.0–74.7） |
| `clean-builds (1)`／`(2)` Job | 50.7／38.5 分鐘（建置 Step 47.6／35.4）；兩台 Runner 映像版本不同，相差約 12 分鐘 |
| `verify-and-publish` Job | 1.3 分鐘（SHA 比對、位元組核對、QEMU、封裝） |
| Runner 分鐘 | 約 111（變更前 94–97）；兩台 Runner 各自重做 apt 與來源準備，另加驗證 Job |

平行後的 wall-clock 由較慢的那台 Runner 決定，所以實際縮短幅度（約 20 分鐘）小於下方方案比較的估算（以單次建置約 36 分鐘推算）。

## 方案比較（推論：以上述實測 Step 時間推算，未實測者標示估算）

| 方案 | 首次失敗回饋 | Draft 單次（含映像變更） | 最終驗收 | 轉 Ready 額外等待 | Runner 分鐘／映像 Push | 安全性 |
| --- | --- | --- | --- | --- | --- | --- |
| A. 變更前（同 Job 依序兩次建置） | Python 1.5；映像 ~36；可重現性 ~73 | ~73 | ~73 | 0 | ~95 | 基準 |
| B. PR #88 先前版本（Draft 不建映像、Ready 才雙建置、`ready_for_review` 重跑） | Python 1.5；映像錯誤延到 Ready 才發現 | ~2（無映像驗證） | ~42（估算） | ~42（同 SHA 重跑） | Draft 0；Ready ~95 | Draft 的 Required 成功不代表映像已驗證；轉 Ready 到新 Run 建立前有競態窗口 |
| C. Draft 單建置、Ready 雙建置 | 同 D | ~40（與雙建置相同，平行） | ~42 | ~42 | Draft ~55；Ready ~95 | 同 B 的語意問題 |
| **D. 最終採用：所有 PR／main 同一 Gate，平行雙建置，不因 Ready 重跑** | Python 1.5；映像 ~36（估算，實際取決於失敗那台 Runner）；可重現性實測 53.6 | 實測 53.6（n=1；估算原為 ~42） | 實測 53.6（n=1） | **0** | 實測約 111（估算原為 ~95） | Required 成功 = 該 SHA 完整驗證；無競態 |

B、C 欄位的 ~40／~42 是以單次建置約 36 分鐘推算；實測單次建置 Job 為 38.5–50.7 分鐘，實際值應會更高。

Lead Time（推論，含映像變更、Review 與 CI 平行、2 次 Push）：A ≈ 2×73 = 146 分鐘；B ≈ 2×2 + 42 + 42 = 88 分鐘（估算，偏樂觀），但若映像在 Ready 才失敗，每輪再加一次雙建置；D 以實測單筆推算 ≈ 2×54 = 108 分鐘，且映像錯誤在第一次 Push 就回報。非映像變更所有方案都約 2 分鐘。

## 最終架構

1. **分層依「變更範圍」而非 Draft 狀態**：`scripts/ci_checks.py`／`ci_workloads.py` 決定 workload；未知檔案、workflow 修改、比較失敗、手動或未知事件一律選完整驗證（fail closed）。
2. **Fail-fast**：`live_usb` 需 Python 3.12／3.13 成功才啟動；被跳過時 `CI / Required` 仍失敗。
3. **平行雙 Clean Build**：兩個獨立 Runner 各自完整建置與靜態稽核；`fail-fast: true` 讓一邊失敗即取消另一邊。第三個 Job 比對兩份 SHA-256、核對實際下載的映像與 kernel 位元組、QEMU/OVMF 開機與稽核標記，最後封裝 testnet-only Artifact。
4. **觸發**：`pull_request` 只用 `opened`／`synchronize`／`reopened`；轉 Ready 不重跑。
5. **Concurrency**：只取消同一 PR 的舊 Run；main／手動以 `run_id` 分組。
6. **快取**：只快取來源下載（不可信輸入，每次驗證雜湊與簽章）；實測只省約 1.5 分鐘，不是主要收益。
7. **Timeout**：建置 120 分鐘（實測 Job 38.5–50.7 分鐘，n=1 次 Run）、驗證 30 分鐘，卡住時更早失敗。
8. **Merge**：Ruleset 只要求 `CI / Required`、`strict=false`（不要求 PR 與 main 同步，避免無謂重跑；合併後 main Push 會再跑完整 CI）。個人帳號 repo 不支援 Merge Queue；repo 已關閉 Auto-merge。

### 驗證矩陣

| 事件 | Scope 分類 | Python 等快速測試 | Live USB 雙建置＋SHA＋QEMU | Required |
| --- | --- | --- | --- | --- |
| Draft PR（opened/synchronize/reopened） | 依變更 | 依變更 | 選中即執行 | 必須全部符合 |
| 轉 Ready | 不觸發（沿用同 SHA 的完整結果） | — | — | 同上一筆 |
| Ready PR 新 Push | 依變更 | 依變更 | 選中即執行 | 必須全部符合 |
| main Push | 依 `before` 比較 | 依變更 | 選中即執行，不被後續合併取消 | 必須全部符合 |
| workflow_dispatch／未知事件 | 完整 | 全部 | 執行 | 必須全部符合 |
| schedule | 依賴稽核 | 依賴／Node 稽核 | 不執行 | 必須全部符合 |
| Release | main 目前沒有 Release Workflow（見 #57）；本 PR 不放寬任何 Release 門檻 | | | |

## 未做的方案與原因

- **Draft 跳過映像**：見方案 B；映像錯誤延後發現，且轉 Ready 需重跑。
- **快取 build/output 或 ccache**：違反獨立 Clean Build。
- **xz `-9e` 改 `-6`**：實測整個封裝步驟 0.3 分鐘，沒有可量測效益，維持原參數。
- **QEMU 提前到建置 Job**：QEMU 只要 0.1 分鐘，且必須在兩份 SHA 比對成功後才執行，提前沒有收益。
- **Debounce（延遲啟動以吸收連續 Push）**：每次 Push 固定多等，公開 repo 不計分鐘費；以「批次 Push」流程解決。

## 常見失敗與防止重複浪費 CI 時間（#87）

每次修改 CI、Buildroot 或其測試前，先讀本節與 `docs/CI_SECURITY.md`；新發現的重複性故障須記錄**實際 run、根因、預防測試與驗證結果**，不能只記錄症狀。

| 已發生的問題／證據 | 根因與避免方式 | 最小驗證 |
| --- | --- | --- |
| [CI #45002446458](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/45002446458)：Python 3.12／3.13 同時失敗，819 passed、1 failed、3 skipped | Step 層級斷言以 `lstrip().startswith('if: ...')` 比對 YAML，新增註解後誤判。新測試改用 `yaml.safe_load` 結構化檢查 Step 的 `if`，不依賴註解或文字位置 | 先執行 `python -m pytest -q tests/test_ci_checks.py`，再推送；兩個 Python Matrix 均須成功 |
| [CI #45004649586](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/45004649586)：2 failed、826 passed，`ModuleNotFoundError: No module named 'yaml'` | 新測試使用 PyYAML，但它不在 `requirements/ci.lock`；本機剛好有安裝所以沒發現。改為只用標準函式庫的 job／step 範圍解析，不為測試新增依賴 | 本地以 `PYTHONPATH` 指向會拋出 ImportError 的假 `yaml` 模組再跑 `tests/test_ci_checks.py`，模擬 CI 環境 |
| [CI #44997976256](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44997976256)：Python Matrix 已失敗，Live USB 仍耗時建置 | 缺少快速測試前置依賴。完整 Live USB 需等待 Python Matrix 成功；選中 Live USB 卻因失敗而跳過時，`CI / Required` 必須失敗，不能把 skipped 當 PASS | `test_live_usb_heavy_build_requires_successful_python_matrix` 與 Required Gate 負向測試 |
| [CI #44979598989](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44979598989)、[#44979598997](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44979598997)：同一 PR 跑重複主 CI／Live USB | 已由 #78 改成單一主 CI 呼叫 reusable Live USB；不要再加入獨立 PR trigger，造成重複昂貴建置 | `test_full_live_usb_is_called_and_gated_with_no_path_filtered_bypass` |
| Live USB 兩次 Clean Build 在同一 Job 依序執行（約 70.6 分鐘） | 兩個獨立 Runner 平行建置；Draft／Ready 使用同一 Gate（平行下單建置不會更快，分流只會讓轉 Ready 時重跑）。不要再加回 `ready_for_review` 觸發或 Draft 條件 | `test_draft_and_ready_run_identical_full_gate_without_ready_rerun`、`test_parallel_live_usb_requires_two_independent_clean_runners_and_real_bytes` |
| 最近 300 次 CI 有 250 次（83%）被取消；PR #88 的 29 個 Commit 產生 27 次被取消的 Run | 逐檔 Commit／Push（例如透過 API 一次只提交一個檔案）讓每次 Push 取消前一次 Run，Live USB 永遠跑不完。**本地完成同一輪修改與 `tests/test_ci_checks.py` 後，一次 Push** | 推送前 `git log origin/<branch>..HEAD` 確認是一批完整修改 |
| main 連續合併時，後一次 main CI 的 reusable Live USB 以 `github.ref` 分組並 `cancel-in-progress: true`，會取消前一次 main 驗證並使其 Required 失敗 | Live USB concurrency 改為 PR 以 PR 編號分組可取消；main／手動以 `run_id` 分組不取消 | `test_live_usb_concurrency_only_supersedes_pull_requests` |
| [PR #76](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/76)：Live USB GPT 唯讀屬性稽核失敗（過往紀錄） | 映像分割區屬性必須對照**實際 raw GPT entry bytes**、產生器設定與稽核解析；不得為了綠燈只修改預期值或測試 | 執行映像稽核並核對 raw image；QEMU 不等於實體 USB 驗收 |
| [PR #79](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/79)：`framebuffer_poc.py` 未列入離線模組 Allowlist（過往紀錄） | 新增冷端 Python 模組時，同步審查 runtime imports、離線 Allowlist、Buildroot 安裝清單；不得藉由開啟 `CONFIG_NET` 解決 | 離線模組測試＋Buildroot 安裝稽核＋QEMU 畫面證據 |
| [CI #46045030811](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/46045030811)（PR #79 `c666838`）：`clean-builds (2)` 映像建置與 SHA 都成功，`verify_image.sh` 在 `img: OK` 後以 exit 1 結束、無錯誤訊息 | #76 合入後 tty1 預設 session 改為 `usb-wallet-gui-session`，#79 的 `verify_image.sh` 仍以 `grep -q` 要求 `usb-wallet-console`，`set -e` 下靜默失敗。整合 main 後，所有寫死 inittab／session 名稱的稽核都要對照 `post-build.sh` 實際寫入的行 | `test_verify_image_tty1_session_matches_post_build`：要求 `verify_image.sh` 檢查的 tty1 行與 `post-build.sh` 寫入的行相同 |
| [CI #46144840043](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/46144840043)（PR #79 `9989b71`）：雙 clean build 與 OVMF 開機都過，framebuffer QEMU 在第一次選單就報 `unexpected menu return count before session 1: 2` | main 已在第一次選單由 `identify_media.py --serial console-ready` 送出一次性的 `USB_WALLET_CONSOLE_READY`；#79 又在每次畫選單時送同一字串，第一次就數到 2。每次選單改用獨立的 `USB_WALLET_CONSOLE_MENU`，一次性 READY 只用來等開機完成。新增 serial marker 前先 `git grep` 確認字串沒有其他送出者 | `test_menu_marker_is_distinct_from_one_shot_console_ready` |

### CI 修改前的固定檢查順序

1. **先在本地跑受影響的短測試**：修改 `.github/workflows/**`、`scripts/ci_checks.py`、`scripts/ci_workloads.py`、`tests/test_ci_checks.py` 時，至少執行 `python -m pytest -q tests/test_ci_checks.py`。若無本地執行環境，明確標記未驗證，避免宣稱成功。
2. **同時檢查正向與負向 Gate**：測試失敗、Job skipped/cancelled、未知路徑、workflow-only 變更、PR 新 HEAD、main 連續合併，均不得錯誤通過 Required Gate。對 YAML 使用結構化解析或限定 Step 範圍，避免脆弱的全文字串位置斷言。
3. **按變更影響執行必要工作**：docs/tests-only 不跑 Buildroot；GUI、Kernel、rootfs、映像／安全邊界變更才跑完整 Live USB。未知路徑維持 fail-closed；不為了省時關閉安全 Gate。
4. **不要用修文件反覆觸發完整 Buildroot**：將同一輪已確認的 CI 修正、測試與文件一次提交；若連續失敗，先取該次最新 HEAD 的失敗 Job Logs，定位單一根因後再推送。
5. **驗證以最新 HEAD 為準**：記錄 Commit SHA、Run URL、各 Job 結果、總 wall-clock 與 runner-minutes；只在實測後宣稱效能改善。對 GitHub API 無法列舉的歷史 Runs，不宣稱已完成全量稽核。


