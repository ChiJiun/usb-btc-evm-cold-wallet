# CI 效能稽核（2026-11-22，Issue #87／PR #88）

## 量測範圍與限制

透過 GitHub API 檢視已合併 PR #7/#62/#63/#64/#65/#68/#69/#70/#71/#73/#74/#78，以及 Open PR #75/#76/#79/#85/#88 的可取得 Workflow Runs、Jobs、部分 Logs 與 Artifacts。Actions 連線工具只有「以 Commit SHA 查詢 PR Runs」及「以 Run ID 查詢 Jobs」，無法列舉所有歷史 Runs 或取回超過服務回應上限的完整 Buildroot Log，因此本報告不是全庫所有歷史執行的完整統計，不能提供未經量測的平均數／p90。

可查證範例：

| Run | 實際證據／問題 | 判斷 |
| --- | --- | --- |
| [#44987850724](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44987850724)（PR #78） | BTC/PSBT Artifact 05:05:41 UTC；已驗證 Live USB Artifact 06:14:03 UTC，兩者相差 68 分 22 秒 | 完整 Buildroot／QEMU／封裝主導總等候時間（不代表 Buildroot 單一 Step 精確耗時） |
| [#44997976256](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44997976256)（PR #75） | Python 3.12/3.13 測試失敗（4 failed、836 passed、3 skipped，pytest 約 51.76 秒）；同時完整 Live USB 仍在執行 | 已失敗的 PR 浪費昂貴建置 |
| [#44997656443](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44997656443)（PR #85） | Live USB 等不相關 Job 正常跳過，CI / Required 成功 | #78 的文件／測試分流有生效 |
| [#44979598989](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44979598989) 與 [#44979598997](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44979598997)（PR #68） | 過往同一 PR 同時跑主 CI 和獨立 Live USB Workflow | 已由 #78 的 workflow_call 整合消除，不應重新實作 |
| [#44930958640](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44930958640)、[#44933217959](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44933217959) | 先前獨立 Live USB Build 完成；原本兩次 Clean Build 在同一 Job 依序執行 | 可用平行獨立 Runner 壓縮關鍵路徑 |

## 本次修正

1. **快速失敗**：`live_usb` 依賴 Python 3.12／3.13 matrix 成功；失敗時不啟動完整建置，`CI / Required` 仍必須失敗。成功的 HEAD 不減少任何必要安全驗證。
2. **下載快取**：只重用 Buildroot 來源、Buildroot 發行壓縮檔、hash-locked Wheelhouse（`build/dl`、`build/cache`、`build/wheelhouse`）；仍逐次進行 Buildroot 簽章/來源雜湊與 Wheelhouse SHA-256 驗證。編譯輸出、rootfs、映像與通過紀錄不快取。
3. **分階段 Clean Build**：Draft PR 僅執行一次完整 Buildroot 建置、映像 SHA-256 驗證及 QEMU/OVMF 開機，Artifact 明確標示未通過可重現性驗證；Draft PR 不能合併。PR 轉為 Ready 時，`ready_for_review` 觸發新的 CI，執行兩個獨立 Runner 平行 Clean Build，第三個 Job 比對完整 SHA-256、核對實際映像與 kernel，再執行 QEMU/OVMF；main Push 與手動執行同樣保留雙重驗證。
4. **縮短測試映像封裝**：測試用途 `.img.xz` 從固定單執行緒 `-9e` 改為 `-6`；保留 `xz --test`、解壓縮後逐位元組 `cmp` 與 SHA-256。
5. **負向 Gate 回歸測試**：Python 失敗、Live USB 跳過與 `CI / Required` fail-closed；source-only cache；Draft 單次與 Ready 雙次建置、實際映像位元組驗證。

## 安全性與效能權衡

- **沒有**重用舊 Commit 的 CI 結果；Draft PR 每次受影響的 HEAD 執行一次 Clean Build，Ready PR／main 執行兩次。Draft 的成功不能取代 Ready PR 最新 HEAD 的雙重驗證。
- 平行 Runner 可減少關鍵路徑，但對 Runner 併發額度較敏感；Runner 分鐘數可能因獨立啟動與 Artifact 傳輸而略增。不可將預估減半視為實測。
- 雙建置不一致、下載驗證失敗、UEFI 啟動失敗或建置取消時，均不可發行已驗證映像。
- Release 工作流的簽章、來源 SHA、Provenance 與正式發行驗收維持獨立。
- PR #88 的**最新 HEAD** CI 與獨立 Security Review 必須完成才能將此稽核標為驗收通過。

## 後續實測方式

對比相同類型冷端變更的 CI：Scope、Python Matrix、兩個 Clean Build、雜湊比對、QEMU、壓縮封裝與 Required Gate。以 GitHub Actions 顯示的實際 Job 時間與 Artifact 時間計算 before/after，並記錄 cache hit/miss、排隊與是否發生取消。若歷史 API 查詢權限不支援全域列舉，需 GitHub Actions API `GET /repos/{owner}/{repo}/actions/runs` 的可列舉權限才能補足全量統計。

## 常見失敗與防止重複浪費 CI 時間（#87）

每次修改 CI、Buildroot 或其測試前，先讀本節與 `docs/CI_SECURITY.md`；新發現的重複性故障須記錄**實際 run、根因、預防測試與驗證結果**，不能只記錄症狀。

| 已發生的問題／證據 | 根因與避免方式 | 最小驗證 |
| --- | --- | --- |
| [CI #45002446458](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/45002446458)：Python 3.12／3.13 同時失敗，819 passed、1 failed、3 skipped | `test_draft_skips_expensive_image_packaging_and_upload` 用 `lstrip().startswith('if: ...')` 斷言 YAML Step；新增註解後測試誤判。改為檢查該 Step 範圍內的實際 `if`，避免依賴註解、空白或相鄰 Step 的文字位置。修正 Commit `7fa0bbe1`；**尚待最新 HEAD CI 證明通過** | 先執行 `python -m pytest -q tests/test_ci_checks.py`，再推送；兩個 Python Matrix 均須成功 |
| [CI #44997976256](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44997976256)：Python Matrix 已失敗，Live USB 仍耗時建置 | 缺少快速測試前置依賴。完整 Live USB 需等待 Python Matrix 成功；選中 Live USB 卻因失敗而跳過時，`CI / Required` 必須失敗，不能把 skipped 當 PASS | `test_live_usb_heavy_build_requires_successful_python_matrix` 與 Required Gate 負向測試 |
| [CI #44979598989](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44979598989)、[#44979598997](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44979598997)：同一 PR 跑重複主 CI／Live USB | 已由 #78 改成單一主 CI 呼叫 reusable Live USB；不要再加入獨立 PR trigger，造成重複昂貴建置 | `test_full_live_usb_is_called_and_gated_with_no_path_filtered_bypass` |
| Live USB 建置過慢且 Draft PR 反覆跑兩次 | Draft PR 只需一次乾淨建置＋實際 SHA-256＋QEMU，避免大型封裝與最終 Artifact；Ready PR 最新 HEAD、main 與手動完整驗證才執行兩次獨立建置與可重現性比較。Draft 的成功不能替代 Ready Gate | `test_draft_feedback_is_single_build_but_ready_event_requires_dual`、`test_draft_skips_expensive_image_packaging_and_upload`；另需 Ready 事件實際 CI 證據 |
| [PR #76](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/76)：Live USB GPT 唯讀屬性稽核失敗（過往紀錄） | 映像分割區屬性必須對照**實際 raw GPT entry bytes**、產生器設定與稽核解析；不得為了綠燈只修改預期值或測試 | 執行映像稽核並核對 raw image；QEMU 不等於實體 USB 驗收 |
| [PR #79](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/79)：`framebuffer_poc.py` 未列入離線模組 Allowlist（過往紀錄） | 新增冷端 Python 模組時，同步審查 runtime imports、離線 Allowlist、Buildroot 安裝清單；不得藉由開啟 `CONFIG_NET` 解決 | 離線模組測試＋Buildroot 安裝稽核＋QEMU 畫面證據 |

### CI 修改前的固定檢查順序

1. **先在本地跑受影響的短測試**：修改 `.github/workflows/**`、`scripts/ci_checks.py`、`scripts/ci_workloads.py`、`tests/test_ci_checks.py` 時，至少執行 `python -m pytest -q tests/test_ci_checks.py`。若無本地執行環境，明確標記未驗證，避免宣稱成功。
2. **同時檢查正向與負向 Gate**：測試失敗、Job skipped/cancelled、未知路徑、workflow-only 變更、Draft→Ready、Ready 新 HEAD，均不得錯誤通過 Required Gate。對 YAML 使用結構化解析或限定 Step 範圍，避免脆弱的全文字串位置斷言。
3. **按變更影響執行必要工作**：docs/tests-only 不跑 Buildroot；GUI、Kernel、rootfs、映像／安全邊界變更才跑完整 Live USB。未知路徑維持 fail-closed；不為了省時關閉安全 Gate。
4. **不要用修文件反覆觸發完整 Buildroot**：將同一輪已確認的 CI 修正、測試與文件一次提交；若連續失敗，先取該次最新 HEAD 的失敗 Job Logs，定位單一根因後再推送。
5. **驗證以最新 HEAD 為準**：記錄 Commit SHA、Run URL、各 Job 結果、總 wall-clock 與 runner-minutes；只在實測後宣稱效能改善。對 GitHub API 無法列舉的歷史 Runs，不宣稱已完成全量稽核。


## #88 目標架構與最終驗收標準

採用「**依檔案與依賴選擇必要工作 → 快速失敗 → 依驗收階段升級**」的分流。優先改善等待時間、Runner 分鐘數與錯誤定位，同時保留安全完整性。

| 階段／變更 | 必要驗證 | 不應浪費的工作 |
| --- | --- | --- |
| 文件、AGENTS、Issue 模板 | Scope、Secret scan、Required Gate；README 發行中繼資料變更需 Wheel smoke | 不重建未受影響的 Buildroot／Windows／Node |
| Python／測試／CLI | Python 3.12／3.13、Wheel、受影響整合測試、Required Gate | 無冷端映像輸入變更時不重建 Live USB |
| Windows／Node／QR／Snap | 對應 Node、Windows、瀏覽器與跨語言測試；依賴改動加 Audit | 不因單純 UI／前端修改重建離線映像 |
| CI／Scope／Required Gate | Python 回歸、實際 reusable workflow smoke、所有相關 Gate 的正負向測試 | 僅 CI 呼叫／Scope 變更不重編未變動的映像 |
| Buildroot／Kernel／冷端 Runtime／映像 | Python 先 PASS；Draft 一次乾淨 Build＋raw SHA＋QEMU；Ready 最新 HEAD 雙獨立乾淨 Build、SHA 比對、QEMU、映像封裝 | Draft 不執行第二次 Build、不壓縮或發布最終映像 |
| main／正式 Release | 完整必要 CI；Release 額外要求簽章、來源 SHA、Provenance、獨立重建與 Publish Gate | 不以 Draft 的 PASS 取代 Release 驗收 |

**分流例外必須保守**：未知路徑、比較 SHA 失效、刪除／重新命名、模組 Allowlist 異動、Build Script／Workflow 真正建置邏輯變更，應觸發相應的完整安全驗證；不能僅因副檔名或測試名稱而豁免。受影響 Job 的 failed、cancelled、skipped 或缺席不能被 Required Gate 誤認為成功。

### #88 可合併的證據門檻

1. **最新 HEAD** 的 Python 3.12／3.13、相關整合測試與 `CI / Required` 全部成功；若 HEAD 再變更，重新驗證。
2. 對分類器提供代表性正反案例：純文件、README、Windows、QR、冷端、Buildroot、Workflow body、未知路徑、刪除／改名、無效 SHA；逐一確認 Job 被選中或略過的結果正確。
3. 實際驗證 Draft 只有一個 Clean Build、完成 raw SHA 與 QEMU；Draft 不產生標示為雙重可重現的正式 Artifact。
4. **必須另有 Ready PR 的實際事件證據**：同一最新 HEAD 觸發兩個獨立 Runner，SHA 完全一致，驗證選中的實際 raw image，QEMU 成功後才封裝。不能以靜態讀 YAML 或 Draft 的成功代替。
5. 核對 Required Checks／Ruleset：Draft 轉 Ready、PR 更新、main Push 不得利用舊的成功狀態跳過應執行的 Gate。
6. 記錄實測 wall-clock、Runner 分鐘數、cache hit/miss、排隊時間與失敗成本；效能宣稱必須有可比的 before／after，不把估算當實測。
7. 由獨立 Review 檢查完整 Diff、CI Logs 與安全邊界；未解除的實體 USB／GUI 驗收不得被描述為 CI 已完成。

**完成判定**：上述證據全部齊備才標為 Done；缺 Ready 雙建置、Ruleset 或實測資料時，明確標為 BLOCKED／NOT VERIFIED。禁止為追求綠燈而降低安全 Gate。

## Lead Time 優先方案（PR #88 後續修訂）

為縮短「第一個 Commit → Merge」時間，**Draft PR 預設不執行完整 Live USB Clean Build**。Draft 仍執行 Scope、Python、受影響的跨平台／整合測試、Live USB reusable workflow contract smoke 與 Required Gate；`live_usb` 在 Draft 被跳過屬預期結果，Ready／main／手動完整驗證時，若該工作應執行卻 skipped、failed、cancelled，Required Gate 必須拒絕。

**Ready PR** 在最新 HEAD 上直接平行執行兩次獨立 Clean Build，SHA-256 完全一致後才驗證實際映像、QEMU/OVMF、封裝與 Artifact。此時必須完成獨立 Security Review；不得拿 Draft 的快速 CI 代替完整安全驗收。Draft 開發若需要實際 GUI／映像證據，可使用獨立的手動完整 Workflow，但該結果不能代替 Ready 最新 HEAD 的 Gate。

### 時間預估（尚非實測，包含 Runner 排隊的不確定性）

| 情境 | CI 回饋／驗收預估 | 合併 Lead Time 影響 |
| --- | --- | --- |
| 純文件 | 2–6 分鐘 | 免 Buildroot，仍需 Review |
| Python／小範圍程式 | 5–20 分鐘 | 可在短測試期間同步 Review |
| Windows／Node／QR／Snap | 10–30 分鐘 | 瀏覽器、跨語言與 Windows Job 可平行 |
| Draft 冷端／Buildroot | 5–30 分鐘（快速 CI，不包含映像驗證） | 省下每輪約 40–90 分鐘的完整映像建置等待；估計值不能當實測 |
| Ready 冷端／Buildroot | 45–110 分鐘（雙 Clean Build＋比對＋QEMU＋封裝） | 一次正式驗收，Review 可同步進行 |
| 修正後再次 Push Ready | 45–110 分鐘／輪（若變更仍影響映像） | 每次新 HEAD 必須重跑；減少返工比快取更重要 |
| 正式 Release | 60–150+ 分鐘 | 與 PR Merge Gate 分開，保留簽章與 Provenance 驗證 |

以上時間是規劃區間，未以相同變更類型實際比較 before／after。若 Review 未完成、出現衝突、Actions 排隊或驗證失敗，總 Lead Time 會增加。應追蹤 median／P90 PR Lead Time、每 PR CI 輪數、失敗至修復時間、Runner 分鐘數，避免只最佳化單一 Job。

**既有文件若仍提及「Draft 每次必做一次 Clean Build」，以本節最新策略為準。** 本次變更需等待最新 HEAD 的 CI 與 Ready 事件實際驗證後才可標 Done。
