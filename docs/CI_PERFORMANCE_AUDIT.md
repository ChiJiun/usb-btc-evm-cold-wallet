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
3. **雙獨立 Clean Build 平行化**：原本一個 Job 依序重建兩次，改為 `matrix.run=[1,2]` 兩個全新 Ubuntu Runner 同時建置、各自靜態稽核 `usb-cold-wallet.img` 與 `bzImage`；上傳兩份 SHA-256 證據及第二份實際映像。第三個 `verify-and-publish` Job 在**兩次建置均成功**後下載證據，先比對兩份雜湊，再對下載的實際映像與 kernel 執行 `sha256sum -c`；最後執行原本 QEMU/OVMF 開機、原始映像驗證、壓縮結果驗證與 Manifest，才能上傳 testnet-only Artifact。
4. **縮短測試映像封裝**：測試用途 `.img.xz` 從固定單執行緒 `-9e` 改為 `-6`；保留 `xz --test`、解壓縮後逐位元組 `cmp` 與 SHA-256。
5. **負向 Gate 回歸測試**：Python 敗退、Live USB 跳過與 `CI / Required` 的 fail-closed；source-only cache；兩個獨立建置與第三階段完整位元組驗證。

## 安全性與效能權衡

- **沒有**重用舊 Commit 的 CI 結果；每個受影響的 HEAD 仍有兩次完整 Clean Build。
- 平行 Runner 可減少關鍵路徑，但對 Runner 併發額度較敏感；Runner 分鐘數可能因獨立啟動與 Artifact 傳輸而略增。不可將預估減半視為實測。
- 雙建置不一致、下載驗證失敗、UEFI 啟動失敗或建置取消時，均不可發行已驗證映像。
- Release 工作流的簽章、來源 SHA、Provenance 與正式發行驗收維持獨立。
- PR #88 的**最新 HEAD** CI 與獨立 Security Review 必須完成才能將此稽核標為驗收通過。

## 後續實測方式

對比相同類型冷端變更的 CI：Scope、Python Matrix、兩個 Clean Build、雜湊比對、QEMU、壓縮封裝與 Required Gate。以 GitHub Actions 顯示的實際 Job 時間與 Artifact 時間計算 before/after，並記錄 cache hit/miss、排隊與是否發生取消。若歷史 API 查詢權限不支援全域列舉，需 GitHub Actions API `GET /repos/{owner}/{repo}/actions/runs` 的可列舉權限才能補足全量統計。
