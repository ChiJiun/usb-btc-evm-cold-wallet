# Issue #20 — 快速啟動、短暫解鎖與自動鎖定

> **僅供 Bitcoin testnet / Sepolia 測試。未經實體 Live USB 安全審計，禁止使用真實資產。**

本變更以 #19 離線 Tk GUI 為基礎，故 PR 採 **stacked** 方式指向
`feat/issue-19-offline-review-gui`。沒有實作額外的網路、RPC、瀏覽器、
USB HID 解鎖功能，也沒有把 passphrase 或 seed 寫入環境變數。

## 開機與主機安全

1. #1 Live USB 的可信任、唯讀系統啟動，並執行網路停用、swap 停用、
   RAM-root、COLD_VAULT、持久化掛載及 lockdown 檢查，將結果保存在
   `/run/usb-wallet/boot-checks.txt`。
2. 啟動 GUI 前再次呼叫 `runtime_audit()`；缺少檢查、偵測到網路介面、
   swap 或不允許的寫入持久化掛載，**拒絕啟動簽署畫面**。
3. 在進入 GUI 時設定目前程序的 `RLIMIT_CORE=0` 和檔案 `umask 077`。
   這不能阻止惡意 root、firmware、DMA、冷開機攻擊或 kernel dump。
4. 啟動後的第一個畫面預設 **LOCKED**；按選擇 BTC/EVM 才會進入
   **UNLOCKING**。每次解鎖及每次簽章前重新執行 runtime audit。
5. `scripts/launch_locked_signer.sh` 提供離線 image 的單用途啟動介面，
   交由 #1 Buildroot 套件安裝。此 PR **沒有**變更系統 init、systemd、
   開機設定或在 Devspace 安裝 GUI/Tk 套件。

唯一開發例外 `--public-test-vector-mode` 只能解鎖 repo 內已公開、
已遭破解的測試向量；非測試助記詞一律拒絕。

## 工作階段設計

```text
LOCKED → UNLOCKING → REVIEWING → APPROVED → SIGNED
   ↑         │           │          │        │
   └──任何錯誤 / 取消 / 逾時 / 安全稽核失敗────┘
                         ↑                    │
                         └─下一筆全新 review─┘
```

預設：

| 參數 | 值 |
|---|---:|
| 無動作鎖定 | 600 秒（10 分鐘） |
| 同一次解鎖最多完成簽章 | 3 筆 |
| 一次解鎖的最長存續 | 900 秒（15 分鐘） |
| 解鎖提示畫面最長 | 120 秒 |
| 連續失敗後延遲 | 2 → 4 → 8 → 16 → 32 → 60 秒（上限） |

- 每個簽章請求都重新建立 **ReviewSession**；原先逐頁勾選與最終
  挑戰字串**不會**繼承到下一筆。若 transaction digest 被修改，鎖定。
- 即使第二筆同網路、同收款人、同金額，仍需完整閱讀每頁並重新確認。
- **沒有**背景/自動簽章、熱鍵跳過確認或遠端 unlock。簽章同步執行。
- **SIGNED** 後可選擇「下一筆重新審核」或「完成／鎖定」；按後者立即
  丟棄本程式持有的金鑰參考。到達 3 筆上限則即刻鎖定。
- 取消解鎖、拒絕交易、輸入格式錯誤、USB-B 匯入取消、相機不可用、
  未能完成掃描、UI callback 例外、簽章失敗、匯出錯誤以及監測到來源
  USB 檔案遭刪除或替換，皆返回 **LOCKED**。掃描器內部超時須由
  #18 adapter 額外執行；同步阻塞攝影機 SDK 可能妨礙 UI 定時器。
- GUI 每秒檢查 idle/absolute deadline 與 runtime audit；簽署動作另有
  同步檢查。解鎖錯誤提示不回顯密碼或原始 mnemonic。

**注意：** rate limiting 目前是 **RAM 內／同一程序** 的 backoff，
重新啟動程序會重置計數。它不是對實體持有者的防暴力破解保證。
Vault KDF 仍使用原本 scrypt；未修改成本以換取速度。

## 啟動速度量測計畫

參考硬體上的驗收**目標**：USB 3.x 的 x86_64 UEFI 筆電冷開機
至 **LOCKED GUI 可操作**，目標 `p95 <= 90 秒`；需 5 次完全關機
冷開機（非重啟或待機），從按電源鈕用外部計時器到首個畫面接受
滑鼠／鍵盤操作，記錄型號、USB 硬體、韌體、時間與 PASS/FAIL。
若未達標，不得宣稱已滿足快速啟動要求。

GUI 初次顯示的 stdout 另外輸出：

```text
READY locked_gui kernel_boot_elapsed_ms=<毫秒>
```

此數字是 **Linux kernel 啟動後到 GUI ready 的時間**，不是電源鈕起算；
必須與外部冷開機量測分開比較。本次 Devspace 沒有實際 x86_64 USB
開機畫面／Tk 顯示，因此沒有硬體量測數據可填入結果。

## 安全限制與故障恢復

- 解鎖時 BIP39 助記詞、passphrase 與 BIP32 私鑰資料不可避免地進入
  Python 的 RAM，取消引用**無法保證 zeroize**。短暫的 10 分鐘工作
  階段是一項便利性／記憶體暴露時間折衷；請在完成後手動鎖定並關機。
- 設定 `RLIMIT_CORE=0` 僅限制目前程序的 core dumps；必須另外由
  #1 image 禁用 OS swap、hibernate、kernel kdump、除錯登入／
  意外可寫系統持久化。不要將助記詞、私鑰或密碼傳入 debug logs、
  crash reporter、命令列參數或環境變數。
- 失電後從 **LOCKED** 啟動，沒有儲存未加密密碼或 session token；
  已生成但尚未成功寫回的簽章可能遺失，online host 應確認鏈上
  nonce／UTXO 後再重新產生請求，不可不經核對直接重簽或廣播。
- 若來源 USB 被拔除或檔案身分（inode/device）變更，GUI 在定時檢查
  或簽署前鎖定。這只能偵測部分已掛載檔案的移除／替換，**無法取代**
  USB 控制器及實體主機層級的安全監測。
- 共享／感染主機不能被此軟體改造成可信硬體。鍵盤攔截、顯示器
  替換、firmware malware 與側通道均超出 Python 應用層防護。
- 關閉 GUI 不等於實體電腦斷電；使用可信任硬體電源按鈕關機。
  不在連網 Devspace 上修改 systemctl、Caddy、swap、kernel、init 等設定。

## 驗證範圍

純狀態機以虛擬時間驗證 600 秒 deadline、900 秒絕對 deadline、
120 秒解鎖時限、多筆交易獨立確認、backoff、取消與安全稽核失敗。
無 Tk 的 GUI 整合測試驗證未確認不得簽章、3 筆上限、USB 拔除及
相機不可用鎖定；既有 #19 全套測試須維持通過。

**仍待完成：** #1 真實 x86_64 image 開機與 Tk 安裝、實體 GUI
時間和操作測試、實體休眠/斷電恢復測試，以及與 #18 QR 相機
adapter 的整合。這些完成前 PR 應維持 Draft。
