# 單 USB 真機驗收（預備工具；尚無實機 PASS）

範圍：Issue #24 / #37 / #43。**目前主線的 two-USB M0 與 #37 單 USB 是不同驗收關卡。** PR #68 提供的 testnet-only artifact 主要是 two-USB 基準；#75 / #76 尚在整合，不能把 #68 的兩分割區映像認成 #76 的三分割區單 USB 映像。執行前必須取得最終整合 SHA、對應 exact image、兩次 clean-build + QEMU/OVMF 證據，確認同版本的 Windows Companion 與冷端 runtime。只用專用測試幣與測試錢包。

## 安全限制與來源核對

- 預設唯讀：本目錄的工具只查磁碟資訊、計算**映像檔本身**的 SHA-256、寫入指定的**本機內接磁碟** JSON 紀錄；沒有磁碟清除、格式化、分割、刷寫、掛載、簽名或廣播命令。
- Windows 每次重跑 `physical_usb_inventory.ps1`，以當次 drive letter 查詢 partition → disk number → 全部分割區，核對 USB BusType / 型號 / 容量。**F: 與 PhysicalDrive3 均不能假設永久不變**；出現多個候選或不符時停止。此前 F: General UDisk 31.46 GB 的唯讀辨識僅供比對，非現次授權。
- 影像 SHA-256 來源必須是已核實的 workflow artifact/manifest（不能從同一個未驗證下載包自我宣稱可信）。Windows 的 Get-FileHash 只作逐位元比對；Linux 已存在的 `scripts/verify_image.py`、`scripts/verify_image.sh`、`scripts/verify_uefi_boot.sh`、`scripts/verify_release_assets.py` 負責既有 GPT／kernel／release 驗證，不另造平行判斷器。
- `Get-FileHash` 的 PASS 只證明本機映像檔與**手動指定** digest 一致，**不代表裝置內容已刷寫一致**，更不是 boot provenance 認證。若 image 來源、大小或可信 digest 不明，記錄 BLOCKED。
- Windows 連網／系統權限可以更改普通 USB 的 ESP、Vault、TX_TRANSFER，GPT 只代表結構，沒有 secure boot／防回滾保障。不得把此工具當作 USB 硬體信任證明。
- 證據只收 public testnet txid、硬體型號、firmware 版本、分割區 label/type/size、timestamp、public image commit/hash 與**經人工去識別**的截圖或文字紀錄位置。禁止助記詞、紙本 policy anchor、密碼、私鑰、vault、完整未遮罩交易請求、可識別裝置序號。實體中斷測試使用無資產測試帳戶與可重建測試 USB。

## Windows 唯讀 inventory 與 media readback（PowerShell 5.1+）

目前尚無 #76 自動發布、具獨立可信來源雜湊的最終 manifest；缺少來源驗證時必須 BLOCKED。先以最終整合版本的 verify_image.py 核對 image 本身的 primary/backup GPT、FAT 與 geometry，再建立以下 JSON manifest，從可信 CI/簽章另行取得 manifest SHA-256、image SHA-256、source commit。不得信任同一個未驗證檔案包自述的 digest。

Manifest schemaVersion 1 的三分割區內容如下（sourceCommit、imageSha256、imageSizeBytes、model 需填入最終 exact-image 驗證結果）：

~~~json
{
  "schemaVersion": 1,
  "layout": "single-usb-issue-37",
  "sourceCommit": "<40-hex exact commit>",
  "imageSha256": "<64-hex exact image sha256>",
  "imageSizeBytes": 0,
  "diskGuid": "f1448aa1-28cc-54bf-8fdd-3008514c0ab5",
  "model": "<verified USB model>",
  "partitions": [
    {"partitionNumber": 1, "partitionGuid": "e2bd6d1b-8de5-502d-a897-c53a8e60f46b", "gptType": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "offsetBytes": 1048576, "sizeBytes": 67108864, "filesystem": "FAT", "label": "USBCOLD_EFI"},
    {"partitionNumber": 2, "partitionGuid": "18f1c36f-d5c0-5052-9cd2-03e9c2a48f00", "gptType": "0fc63daf-8483-4772-8e79-3d69d8477de4", "offsetBytes": 68157440, "sizeBytes": 67108864, "filesystem": "FAT", "label": "COLD_VAULT"},
    {"partitionNumber": 3, "partitionGuid": "42f6f5d4-9310-5ac3-b5d4-1540cbe7d6b4", "gptType": "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", "offsetBytes": 135266304, "sizeBytes": 536870912, "filesystem": "FAT32", "label": "TX_TRANSFER"}
  ]
}
~~~

上述 layout GUID/geometry 來自 #76 當前 genimage.cfg/identify_media.py；不得在 #76/#79 整合後未重新檢驗就沿用。

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/physical_usb_inventory.ps1 -DriveLetter F -ImagePath "C:\wallet-tests\usb-cold-wallet.img" -LayoutManifest "C:\wallet-tests\trusted-layout.json" -ExpectedManifestSha256 "<independent 64-hex manifest SHA>" -ExpectedCommit "<exact 40-hex commit>" -ExpectedSha256 "<trusted 64-hex image SHA>" -VerifyMediaReadback -Json
~~~

每次拔插都需重新執行 drive letter → partition → parent disk discovery。PhysicalDriveN 只在當次新辨識後供唯讀 raw media 開啟，不能保存重用或當作寫入目標。逐一驗證全部三個 partition 的 disk number、unique GUID、type GUID、offset、size、filesystem、FAT label、drive letter，並拒絕非 USB、GUID 重複、假 label、錯誤 parent 或轉接替換。

輸出 imageFileVerified（主機檔案 hash）、deviceLayoutVerified（分割區/原始 FAT metadata）、writtenMediaVerified（≤ 1 GiB 的 raw image 長度 prefix 唯讀 readback hash）三個獨立狀態；三者全真只產生 INVENTORY_VERIFIED，physicalAcceptance 始終 NOT TESTED。Windows 無法取得唯讀 physical readback 時直接 BLOCKED。此比對不提供硬體不可複製身分、Secure Boot 或防回滾保證。

## 跨重開機紀錄

先在**本機內接固定磁碟**建立 `C:\\wallet-tests\\evidence`（非 USB、非同步分享資料夾），只在人工核對來源後執行：

```powershell
py -3 scripts/physical_acceptance.py init --file C:\\wallet-tests\\evidence\\run.json --commit <40-hex-exact-commit> --image-sha256 <64-hex> --hardware "ThinkPad T14" --firmware "UEFI 1.20" --device-identity "redacted-usb-test-a"
py -3 scripts/physical_acceptance.py record --file C:\\wallet-tests\\evidence\\run.json --case WIN_USB_ID --status PASS --evidence "inventory-redacted.json" --command "physical_usb_inventory.ps1 WIN_USB_ID" --exit-code 0 --operator-verified --note "Observed physical readback and full GPT layout"
py -3 scripts/physical_acceptance.py boot --file C:\\wallet-tests\\evidence\\run.json --phase WINDOWS_TO_USB --seconds 78 --evidence "boot-timing-redacted.txt"
py -3 scripts/physical_acceptance.py tx --file C:\\wallet-tests\\evidence\\run.json --chain sepolia --txhash <0x...64-hex> --evidence "sepolia-explorer-redacted.txt"
py -3 scripts/physical_acceptance.py show --file C:\\wallet-tests\\evidence\\run.json
```

若測試 Windows 沒有 Python，記錄工具可在**另外的測試工程機**執行，傳輸**僅公開、已去識別**的步驟與時間；產品 Companion 在驗收時仍必須證明無 Python/Node 依賴。受測 USB OS 不需要 Python CLI 操作此工具。JSON 所有 cases 初值為 NOT TESTED。人工判定 PASS 須具既有證據檔及 SHA-256、實際 command、退出碼 0、--note 觀測及 --operator-verified。WIN_USB_ID / GPT_LAYOUT 必須由 INVENTORY_VERIFIED JSON 佐證，且 writtenMediaVerified 為 true；只有 image SHA 不可通過這兩項。證據超過 30 天或遭竄改、缺欄位、symlink/junction、partial write 均拒絕，FAIL/BLOCKED 保留原因。重開機時間須由人工實測，不能用命令呼叫時間推算。

## E2E 測試矩陣

每項先標記 NOT TESTED；在同一份 `run.json` 中更新各 case 的 status、observations、timestamp。每項留可稽核的**已遮罩**照片／影片、CLI-free GUI 螢幕紀錄或既有 audit log；證據不得含敏感資料。

| Case | 實際操作／預期結果 | 證據 |
| --- | --- | --- |
| WIN_USB_ID | Windows 10/11 無管理員環境，重新辨識 USB bus、型號、容量、partition；候選不一致拒絕 | `inventory-redacted.json` |
| IMAGE_SHA256 | 與可信 exact image manifest 比對完整 raw .img SHA-256，拒絕 mismatch | raw digest / artifact run URL |
| UEFI_BOOT | 真實 x86_64 UEFI 明確選 USB，完整啟動 cold appliance，記錄 firmware/Secure Boot、冷開機時間 | 螢幕、計時 |
| GPT_LAYOUT | 最終單 USB 映像應依 #76 exact 3 partitions：EFI、COLD_VAULT、TX_TRANSFER；核對 backup GPT、Guid/type、容量、Windows 可見性；不套用 #68 的 two-USB 規格 | Windows inventory + 現有 verify_image.py + 現場照片 |
| VAULT_PERSISTENCE | 建立專用測試錢包／關機重啟，僅加密 vault 保留、錯誤密碼拒絕；檢查 Windows 不可直接取得秘密 | audit、遮罩截圖 |
| MOUNT_AUDIT | 真機確認 RAM root、partition parent 唯一性、Vault / transfer exact mount source/options、內建磁碟未掛載；異常進 lockdown | runtime audit 紀錄 |
| NETWORK_ISOLATION | 真機確認 CONFIG_NET=n、無 /proc/net、無可使用的網路通道、swap 為空 | offline screen/audit |
| BTC_REQUEST | Windows portable GUI 以 watch-only BTC testnet 準備 PSBT v0、記錄 outputs/UTXO/change/fee 與 requestId；不得手改 JSON | 遮罩 GUI |
| BTC_COLD_REVIEW | Reboot USB OS，GUI 完整展示 network/account/recipient/amount/change/fee 並需人工確認 | 螢幕與核對欄位 |
| BTC_SIGN | 人工確認後冷端只產生預期 signed PSBT，拒簽不得產生簽名 | 遮罩 signed result hash |
| BTC_IMPORT_VERIFY | 再 reboot Windows，Companion 重新解析 signed bytes、核對原始請求與 PSBT，finalize/extract；錯誤拒絕 | import/recover 紀錄 |
| BTC_BROADCAST / BTC_CONFIRM | 使用者按 Broadcast 後才廣播，記錄 BTC testnet txid/確認 | txid 與 explorer / 自有節點 |
| SEPOLIA_REQUEST | Windows GUI 建立 Sepolia chainId=11155111、type-2 native transaction，顯示 nonce/value/gas/fee | GUI |
| SEPOLIA_COLD_REVIEW | Reboot USB OS，顯示 chain/account/to/value/nonce/total max fee，人工按批准 | 螢幕 |
| SEPOLIA_SIGN | 只簽允許的原始 payload，使用者取消不回傳簽章 | receipt hash |
| SEPOLIA_IMPORT_VERIFY | Reboot Windows，Companion recover signer、逐欄核對 requestId/chain/account/payload digest | 遮罩驗證紀錄 |
| SEPOLIA_BROADCAST / SEPOLIA_RECEIPT | 使用者明確廣播，再紀錄 Sepolia tx hash、receipt status | public tx hash |
| REPLACE_REQUEST / REPLACE_RESPONSE | 在**可重建測試交換區**替換內容，拒絕不符 digest/requestId/account，零未授權簽章/廣播 | expected/actual |
| REPLAY_REQUEST / REPLAY_RESPONSE | 同一請求或 signed response 重播／重開機重送，應拒絕或安全 reconcile，不能重簽／雙重廣播；若缺 trusted monotonic anchor 依 #75 必須 BLOCKED | state/拒絕證據 |
| WRONG_CHAIN / WRONG_ACCOUNT | 交換 BTC/Sepolia chainId、account、nonce/UTXO，必須 fail closed | expected/actual |
| WRONG_DISK / USB_REPLUG | 交換 USB 或重新插入後核對裝置 identity，不得沿用舊 disk number／drive letter，錯誤裝置 fail closed | 前後 inventory 與拒絕證據 |
| MALFORMED_TRANSFER | 可重建交換區注入不合法 JSON／缺少欄位／錯誤 digest，應拒簽、拒匯入 | 輸入摘要與拒絕紀錄 |
| USB_UNPLUG | 冷端確認前拔除 USB，觀察 lockdown、錯誤、重新插入後重新辨識，不自動簽 | 影片與錯誤 |
| POWER_INTERRUPTION | 僅測試專用／可重建 USB，分別在 request / vault / response 寫入階段斷電；檢查原子性與可恢復性 | 時點、恢復紀錄 |
| RECOVERY | 使用專用測試種子演練損毀／恢復，禁止在公開 log 錄下助記詞 | 遮罩紀錄 |

### 執行順序與阻擋條件

1. 核對最終整合版 exact HEAD、Live USB artifact（完整 raw image）、checksum、可信 commit 與 CI；需要二次 clean build / QEMU，並使用專案現有的 image verifier。若 #75 replay anchor 未解或 #76 GUI 未經驗證，E2E 註記 BLOCKED。
2. Windows 唯讀盤點；人工另行決定是否刷寫，**此工具不會自動刷寫**。刷寫行為須另行由具權限的操作者在核對裝置後執行。
3. 在 Windows 上建立 watch-only 請求、人工 reboot UEFI、離線 GUI 人工核對與簽署、人工 reboot Windows、由 Companion 驗證並按 Broadcast。BTC 與 Sepolia 分別全程測一次，記錄兩次 reboot 各自耗時。
4. 完成正向流程後，在可重建測試資料上逐個注入負向情境；實機拒絕時保留 fail-closed 證據；**不可用模擬測試結果填實機 PASS**。
5. 測試矩陣中所有項目獨立判定 PASS / FAIL / BLOCKED / NOT TESTED；本次提交的初始狀態全部 NOT TESTED。對 #24/#37/#43 的 release gate 仍須人工追蹤，不會自動關閉 Issue。

## 重用與來源

僅使用本 repo 的 `scripts/verify_image.py`、`scripts/verify_image.sh`、`scripts/verify_uefi_boot.sh`、`scripts/verify_release_assets.py` 作既有驗證；PowerShell 使用 Microsoft 原生 `Get-Partition` / `Get-Disk` / `Get-Volume` / `Get-FileHash`，Python 使用標準函式庫。沒有複製任何第三方專案原始碼、沒有新增簽章或映像 parser。上游 SeedSigner/Krux/Bitcoin Core 僅作既有 Issue #24/#43 測試場景參考；未主張任何上游測試已通過。

## Journal 與證據限制

Journal schemaVersion 2。`PASS` 需要實際檔案（與 journal 同目錄）、SHA-256、`--command`，每筆 observation 綁定 source commit、image SHA-256、device identity 及 UTC 時間。當次 Windows inventory 必須核對 GPT disk/partition GUID、parent、offset、size、filesystem、label、傳輸磁碟機代號及 physical readback，缺少 exact image manifest/commit/digest 均回報 BLOCKED。原始 journal 的內文與檔案可由本機使用者整體替換，因此此功能提供可稽核完整性檢查，**不構成不可否認證明或防回滾 trusted anchor**。不得以自行建立的文字檔冒充真實硬體驗收結果。

## Harness 測試與真機驗收分離

PowerShell fixtures 與 Python unit tests 只證明 harness fail-closed 行為，CI 成功標記 harness unit-test PASS。#66/#43 真實 USB physical acceptance 仍為 NOT TESTED，不因本 PR 合併而關閉；後續須以整合後最終 image 重測 Windows 兩次插拔、錯誤裝置/相同 label、USB 真機 UEFI/GUI、BTC testnet/Sepolia 跨重啟、斷電持久化與 replay trusted anchor。測試可重建專用 USB，禁止以 CI/mock 證據替代真機。
