# 實體 USB 驗收操作清單

先完成 [Two-USB M0（#66）](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/66)，再做 [Single-USB（#37）](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/37) 和 [發行前實體安全驗收（#24）](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/24)／[#43](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/43)。這份清單供 Windows 操作者使用。[M0 詳細規格](TWO_USB_M0_ACCEPTANCE.md) 定義映像、讀回與證據要求，[Vault 演練](RECOVERY_REHEARSAL_CHECKLIST.md) 定義恢復方式。全程只用專用測試錢包與測試網資產。

## 目前有什麼證據

| 範圍 | 已有證據 | 實體狀態 |
| --- | --- | --- |
| #85 合入時的主線 `db9f72eba8a893484be8fd035590a7a3e3fcc7f7` | [主線 CI 45151530324](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/45151530324) 成功，合入 [#85](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/85) 文件。[#81](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/81) 已合入公開向量與 Vault 故障自動化。[#86](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/86) 已合入 Core/regtest、Policy、ReplayLedger 自動化。 | 真機 **NOT TESTED**。Linux 掛載 VFAT、Windows EXE smoke 及模擬故障屬各自的測試環境。 |
| Two-USB 映像 | [#7 的 CI 44917033751](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/44917033751) 有 clean build／OVMF 與雜湊，該次只留雜湊。較新的 [CI 45048499740](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/45048499740) 對 `5e49d4c97eb1e800bdb513c7b38465bbb33274aa` 完成獨立兩次建置、QEMU/OVMF 及發布，曾確認驗證後的測試映像 artifact ID `14765414896` 可取得，下載時須再查有效期限。 | 映像選定 **BLOCKED**。#66 歷史上指定 #7，需取得該來源的匹配原始映像，或由負責人在 #66 明確指定較新來源及其精確映像。 |
| Single-USB | [#76](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/76) 已合入主線 `da6accda646b5690cf97339ea8652b68af840fae`（三分割區 GPT 與冷端 runtime）。2026-11-27 以 [CI 45936083525](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/45936083525) 的 `usb-cold-wallet.img`（SHA-256 `5cda1cd930e4eac5d8f82868fc9c794d4cfa4f22de710aa3df6404bde7a2d700`，來源 `7eaa7ec`）在 Acer Aspire A515-57G 實機開機（Secure Boot **關閉**：映像使用未簽章 GRUB2，不支援 Secure Boot，見 [Single-USB runtime](SINGLE_USB_RUNTIME_API.md)；2026-11-28 由 Windows 登錄檔 `UEFISecureBootEnabled=0` 確認該機目前狀態），開機稽核全部 PASS，選單 **5** 顯示 `TX_TRANSFER mounted.`，選單 **6** 由 OS 接受關機；未建立錢包、未簽署，也未確認硬體最終斷電。證據（映像與刷寫檔 SHA-256、dd 部分寫入與讀回比對、開機稽核逐項結果、已知限制）見 [#76 實機驗收紀錄](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/76#issuecomment-7218438457)。[#75](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/75) 有 v2 流程與狀態測試，[#79](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/79) 有 framebuffer/evdev 原型，[#80](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/80) 有唯讀盤點與證據表。#80 [45053606804](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/45053606804) 的雙建置及發布 job 成功，僅適用各次 CI 的 checkout。#79 [45150990859](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/45150990859) 已完成且成功。 | 冷端開機與媒體稽核 **PASS（部分 S-01）**。GUI、簽署與跨開機整合實測 **BLOCKED**：#75、#79、#80 仍是 Draft，須等候同一個可測整合版本。 |

狀態逐案填寫。**PASS** 代表指定環境實作符合預期且有可檢閱的證據。**FAIL** 代表實測違反預期。**NOT TESTED** 代表尚未測試或缺少可核對的實測證據。**BLOCKED** 必須列出阻礙，例如缺少第二支 USB、映像或測試網交易來源。工作流程的 skipped 不計為 PASS。

## 1. Two-USB M0（#1／#43／#66）

準備一台 x86_64 UEFI 冷端機、一台可保留 Companion 待簽狀態的 Windows 線上機、兩支可清空的測試 USB，以及經驗證的測試映像。先在 Windows 系統碟建立證據資料夾，手動備份兩支 USB。若沒有獨立線上機，先回報設備限制。主線 Companion 的 pending 狀態會隨服務重啟消失。保持冷端實體網路斷開，先拆除非測試的外接儲存裝置。

### Windows 唯讀預檢

每次只識別剛插入的目標，再同時插入兩支核對父磁碟，並在每次重插後重做。輸出先保存在本機，回傳前遮蔽序號和可辨識個資。用容量、型號、USB bus 和分割區映射共同辨識，磁碟編號或代號變動時重新核對。

```powershell
Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,SystemType
Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion
Get-ComputerInfo -Property BiosFirmwareType,OsBuildNumber
Get-Disk | Select-Object Number,FriendlyName,BusType,PartitionStyle,Size,LogicalSectorSize,Guid,IsBoot,IsSystem
Get-Partition | Select-Object DiskNumber,PartitionNumber,Guid,GptType,Offset,Size,DriveLetter
Get-Volume | Select-Object DriveLetter,FileSystem,FileSystemLabel,Size
```

預期 USB-A/B 各有獨立的 `DiskNumber`、`BusType=USB`、`IsBoot=False`、`IsSystem=False` 與 512-byte logical sector。任何不明或重複候選先停止。取得 #66 選定的 artifact 後，在解壓目錄執行以下唯讀命令。

```powershell
Get-Content -LiteralPath .\ARTIFACT-MANIFEST.txt
Get-Content -LiteralPath .\run-1.sha256,.\run-2.sha256,.\usb-cold-wallet.img.sha256,.\usb-cold-wallet.img.xz.sha256
Get-Item -LiteralPath .\usb-cold-wallet.img | Select-Object Name,Length
Get-FileHash -Algorithm SHA256 -LiteralPath .\usb-cold-wallet.img,.\usb-cold-wallet.img.xz
```

預期 raw SHA-256 等於兩份 clean build 清單、raw checksum 與 artifact manifest，kernel SHA-256 在兩份 runner 清單間一致，XZ 的 SHA-256 等於其清單及 manifest。核對 GitHub run、attempt、兩個 runner、驗證 job 與 artifact ID。`event_head_sha` 對照事件來源，`commit_sha` 對照實際 checkout，PR merge ref 下兩者可能不同。只取驗證發布 job 的 artifact。需要驗證解壓位元或做整碟唯讀讀回時，依 [M0 詳細規格](TWO_USB_M0_ACCEPTANCE.md) 在可信 Linux 執行，避免 Windows 自動掛載後才做第一次讀回。

### 人工執行與回傳

| 案例／依據 | 你要親手操作 | 預期結果與回傳 |
| --- | --- | --- |
| `USB_A_READBACK`／#1 #66 | 核對上一步的裝置資訊並確認可清空後，用可信 GUI 將已驗證 raw `.img` 刷入 USB-A，使用寫後驗證。第一次開機前獨立讀回映像長度，核對 GPT（ESP、`COLD_VAULT`）及匹配來源的 Disk GUID 和 PARTUUID。M0 只適用 #76 之前的兩分割區映像（#7 或 `5e49d4c`）；#76 之後的映像本身已含 `TX_TRANSFER` 分割區，再插 USB-B 會出現兩個候選，選單 5 依設計拒絕掛載。 | 回傳裝置型號、容量、讀回長度、雜湊、GPT 唯讀輸出與 GUI 驗證結果。若 Windows 提示格式化 USB-A，一律取消。 |
| `USB_B_FAT32_ID`／#66 | 手動準備另一支測試 USB-B，FAT32 且標籤 `TX_TRANSFER`。使用上面的 PowerShell 驗證。 | 回傳兩支 USB 的去識別化父磁碟對照、檔案系統與標籤。 |
| `UEFI_PHYSICAL_BOOT`、`OFFLINE_ISOLATION`／#43 #66 | 冷端實體關機後從一次性 UEFI Boot Menu 選 USB-A。先不插 B，核對啟動和 runtime 稽核，再插 B，用 appliance 選單 **5**。 | 回傳經遮蔽的啟動畫面、耗時、UEFI 機型／韌體／Secure Boot 狀態與稽核逐項結果。預期 RAM root、`/proc/net` 不存在、無 swap、無非預期可寫持久掛載，Vault 來源正確且 `rw,noexec,nodev,nosuid,sync`。選單 5 顯示 `TX_TRANSFER mounted.`。看到 LOCKDOWN 或 FAIL 就停止。 |
| `VAULT_POLICY_REBOOT`／#5 #66 | 以選單 **1** 建立一次性測試 Vault、**2** 核對公開帳戶、**7** 建 policy。紙本保管 policy SHA-256 與還原資料。用 **6** 關機再冷開機，驗證持久性及錯密碼拒絕。 | 回傳重啟前後公開帳戶比對、錯誤密碼被拒及 policy 錨點核對結果。 |
| `SEPOLIA_REQUEST`、`SEPOLIA_COLD_REVIEW`、`SEPOLIA_SIGN`、`SEPOLIA_IMPORT_VERIFY`／#24 #66 | Windows 以經驗證 Companion 匯入公開帳戶，建立 Sepolia type-2 原生轉帳並下載 bounded JSON 到 B。保持 Companion 執行。冷端由 **3** 選取請求，核對獨立來源的收款人、金額及 policy 雜湊，以畫面核對帳戶、chain ID `11155111`、nonce、wei、gas 與費用上限，再由本人確認簽署。安全取出 B，回 Windows 匯入。 | 顯示已驗證的簽署回覆，recovered signer 與原帳戶相同，原始交易欄位一致。回傳請求摘要、各階段結果及經遮蔽的驗證頁面。 |
| `BTC_REQUEST`、`BTC_COLD_REVIEW`、`BTC_SIGN`、`BTC_IMPORT_VERIFY`／#24 #66 | 用專用 testnet UTXO 建立 BIP84 P2WPKH PSBT v0，將 Companion 匯出的 bounded BTC JSON 放到 B。冷端由 **4** 核對 UTXO、完整收款人、sats、找零地址／索引、費用及 policy 錨點。由本人確認簽署，回原 Windows session 匯入結果。 | 預期 Companion 驗簽、核對 PSBT 語意與原請求並 finalize。回傳網路、請求摘要、review 結果、驗簽與 finalize 結果。 |
| `BTC_BROADCAST`、`SEPOLIA_BROADCAST`／#24 #43 | M0 可分開記為選做。若後續明確批准、已驗證且有測試資產，由本人在 Companion 點選廣播並查詢狀態。 | 僅實際送出才附公開 TXID／hash 與鏈上回執。未送出填 NOT TESTED。不確定結果先查詢，保持無自動重送。 |

Windows 建議先按發行文件核對與所選來源相容的 EXE SHA-256，然後從 EXE 所在目錄列出支援參數及啟動。需要特定節點時依 [Companion 文件](ONLINE_COMPANION.md) 選擇測試網，回傳的命令應遮蔽憑證。

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath .\USBColdCompanion.exe
.\USBColdCompanion.exe --help
.\USBColdCompanion.exe
```

預期瀏覽器由 localhost 開啟 watch-only Companion，登入或密鑰輸入不屬線上流程。每次測試先確認 BTC 探索端點與測試幣網路相符。若遇舊版 UI、無法匯入 JSON 或缺少相容的 Companion，停止並記錄版本與案例為 BLOCKED。

## 2. Single-USB（#37／#43，待整合版本）

先記錄 #66 結果。#75 審查仍要求獨立可信冷端 replay anchor、線上 journal 回滾或可信對帳、Windows parent/GPT/replug 識別、模糊廣播結果驗證及實體 FAT32 持久性。#76 已合入主線，冷端 runtime 提供媒體邊界；#79 的 framebuffer 測試仍需接上實際請求／解鎖／簽署／匯出。#80 的唯讀腳本與 journal 可待合入或於明確的受測 checkout 採用。以下硬體列中，只有 S-01 的冷端開機稽核部分已於 2026-11-27 實機執行（見上表），Windows 唯讀預檢與其餘各列都尚未執行。參見 [#75 anchor review](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/75#discussion_r4664166518)、[#75 Windows review](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/75#discussion_r4664167449)。

| 案例／前置 | 你要親手操作 | 預期結果與回傳 |
| --- | --- | --- |
| S-01 映像與 GPT，需整合候選和可清空測試 USB | 核對精確 SHA 與 raw 映像，依 M0 人工方式刷寫及讀回，執行 Windows 唯讀預檢並比對冷端稽核。 | 同一父磁碟，按該版 layout 核對 Disk GUID、三個 PARTUUID、類型、容量和區段。#76 預期 ESP 64 MiB、Vault 64 MiB、FAT32 交換區 512 MiB。僅交換區有日常 Windows 存取代號。記錄前後磁碟與分割區的映射。 |
| S-02 Windows，需配對 EXE 和乾淨標準使用者環境 | 驗證 EXE 雜湊，從該版規定的交換區路徑由標準 Windows 帳戶啟動。匯入公開帳戶，分別建立 BTC v0、Sepolia type-2 v2 請求。 | 正確唯一識別物理 USB；保留原始綁定與 pending 資料。回傳 OS build、EXE SHA、去識別化 Windows 映射和請求 ID／摘要。 |
| S-03 冷端 framebuffer，需整合 #75/#76/#79 | 從 Windows 重開機進 USB；用實體螢幕、鍵盤和已驗證 policy／anchor，檢查完整地址、金額、費用、鏈別及 BTC 找零或 EVM nonce。依受測 GUI 捲至各頁末端、按 Enter 核對，再按獨立確認鍵（#79 原型為 C）。另測 Esc 及鍵盤拔除。 | 進入實際 GUI，逐頁確認和簽署授權有明確分界。取消、輸入裝置離開或稽核失敗時不出現新簽署檔。回傳去識別化畫面、確認前後狀態及時間。 |
| S-04 回 Windows，需同一錢包／請求及可信狀態 | 安全關機，重開 Windows。安全退出後重插並重新盤點，即使代號變動也不手動繞過檢查。用 Companion 回復原待簽狀態、匯入並驗證兩條鏈的回覆。 | 磁碟身分重新驗證，舊或錯置回覆被拒，原交易內容與簽署結果一致，無自動簽署或廣播。回傳兩次 reboot 耗時、重插前後對照、Request ID／摘要與驗證結果。 |

## 3. 發行前實體負向測試（#24／#43，Vault 另見 #5）

只在有備份、可丟棄的測試 USB、已核准測試 fixture 與測試錢包上執行。一個變因一個案例，保存測前與測後去識別化狀態。M0 當場先做錯誤 USB 與明顯無效請求的拒絕檢查，其他觸及持久化／掉電的案例依 [詳細矩陣與門檻](TWO_USB_M0_ACCEPTANCE.md) 判定必做項，阻礙須保留。只有按既定範圍通過的證據才能更新 Issues。

| 案例／前置 | 人工動作 | 預期結果／回傳 |
| --- | --- | --- |
| N-01 錯 USB／重複 GUID／媒體替換（#43 #66 #37） | 用獨立備用測試媒體逐項更換，測無 USB-B、同標籤、重複 GUID、錯分割區／父磁碟、重插與替換。 | 拒絕模糊來源或 runtime 身分改變，無簽章。附識別、順序與拒絕結果。 |
| N-02 不可信交易（#24 #66） | 逐項使用已審查 fixture 測試截斷、錯鏈／帳戶、收款人／金額／費用變更及錯 policy 錨點。 | 顯示拒絕，無新簽章。回傳 fixture ID、預期拒絕點、實際結果。 |
| N-03 Replay／Rollback（#24 #37） | 在獨立可信 anchor 與回復流程到位後，分別重匯已處理請求／回覆，測整組舊測試狀態回復及重啟。 | 拒絕重新處理、簽署和廣播。回傳重啟前後判定。缺可信 anchor 時整組回滾填 BLOCKED。 |
| N-04 拔除／電源中斷（#43 #37） | 用可丟棄 USB，在受控測試中分別中斷請求、回覆、Vault 發布，重插或重啟後重驗。 | 半寫檔不被採用，舊完整資料保持可驗。遇不確定狀態時停止安全敏感動作。附中斷點、結果與桌面／冷端觀察。 |
| N-05 Vault 損毀與恢復（#5 #43） | 在離線備用媒體用受控損毀 fixture 驗證拒絕解鎖，依 [恢復清單](RECOVERY_REHEARSAL_CHECKLIST.md) 從紙本復原到新空 Vault，再重開機。 | 回傳損毀拒絕、未覆寫、還原前後 BTC／Sepolia 公開帳戶一致性與持久性結果。 |
| N-06 隔離與殘留（#24 #43） | 記錄冷端 RAM root、網路、swap、可寫掛載，按安全關機後，在可信檢查環境對照測前與測後的測試媒體檔案清單、類型和預期持久化路徑。另於第二台不同 UEFI 實機重驗。 | 交換區僅見預期檔，內建磁碟無預期外可寫掛載，證據無 secret 或非預期明文檔。回傳範圍、稽核及差異摘要。這個觀察範圍無法證明 RAM 或控制器殘留已清除。 |

Secure Boot 鏈、撤銷及不可信啟動拒絕由 [#60](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/60) 追蹤，主網由 [#24](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/24)／[#48](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/48) 追蹤，實體 QR 攝影機由 [#56](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/issues/56) 追蹤。這三項是後續階段，M0 不等待。Secure Boot 設定變更由操作者自行評估與記錄。

## 4. 回傳給 Codex 的資料

操作者負責刷寫／格式化、按 UEFI 選單、冷端離線、插拔、紙本復原、核對與確認簽署，以及另行授權的廣播。Codex 可查 CI／雜湊、核對你提供的資料、按案例判定並更新既有 Issues。原始證據留在線上機的本機目錄，公開 Issue 只貼去識別化摘要。保留原始檔開放範圍的控制權。

每一案回傳同樣格式，M0 同時依 [詳細規格的 JSON 欄位](TWO_USB_M0_ACCEPTANCE.md#c-evidence-schema-and-strict-decision-rules) 記錄。可用 `Get-FileHash -Algorithm SHA256 -LiteralPath .\evidence\boot-audit.txt` 計算已遮蔽證據的雜湊。

```text
案例 ID / Issue =
狀態 = NOT TESTED
操作者 / UTC 時間 / 環境（實機、QEMU 或自動化） =
主機與 UEFI / USB 型號容量 / 去識別化磁碟與分割區對照 =
實際 checkout SHA / image SHA-256 / CI URL / artifact ID =
實際指令或操作 / exit code（如適用） =
預期結果 / 實際結果 / 失敗點或缺少的前置 =
Request ID 或摘要 / 已實際廣播的公開交易 ID（如適用） =
證據檔名與 SHA-256 =
```

禁止附上助記詞、私鑰、密碼、Vault 原始檔、完整交易檔或簽章檔、原始設備序號、RPC 憑證及紙本驗證資料。#66 記錄 M0，#43 記錄實體發行門檻，#24 記錄端到端與安全覆蓋，#37 記錄單 USB、#5 記錄實體恢復，#1 記錄選用映像來源，#60 記錄可信開機。只有經確認的案例才勾選，避免在各 Issue 複製整份案例。
