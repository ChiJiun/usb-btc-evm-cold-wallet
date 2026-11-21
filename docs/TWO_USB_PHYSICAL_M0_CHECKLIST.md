# #66 M0／#43 第一輪 two-USB 實機驗收清單

狀態：**僅適用 testnet；NOT A RELEASE。** 以下為人工待執行步驟，不能以 CI/QEMU 結果代替實機 PASS。第一輪僅要求一台 x86_64 UEFI、USB-A 作 OS+vault、獨立 USB-B 作交換，以及 BTC testnet / Sepolia 離線簽署與線上驗證。第二台硬體、故障注入、GUI、單 USB、Secure Boot 與完整 Release Gate 留給 #43 後續驗收。

## 0. 取得與驗證映像（在線上可信電腦）

- [ ] 在 GitHub Actions 中選擇本 PR **精確 commit** 的 `Live USB image verification` run，確認結論 `success`；其中兩次 **clean reproducibility** 和 `Boot generated USB image using UEFI OVMF/QEMU (TCG)` 皆成功。不可使用其他 commit 的歷史綠燈。
- [ ] 下載該 run 的 `TESTNET-ONLY-NOT-A-RELEASE-usb-cold-wallet-image` artifact（保留 **3 天**；artifact 是 ZIP 包裝，先解壓縮）。應有 `usb-cold-wallet.img`、`usb-cold-wallet.img.sha256`、`TESTNET-ONLY-NOT-A-RELEASE.txt`。
- [ ] 在檔案所在目錄執行 `sha256sum -c usb-cold-wallet.img.sha256`（Linux/macOS 或 Windows WSL），要求 `OK`；另核對同一 run 的 `live-usb-build-hashes` 內 `run-1.sha256`、`run-2.sha256`，兩者的 image/bzImage hash 一致，且 image hash 等於下載的 image。記錄完整 commit、run URL、image SHA-256、大小與 artifact 名稱。
- [ ] GitHub Actions artifact + SHA-256 用於辨識同一 run 的位元組；**不具有獨立簽章或 Release provenance**。失敗、缺檔、來源不一致、run 尚未成功、artifact 已到期：停止，重新執行 full workflow，不使用未驗證本機檔案替代。
- [ ] 保留測試環境來源，所有測試錢包使用已公開、可被任何人控制的測試用 seed；**不得轉入真實資產**。

## 1. 製作兩支 USB（將清除其既有資料）

- [ ] USB-A：獨立空白 USB，建議 8 GB 以上。先確認廠牌、型號、容量、VID/PID、logical sector size（映像要求 512-byte sector）、目標磁碟識別；在可信電腦用 balenaEtcher/Raspberry Pi Imager 選**已驗證**的 `.img`，仔細核對 USB-A 後刷寫並啟用工具的寫後驗證。**不要選內建系統碟或 USB-B**。
- [ ] 確認 USB-A GPT 具有 `USBCOLD_EFI`、`COLD_VAULT` 兩個分割區；不要在連網 Windows 上格式化或修改 `COLD_VAULT`。記錄刷寫時間、校驗結果。寫入後不要把映像的 SHA 當作已驗證整支 USB 內容的證據。
- [ ] USB-B：另一支獨立空白 USB，格式 FAT32（VFAT），volume label **完全等於** `TX_TRANSFER`；記錄 VID/PID、容量、檔案系統與 label。不放入 vault、mnemonic、私鑰或可執行檔。
- [ ] 全程只插一支 `TX_TRANSFER` USB；不得將交換區放在 USB-A，也不得插入第二支複製的 USB-A。

## 2. UEFI 實體開機與安全檢查（離線）

- [ ] 記錄 x86_64 CPU、RAM、主機板/UEFI 版本、Secure Boot 狀態。拔除 Ethernet，停用無線/網路開機。此測試版未支援 Secure Boot，必要時在受控測試機停用並記錄；切勿把這當成已具備 Secure Boot。
- [ ] 冷開機，由 UEFI boot menu **明確選擇 USB-A**。記錄從開機到 appliance console 的時間、相片（不得包含任何恢復詞或密碼）。
- [ ] 核對 `USB BTC + EVM COLD WALLET`、`TESTNET DEVELOPMENT BUILD`；startup audit / runtime audit 的每一條安全檢查均為 `PASS`，沒有 `FAIL` 或 `LOCKDOWN`。驗收重點：RAM-only root、`/proc/net` 不存在（`CONFIG_NET=n`）、無 swap、boot+vault 同一 USB block parent、`COLD_VAULT` 使用 `rw,noexec,nodev,nosuid,sync`、無意外 writable persistent mount。
- [ ] 插上 USB-B，選 console `5) Re-scan TX_TRANSFER USB`，確認成功且來源為獨立實體 USB。任何 FAIL/LOCKDOWN、辨識模糊、設備無法掛載：**停止簽署**，只記錄去識別化故障證據。
- [ ] 先不做拔除/斷電故障注入；這些和第二台 UEFI 屬 #43 後續 release gate。

## 3. Testnet Vault、公開地址與獨立 Policy anchor

- [ ] 使用專用**公開測試 seed**，只配測試網資產。Console `1) Create encrypted TESTNET wallet` 為新建流程；如需重現固定公開 mnemonic，須使用支援的離線 `recover` 指令（見 `docs/RECOVERY_AND_USB_EXCHANGE.md`），且目標 vault 必須不存在。**不要把 mnemonic 放在證據、Issue 或 PR**；公開向量也不抄入驗收紀錄。
- [ ] Console `2) Show public BTC testnet + Sepolia addresses`，核對 BTC BIP84 `tb1...` 與 Sepolia `0x...` 地址和預期公開向量一致；僅將必要 watch-only 資料帶回線上。
- [ ] Console `7) Initialize encrypted offline signing policy`；將印出的完整 policy SHA-256 **獨立抄在紙本**，簽署時只能從這份紙本輸入；policy anchor 不從同一支 USB 讀取當作可信值。記錄「anchor 已獨立核對」，不在公開 evidence 附上政策內容、密碼或 vault。
- [ ] 關機再重啟一次，確認 vault 加密檔持久化、可用正確測試密碼解鎖，錯誤密碼拒絕解鎖。**不要重新刷寫已有 vault 的 USB-A**。

## 4. Sepolia EIP-1559 native offline sign/verify

- [ ] 線上端使用現有 Companion/CLI 的 watch-only 帳戶建立固定一筆 **Sepolia chainId 11155111 / type-2 / native ETH / 21000 gas / empty data / empty accessList** request；在連網端保留原始待簽 request（對照用），以 `pack-request --kind evm-request` 包成完整性檢查的 `.json` envelope，複製到 USB-B。
- [ ] 在可信獨立顯示/紀錄核對 nonce、收款 `0x...`、value (wei)、gas、maxFeePerGas、maxPriorityFeePerGas、最高費與 chainId；不要以 USB-B JSON 自稱的 hash 作為內容認證。
- [ ] USB-B 插回離線機，console `3) Sign Sepolia native ETH transaction`；選取正確的 envelope，手動輸入獨立核對的 recipient、wei、**紙本** policy SHA。核對離線 review 與確認提示後核准，取得 `*.signed.json`。
- [ ] 關機後 USB-B 回線上端，使用現有 Companion 的 **pending request binding** 驗證 signed envelope 與原始 request、account、chain、nonce、recipient、amount、fee 一致，並從 raw signed tx decode/recover 驗證簽章。不得只看 `inspect-transfer` 的格式 PASS 就廣播。
- [ ] 有測試幣且使用者明確確認時才手動 broadcast，記錄 Sepolia TxHash/receipt；沒有測試幣則記錄 `not broadcast (no test funds)`，offline sign/verify 仍可獨立判定。

## 5. BTC testnet BIP84 PSBT v0 offline sign/verify

- [ ] 線上端以錢包公開 BIP84 tpub / receive address 建立**有已知 testnet UTXO 的** PSBT v0（BIP84 P2WPKH）；獨立核對 inputs/UTXO、預期收款 `tb1...`、sats、change address/index、最大 fee (sats)。保留原始 unsigned PSBT 供線上回比對。
- [ ] 使用 `pack-request --kind btc-request --input unsigned.psbt --out unsigned-btc.json` 封裝，拷至 USB-B。
- [ ] Console `4) Sign Bitcoin testnet PSBT`，選正確 `.json`；輸入獨立確認的 recipient、sats、max fee、change index（無找零時空白）、紙本 policy SHA；逐項 review 後核准，取得 `*.signed.json`。
- [ ] 線上 Companion 以原始 pending PSBT 驗證所有 inputs、outputs、找零 script/index、UTXO、fee、簽章與 finalized witnesses。**單獨通過 `inspect-transfer` 不能證明找零屬於預期帳戶。**
- [ ] 有測試 UTXO 且明確確認時才 broadcast，記錄 txid 與狀態；無測試幣則記錄未廣播原因。

## 6. Evidence（僅公開／去識別化）

| 欄位 | 應填內容 |
| --- | --- |
| Git | exact HEAD SHA、main base SHA、PR、run URL、所有適用 CI 結果 |
| Image | artifact 名稱、SHA-256、size、run-1/run-2 image digest 是否一致 |
| 裝置 | UEFI 型號/版本、CPU/RAM、Secure Boot 狀態、USB-A/B 型號/VID/PID/容量/sector size |
| 開機 | 刷寫/驗證耗時、boot 到 LOCKED/console 耗時、PASS/FAIL 摘要 |
| 隔離 | RAM root、無 `/proc/net`、無 swap、vault mount、USB parent/label audit |
| Vault/Policy | test-only create/recover/unlock 成敗、政策 anchor 獨立保存確認（不貼秘密） |
| Sepolia | chainId、測試收款、wei、gas/fees、request binding 與 recover 驗證結果、可選 TxHash |
| BTC | network、testnet 測試收款、sats/fee/change、pending PSBT 比對與簽章驗證、可選 txid |
| 問題 | 步驟、預期／實際結果、去識別化訊息、復原步驟；標示硬體/安全拒絕/操作阻塞 |

**禁止保存或上傳**：seed、BIP39 recovery phrase/passphrase、vault、私鑰、錢包密碼、USB 原始磁區、解鎖畫面、含秘密的完整系統日誌。地址、tpub、交易雜湊雖非私鑰，仍屬交易隱私資料，公開前應去識別化。

### Gate 判定

- **#66 M0 PASS**：同一 exact image 的完整 workflow 成功、USB-A 真實 UEFI boot/audit PASS、USB-B 來源隔離 PASS、公開 testnet vault/policy 操作及 **Sepolia + BTC 離線簽署並線上與原始 request 比對驗證** PASS。未廣播應註明原因。
- **#43 完整 Release Gate 仍 OPEN**：第二台不同 UEFI、故障注入/恢復、真實收款與 broadcast、產品 GUI/UX、安全與 release provenance 等尚須各自實測；M0 PASS 也不等於主網可用或已完成硬體安全審計。
