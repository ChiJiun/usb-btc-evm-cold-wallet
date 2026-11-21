# Windows Portable Companion（Issue #37）

本 Windows x64 測試網版本可在沒有預先安裝 Python、Node
的環境執行單檔 USBColdCompanion.exe；標準使用者與 SmartScreen/AV
實機相容性仍待 #43 驗收。
啟動時只綁定 127.0.0.1，開啟本機瀏覽器；按確認才廣播交易。
Windows 僅處理 watch-only 公開帳戶，嚴禁匯入 Vault、助記詞或私鑰。

## 準備與執行

從成功的 GitHub Actions「Windows portable Companion」下載
Windows-Portable-Companion-unsigned Artifacts，解壓並核對
SHA256SUMS.txt 的 SHA-256 後雙擊執行。
此執行檔尚未簽章或發布為正式 Release，只能用於測試網驗收。

預設使用 https://ethereum-sepolia-rpc.publicnode.com 與
https://blockstream.info/testnet/api。公開 RPC 服務商可看到
查詢地址、來源 IP 並提供可能不可信的鏈上資料；離線端需重新核對。
若要使用自己的節點，可從 PowerShell 執行：

    .\USBColdCompanion.exe --rpc-url https://YOUR-SEPOLIA-RPC --btc-esplora https://YOUR-TESTNET-ESPLORA

不可將密碼或 RPC API key 放在命令列、URL 或交換檔中。
埠號預設由系統配置；可用 --port 指定，--no-browser 不自動開瀏覽器。
關閉視窗會停止本機服務並清除揮發性的待簽 session。

## 測試覆蓋與限制

Windows CI 會真正執行完成封裝的 EXE，檢查本機 HTTP、CSP、
靜態頁面、未授權 API 拒絕；另以本機模擬 Sepolia RPC 驗證
EXE 公開帳戶匯入、交易建構、超過 JavaScript 安全整數上限的 Wei 原樣下載、
離線簽署結果匯入及手動單次廣播（不連接真實鏈），並產生 SHA-256。
這是 HTTP/API 交易流程測試，尚未涵蓋真實瀏覽器點擊、Windows 標準使用者、
SmartScreen/AV 或完整 BTC 交易流程。
完整單 USB 自動偵測交換分割區、Windows/UEFI 跨開機、
雙重開機的交易收送與真實 BTC testnet/Sepolia 廣播尚未驗收；
目前使用者仍需下載及匯入 JSON 檔。此包不得直接用於真實資產。

後續硬體驗收見 #43；主網與 Release Gate 分別見 #48、#47。

## 封裝安全邊界與 CI 驗證

GitHub 的單一 `CI / Required` 現在以可重用工作流程執行**真正 Windows x64
EXE 建置與啟動檢查**：任何程式碼變更若 Windows job 失敗、跳過或取消，
Required 都會失敗。純文件變更預期跳過 Windows job。

Windows 封裝明確排除 `usb_cold_wallet.vault`、`keys`、`btc`、
`evm`、`recovery`、`cli`、`gui`、`review`、
`signer_session`、QR 離線簽章流程等冷端模組；CI 進一步使用
PyInstaller 官方 archive viewer **遞迴檢查實際 EXE archive**，確認
只有 Companion 公開資料與獨立交換格式驗證模組，拒絕打包私鑰衍生或簽署程式。
注意第三方 `eth-account` 等密碼學相依套件仍含一般簽章函式，
並不意味著這個 EXE 有可用的私鑰或 HTTP 遠端簽章 API。

Artifact 同時包含 SHA-256、GitHub commit／run ID、PyInstaller 版本與
實際安裝相依套件清單。**目前尚未實作 Windows 平台完整 hash-locked
依賴、可重現 EXE 或發行者簽章／attestation**，這些仍需在 #47 正式
Release gate 驗證，SHA-256 只能確認位元組一致，不能獨立證明來源。
