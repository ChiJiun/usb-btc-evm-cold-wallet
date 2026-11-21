# Windows Portable Companion（Issue #37）

本 Windows x64 測試網版本可在沒有預先安裝 Python、Node
或管理員權限的環境直接執行單檔 USBColdCompanion.exe。
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
靜態頁面、未授權 API 拒絕，並產生 SHA-256 供驗證。
完整單 USB 自動偵測交換分割區、Windows/UEFI 跨開機、
雙重開機的交易收送與真實 BTC testnet/Sepolia 廣播尚未驗收；
目前使用者仍需下載及匯入 JSON 檔。此包不得直接用於真實資產。

後續硬體驗收見 #43；主網與 Release Gate 分別見 #48、#47。
