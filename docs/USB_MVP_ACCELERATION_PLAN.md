# USB MVP 加速計畫

目標：**最短時間取得真實 x86_64 UEFI + 實體 USB 的可重現 testnet 簽署證據**。第一階段不追求單 USB、QR、ERC-20、MetaMask、WalletConnect、Secure Boot 或主網。

## 目前已完成、不要重做

main 已具備：
- Bitcoin testnet：嚴格 PSBT v0 / BIP84 P2WPKH 解析、wallet ownership、recipient/change/fee 驗證、簽章與 finalized transaction roundtrip。
- Ethereum Sepolia：EIP-1559 type-2 native transfer，chainId/recipient/value/gas/fee/data/accessList fail-closed 驗證，簽後 raw transaction decode/recover。
- 加密 Vault：scrypt + AES-256-GCM、create-only/atomic write。
- Offline Policy：錢包綁定、獨立 ciphertext SHA-256 anchor、交易上限與 verified address。
- Offline Review GUI + SignerSession：raw payload 重算、review digest、逐筆批准、idle/session lock。
- USB envelope / request-response binding、FAT32 原子寫入與 mounted-VFAT CI。
- Online Companion 核心：watch-only BTC/Sepolia、建立 request、驗證 signed result、explicit broadcast。
- Generic UR transport；typed ERC-4527/crypto-psbt 由 PR #63 繼續，不阻擋 USB MVP。

**原則：上述核心不因上游有類似功能而重寫。** 上游程式只用於缺口、獨立 oracle、UI/transport pattern 與測試。

## 第一個實體 USB 里程碑：Two-USB smoke

PR #7 已有 Buildroot x86_64 UEFI image、RAM initramfs、CONFIG_NET=n、COLD_VAULT mount 驗證、runtime audit 與文字 appliance。文字 appliance 已可：
1. 建立 testnet encrypted vault；
2. 顯示 BTC testnet / Sepolia public address；
3. 初始化 encrypted policy 並要求紙本 SHA-256 anchor；
4. 從獨立 TX_TRANSFER USB 讀取 request；
5. 簽 Sepolia native ETH；
6. 簽 Bitcoin testnet PSBT；
7. 將 signed result 寫回 TX_TRANSFER。

目前 runtime **要求 TX_TRANSFER 與 boot/vault USB 位於不同實體 block parent**。因此第一次實體驗證固定使用：

- USB-A：Live OS + COLD_VAULT
- USB-B：FAT32，label = TX_TRANSFER

不要先改成 single-USB。#37 在 two-USB 證據完成後再做。

### M0 驗收

1. PR #7 最終 HEAD 的一般 CI + full Live USB image verification 成功。
2. 將該 exact image 寫入 USB-A；USB-B 建 FAT32 TX_TRANSFER。
3. 真實 x86_64 UEFI boot，確認 appliance 顯示 startup/runtime audit PASS。
4. 使用公開測試 seed / 專用 testnet wallet 建立或 restore vault，初始化 policy。
5. USB-B 放入一筆固定 Sepolia native request；appliance 離線 review/sign；signed JSON 正確寫回。
6. USB-B 放入一筆固定 BTC testnet PSBT；appliance 離線 review/sign；signed JSON 正確寫回。
7. 回線上端以現有 Companion/CLI 驗證 signed payload；如有測試幣再 explicit broadcast。
8. 保存 image SHA、PR HEAD、USB/UEFI 型號、audit 結果、txid（若 broadcast）及失敗紀錄。

**M0 不要求 Tk GUI、QR、單 USB、ERC-20、EIP-712、Secure Boot、mainnet。**

## 第二階段：產品化 USB E2E

M0 通過後才依序：
1. PR #64 Online Companion UX；
2. 將 main 的 Offline Tk GUI 安裝進 Buildroot（目前 PR #7 defconfig 未配置 Tk）；
3. GUI 與 appliance 使用同一 review/policy/backend；
4. Windows Portable → USB-B → cold GUI → USB-B → Windows explicit broadcast；
5. 再做 #37 single-USB cross-boot。

這樣可以把「USB 是否真的能開機並安全簽署」與「最終 UX 是否完整」分開，不讓 GUI packaging 阻擋硬體證據。

## 上游程式碼重用策略

### A. 可直接移植（授權已確認）

| 上游 | 固定來源 | 用途 | 本案對應 |
| --- | --- | --- | --- |
| Specter-DIY (MIT) | `bec1ab108d6559a35b9cf8b1ea41da1f5731918a` | SD/QR transaction exchange、PSBT/descriptor workflow、crypto-psbt encoder pattern | #2/#5/#18/#19/#43 |
| AirGap Coin Lib (MIT) | `50c08a4057b0f68b8d223ea4a5ab12853c3f23ba` | ERC-20 transaction semantics、offline/online split、serializer model | #3/#17/#21 |
| AirGap Wallet/Vault (MIT) | current reviewed files | transaction detail / online-offline UX | #17/#19 |
| BlueWallet (MIT) | `66987706630895adbff08099778e4d33e26bd2f7` | watch-only + PSBT import/verify/finalize UX | #2/#17 |
| Blockchain Commons bc-ur-ts (BSD-2-Clause-Patent) | `38d9f35160b171220b4fc5ddab9cdc3c1ea2ae35` | UR multipart/fountain/bytewords | #18/#56 |

移植要求：最小必要 diff、保留 copyright/license、記錄 upstream commit、不要把上游測試當成本案已通過的證據。

### B. 只參考，不直接複製

| 上游 | 原因 | 用途 |
| --- | --- | --- |
| SignerOS | 已核實 GUI 子目錄 MIT，但 `scripts/`、`buildroot-external/` 尚未找到明確涵蓋授權 | Buildroot/UEFI/QEMU/Secure Boot 設計與測試矩陣 |
| Trezor firmware core | 相關 EIP-712/firmware 多為 GPLv3 | 規格、安全顯示、測試向量與攻擊案例 |
| Reown/WalletConnect | 目前 Community License | API/UX 研究，採用前另做授權審查 |

## 直接可搬但目前不值得搬的部分

- **BTC signer core**：本案已比一般 UI wallet 更 fail-closed；不換成 Specter/AirGap signer。
- **Vault/Policy crypto**：已有 scrypt/AES-GCM、atomic write、anchor；不換格式。
- **EVM native signer**：目前限制清楚；不因 ERC-20 擴充重寫。
- **request/response envelope**：已有 digest/account/network binding；不換成 AirGap serializer。
- **generic UR transport**：已有官方 Blockchain Commons dependency；PR #63 只補 typed registry。
- **Online RPC backend**：已完成 BTC/Sepolia 核心；PR #64 聚焦 UX/精確整數/狀態，不換框架。

## 多 Agent 最短關鍵路徑

### Agent A — P0
只處理 PR #7：不得加新功能。full image verification → review → merge/產生 exact image。

### Agent B — P0
準備 M0 固定 public fixtures、USB-B request 與驗證腳本；BTC/Sepolia 各一筆。

### Agent C — P1
PR #64 review/fix；不等待 M0。

### Agent D — P1
準備 Buildroot Tk packaging 的最小 PR；M0 後接續，不改 signer backend。

### Agent E — P2
PR #63/#65；不得讓 QR/ERC-20/EIP-712 阻擋 M0/M1。

## 明確延期

第一次 USB 硬體證據前不做：
- #22 MetaMask
- #23 WalletConnect
- #37 single-USB
- #48 mainnet
- #56 physical QR camera
- #57 release supply-chain completion
- #60 Secure Boot productization
- ERC-20/EIP-712 signing enablement

這些 Issue 保持 open，但標記為不阻擋 Two-USB testnet MVP。

## 預估

若 PR #7 full image verification 成功且手邊有兩支 USB 與一台 x86_64 UEFI 電腦，**第一次實體 boot + 離線簽署 smoke 應以同一天完成為目標**。主要不可平行化時間只剩 image build/verification、刷寫 USB、firmware boot 與人工簽署操作。

完整 Windows Companion + Offline GUI two-USB E2E 則在 M0 後處理；single-USB 再下一階段。
