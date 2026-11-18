# USB 製作與使用指南

> **測試網研究用途。未經安全審計，不要存放真實資產。**

## 需要什麼

- **USB-A / Cold Wallet USB**：建議 8 GB 以上。會被完整刷寫成開機映像。
- **USB-B / Transaction Transfer USB**：另一支 USB，只交換 unsigned / signed transaction；FAT32，Volume Label 設為 `TX_TRANSFER`。
- **x86_64 UEFI 電腦**：作為真正的離線簽署電腦。
- **另一台連網電腦**：watch-only、建立 unsigned transaction、廣播 signed transaction。
- 紙本或金屬 recovery backup。

USB-A 映像有兩個 GPT partition：

1. `USBCOLD_EFI`：UEFI bootloader + kernel/initramfs。
2. `COLD_VAULT`：只保存 AES-256-GCM 加密後的 `wallet.vault`。

Linux root filesystem 位於 RAM，不使用持久 root partition。

## 1. 建置 image

完整建置說明見 [BUILD.md](BUILD.md)。

```bash
make prepare-sources
make image
make verify
```

成功後：

```
build/output/images/usb-cold-wallet.img
build/output/images/usb-cold-wallet.img.sha256
```

刷寫前再次驗證：

```bash
cd build/output/images
sha256sum -c usb-cold-wallet.img.sha256
```

## 2. 刷寫 USB-A

這一步會清除目標 USB 的所有資料。建議使用能顯示來源 image 與目標 removable device 的圖形工具，例如 Raspberry Pi Imager / balenaEtcher，避免手動選錯磁碟。

目前 repository **不自動執行 destructive flash command**。

刷完後，不要在日常連網電腦上建立或解鎖 wallet。

## 3. 準備 USB-B

將另一支 USB 格式化 FAT32，Volume Label 設為：

```
TX_TRANSFER
```

只允許以下類型資料出現在 USB-B：

- 公開 watch-only 資訊
- Bitcoin testnet unsigned PSBT
- Sepolia unsigned transaction JSON
- signed PSBT / signed raw transaction

**禁止放入：**

- BIP39 mnemonic
- BIP39 passphrase
- `wallet.vault`
- private key / WIF
- Debug dump 或記憶體內容

## 4. Boot offline signer

1. 電腦完全關機。
2. 拔除 Ethernet。
3. 在 firmware/UEFI 停用 Wi-Fi、Bluetooth、PXE/network boot（硬體允許時）。
4. 插入 USB-A。
5. 從 UEFI boot menu 啟動 USB-A。

Production kernel config 明確設定：

```
# CONFIG_NET is not set
```

因此不是「Wi-Fi 關掉」而已，而是 Linux networking subsystem 不會被編入 kernel。

系統啟動後會直接進入 `usb-wallet-console`，不提供一般 getty/login 作為正常操作介面。

Console 會顯示：

- network stack 檢查
- swap 檢查
- `COLD_VAULT` 是否已 mount

若任何必要檢查顯示 `FAIL`，不要建立或解鎖 wallet。

## 5. 第一次建立測試錢包

選：

```
1) Create encrypted TESTNET wallet
```

程式會：

1. 從 offline OS CSPRNG 取得 entropy。
2. 產生 24-word BIP39 mnemonic。
3. 要求你手抄 recovery words。
4. 要求確認最後一個 word。
5. 用 scrypt 衍生 vault encryption key。
6. 使用 AES-256-GCM 加密 mnemonic。
7. 只把 encrypted `wallet.vault` 寫到 `COLD_VAULT`。

**紙本 backup 必須獨立存在。USB-A 壞掉或重新刷 image 時，COLD_VAULT 可能遺失。**

## 6. 匯出公開資訊

Console 選：

```
2) Show public BTC testnet + Sepolia addresses
```

這只會顯示：

- Bitcoin testnet BIP84 receive addresses
- Bitcoin account tpub
- Sepolia address

這些資料可以轉移到連網電腦。不要轉移 vault。

## 7. Bitcoin testnet 簽署

在線上 watch-only wallet 建立 PSBT，存為例如：

```
unsigned.psbt
```

放進 USB-B，插到 offline signer，Console 選：

```
4) Sign Bitcoin testnet PSBT
```

需要**獨立輸入**：

- 預期 recipient testnet address
- 預期 satoshi amount
- 最大可接受 fee
- 預期 change index（若有 change）

程式會拒絕不屬於已知 BIP84 wallet input、未知 output、fee 超標或不相符的 recipient/amount。

## 8. Sepolia 簽署

在 online computer 建立 type-2 EIP-1559 JSON，放入 USB-B，Console 選：

```
3) Sign Sepolia native ETH transaction
```

需要獨立輸入 recipient 與 value in wei。

目前會拒絕：

- 非 Sepolia chainId
- legacy transaction
- contract calldata
- ERC-20
- access list
- 非 21,000 gas native transfer
- recipient/value 不符

## 9. 結束 session

簽名完成後：

1. 將 signed transaction 留在 USB-B。
2. Console 選 Power off。
3. 等電腦完全關機後再移除 USB-A。
4. USB-B 回到 online computer 廣播。

## 重要限制

- 普通 USB 沒有 Secure Element，解鎖後 private key 會存在 offline PC RAM。
- 現階段沒有 Secure Boot。
- 目前 image build 尚未完成獨立 bit-for-bit reproducibility 驗證。
- USB-B 是不可信輸入，parser 仍需 fuzzing。
- Recovery workflow 仍在 Issue #5 強化中。
- 主網與 token/contract signing 都尚未開放。
