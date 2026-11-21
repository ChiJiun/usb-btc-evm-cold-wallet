# GitHub Release 獨立驗證（#57 第一階段）

目前本專案**尚未有經真機與獨立安全審查核准的 Release**。本驗證器可在未來 Release 發布後，由另一台乾淨電腦下載及驗證資產；不能以 CI 成功宣稱可安全存放主網資產。

## 前置條件

- 已安裝近期 GitHub CLI（包含 `gh release verify`、`gh release verify-asset`、`gh attestation verify`）且可存取 GitHub。
- 從**獨立可信管道**取得完整 40 字元來源 commit SHA；不可僅複製同一個 Release Notes 的 SHA 當成獨立信任錨點。
- GitHub 已驗證的簽章 annotated tag、Immutable Release、Release Asset Attestation，以及由 `.github/workflows/release.yml` 簽署的 Build Provenance；缺一即拒絕。
- 發行時應另附可重現 `.img`／`.img.xz` 建置證據、SBOM、依賴來源 hashes、硬體/安全驗收紀錄。本工具**不重新編譯**，亦不證明二進位安全。

於乾淨 checkout 執行（以真實且獨立確認的 SHA 取代佔位字串）：

`python3 scripts/verify_release_assets.py --tag v0.1.0-beta.1 --commit <independently-verified-40-hex-commit> --asset usb-cold-wallet-v0.1.0-beta.1.img.xz`

成功回報下載資產的 SHA-256；以下情況非 0 退出：無法核驗簽章 tag、SHA/tag 不符、Draft、缺失/驗證失敗的 Immutable Release、checksum 異常、資產被換、Build Provenance 的來源 ref/commit/signer-workflow 或 digest 不符。

驗證工具限定固定 repository、受限版本 tag、對應的映像檔名；下載到新的暫存目錄，不執行 Release 中的程式碼。`SHA256SUMS` 本身也必須通過 Release Asset Attestation；單純對比攻擊者可一併替換的 checksum 與 image 無法確保真偽。

## 尚未完成的發行工項

本 PR 交付**獨立下載驗證器與負向測試**。#57 尚須在 #7 合併後接續實作：受控簽章 tag 的 release workflow、兩次乾淨 image build、Node/Python/Buildroot 依賴鎖定與 SBOM、成品 attestation、build/publish 權限分離、必要 job skipped fail-closed、第三方獨立重建與 Release 真正驗證。#43/#24 硬體驗收仍為正式發行的必要條件。

GitHub CLI 官方文件：[Release 驗證](https://cli.github.com/manual/gh_release_verify)、[Asset 驗證](https://cli.github.com/manual/gh_release_verify-asset)、[Build Attestation](https://cli.github.com/manual/gh_attestation_verify)。
