# GitHub Release provenance 與獨立驗證（#57）

目前專案沒有經 #24／#43 實體安全驗收核准的 production-safe Release。`.github/workflows/release.yml` 已工程化正式供應鏈流程，但 `publish` 預設為 `false`，且 #24 或 #43 仍為 open 時 publish job 會 fail closed。

## Release workflow 信任邊界

Release workflow 必須從受保護的 `refs/heads/main` 執行 `workflow_dispatch`；workflow definition 的 commit SHA（`GITHUB_SHA`）與待發布 source commit（input `source_sha`）分開處理。Validate job 先要求 `GITHUB_REF == refs/heads/main`，再從 trusted workflow commit checkout verifier；之後才驗證 release tag 是 signed annotated tag、tag 指向 exact source SHA，且 GitHub GraphQL `Tag.signature.signer.login` 是允許的 release signer。Validate 會固定 annotated tag object SHA，供 verify / publish 再次比對。

因此 SLSA provenance 的 workflow/source identity 綁到 **trusted main workflow SHA**，而 release source SHA/tag 則由 signed tag + release metadata 獨立綁定。這避免把不可信 tag commit 同時當成 privileged workflow definition。PR 事件不會執行此 workflow。

權限分離如下：

- validate / build / gate：`contents: read`；build 沒有 OIDC、attestation 或 release write。
- verify：`contents: read` + `attestations: read`，只能讀取並驗證既有 provenance，沒有 write/OIDC。
- attest：只有此 job 取得 `id-token: write`、`attestations: write`，另提供目前 `actions/attest` 寫入 artifact metadata 所需的 `artifact-metadata: write`；沒有 `contents: write`。
- publish：只有 gate 成功且使用者明確設定 `publish=true` 才取得 `contents: write`；另以 `issues: read` 確認 #24 與 #43 均已關閉。既有 Release 一律拒絕覆寫。

所有 `uses:` 都釘選完整 40-hex action commit。Buildroot 版本、來源 SHA-256、簽章與 release key 由 `infra/buildroot.env` 固定；target wheelhouse 由 `infra/wheelhouse-requirements.txt` 與 `infra/wheelhouse.sha256` 固定；Node release runtime 固定為 `24.22.3` 並以 lockfile 執行 `npm ci`。SBOM action 固定 commit，Syft 固定版本。Release host 的 APT 現改用固定 Ubuntu Snapshot ID，並把每個安裝套件解析成 `package=version` 後驗證實際 dpkg version；`build-host-packages.txt` 仍保留作證據。GitHub-hosted `ubuntu-24.04` runner image 與 host kernel 仍是 GitHub 管理的可變輸入，因此目前只能稱為 **APT snapshot-pinned、runner-recorded**，不能宣稱 hermetic build。

## 建置、attestation 與 publish 順序

流程固定為：

1. signed tag → exact source SHA 驗證。
2. 同一來源做兩次 clean Buildroot image build，`scripts/check_reproducible.sh` 比對 raw `usb-cold-wallet.img` SHA-256。
3. 對兩次 raw image 的 SHA-256 再做顯式相等檢查，將共同 digest 寫入 `release-metadata.json`；使用該 Buildroot 版本所固定的 host `xz`，以 `-6 --threads=1 --check=crc64 --no-sparse` 壓縮兩次並 byte-for-byte 比對。
4. 由最後 root filesystem 產生 SPDX JSON SBOM；保存 `build-host-packages.txt`、`release-metadata.json` 與 `SHA256SUMS`。manifest 精確涵蓋最後 image、SBOM、metadata、host dependency evidence。
5. 將這批 candidate bytes 上傳成同一次 workflow 的 immutable Actions artifact；attest job 對 image、SBOM、metadata、host dependency evidence 建立同一 source identity 的 SLSA Build Provenance，並另外對 `SHA256SUMS` 建立 provenance、對 image 建立 SBOM attestation。
6. verify job 重新下載同一 candidate artifact，驗證 trusted workflow SHA、authorized signed tag、固定 tag object SHA、source SHA、每個發布檔案的 subject digest、manifest、SPDX identity 與 metadata。
7. required gate 把 build / attest / verify 的 `skipped`、`cancelled`、`failure` 全部視為失敗。
8. publish job 只下載已通過驗證的 artifact，再做 checksum；緊接著重新取得 tag ref、重新驗證 authorized signer、source SHA 與原先固定的 tag object SHA，任何刪除／重指向／替換都 fail closed，然後才呼叫 `gh release create`。這是 TOCTOU 的程式層縮窗措施；真正防止所有 tag replacement 仍依賴 Active tag ruleset。

## 發行等級與可宣稱範圍

- **測試映像 / candidate artifact**：只存在 GitHub Actions artifact，可供 CI、QEMU 或實體 testnet 驗收；不得建立公開 Release，也不得宣稱 production-safe。
- **Beta (`vX.Y.Z-beta.N`)**：至少 #24 與 #43 的該版本實體 USB/testnet gate 已完成，仍標示 testnet-only、實驗性、未正式安全稽核。
- **RC (`vX.Y.Z-rc.N`)**：Beta gate 全部保留，另完成預定 v1.0 功能矩陣、回歸與 release checklist；未通過主網安全 gate 仍不得開放真實資產。
- **v1.0**：除了 #24/#43，還必須完成 #48 的 BTC/Ethereum mainnet 隔離與最小金額 E2E、獨立安全審查及明確 release decision。CI、QEMU、attestation 或關閉 Issue 本身都不能替代這些證據。

目前 #24、#43 都仍為 open，因此此 workflow 只能產生 candidate evidence，`publish=true` 仍必須 fail closed。所有公開 Beta/RC 都至少要求 #24/#43 closed；沒有 prerelease suffix 的 stable tag 另外要求 #48 closed，避免在主網驗收完成前發布 v1.0/stable 資產。
## 獨立驗證已發布 Release

前置條件：

- 安裝支援 `gh release verify`、`gh release verify-asset`、`gh attestation verify` 的近期 GitHub CLI。
- 從獨立可信管道取得完整 40 字元 source commit SHA；不可只從同一份 Release Notes 複製。
- GitHub Release 已啟用 Immutable Releases，tag 是 GitHub 顯示 `Verified` 的 signed annotated tag。

~~~sh
python3 scripts/verify_release_assets.py \
  --tag v0.1.0-beta.1 \
  --commit <independently-verified-40-hex-commit> \
  --asset usb-cold-wallet-v0.1.0-beta.1.img.xz
~~~

驗證器固定 repository，不接受 URL；它從 GitHub Release 下載 `SHA256SUMS`、指定 image、SPDX SBOM、release metadata 與 host dependency evidence，要求 manifest 精確覆蓋全部 payload 並逐一重算 SHA-256，再對每個檔案要求 Immutable Release asset integrity 與 `.github/workflows/release.yml` 對相同 tag/source SHA/subject digest 的 SLSA Build Provenance。任一缺失或不一致均 nonzero exit。

`SHA256SUMS` 只能證明 bytes 與 manifest 一致；其本身仍需 GitHub 的 Release integrity / asset verification。signed tag、Immutable Release、Build Provenance 各自提供不同保證，不能互相替代。

## Repository admin 必須人工設定

此 workflow **不會也不能假裝已替 repository 開啟下列管理設定**：

1. **Immutable Releases**：Repository → Settings → General → Releases 啟用 immutable releases。正式發布後執行 `gh release verify <tag> -R ChiJiun/usb-btc-evm-cold-wallet`。
2. **Release tag ruleset（目前 BLOCKER）**：建立 Active tag ruleset，target 至少涵蓋 `refs/tags/v*`，啟用 **Restrict creations / Restrict updates / Restrict deletions**；bypass 僅允許實際 release maintainer。完成後以 Repository → Settings → Rulesets 及 `GET /repos/ChiJiun/usb-btc-evm-cold-wallet/rulesets` 確認 target=tag、enforcement=active，再讀 ruleset detail 確認三個限制都存在。
3. **main / workflow trust anchor（目前 BLOCKER）**：現有 `main-protection` 必須至少要求有效 PR review、必要 CI，且 release workflow / verifier 的修改需 Code Owner 或等效獨立 approval；不得保留 0 approval / 0 required check 作為正式 release trust anchor。完成後讀 ruleset detail 確認 `refs/heads/main`、Active、required review/status checks。
4. **Authorized signer**：workflow/verifier 目前只接受 GitHub signer login `ChiJiun`，且要求 signature `isValid=true`、state=`VALID`、不是 GitHub 代簽。若未來增加 release maintainer，必須先經受保護 main PR 修改 allowlist。
5. **Protected release environment（建議的第二道人工 gate）**：建立 `release` environment 並設 required reviewer / deployment protection，再把 publish job 綁定該 environment。未完成前不得把 environment protection 當成已存在。

## 第三方 clean rebuild

同一 GitHub runner 內兩次 clean build 只證明該 CI 環境內可重現。第三方驗證者應在另一台乾淨 x86_64 Linux 主機：

~~~sh
git checkout --detach <exact-source-sha>
sh scripts/check_host.sh
sh scripts/fetch_sources.sh
sh scripts/check_reproducible.sh
~~~

先比對 `build/reproducibility/run-1.sha256` 與 `run-2.sha256`，再將 raw image SHA 與 release build evidence 比對。若要比對實際下載的 `.img.xz`，必須使用 release metadata 記錄的同版 Buildroot host `xz` 與完全相同參數重新壓縮，再比對 `SHA256SUMS` 中的 digest。第三方結果需另行保存其主機、工具版本、source SHA 與 hashes；CI 自身的雙重 build 不算第三方已驗證。

## 發布限制

#57 的工程實作不依賴實體 USB 才能完成，但 #24／#43 驗收前 workflow 會阻擋 publish，文件與 Release Notes 也不得宣稱 production-safe。關閉 Issue 只是自動 gate 的最低條件；正式發布前仍需由維護者確認 Issue 內確實存在相應實體驗收證據及 admin 設定。

官方驗證命令文件：

- https://cli.github.com/manual/gh_release_verify
- https://cli.github.com/manual/gh_release_verify-asset
- https://cli.github.com/manual/gh_attestation_verify
