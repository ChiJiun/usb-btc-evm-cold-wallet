# GitHub Release provenance 與獨立驗證（#57）

目前專案沒有經 #24／#43 實體安全驗收核准的 production-safe Release。`.github/workflows/release.yml` 已工程化正式供應鏈流程，但 `publish` 預設為 `false`，且 #24 或 #43 仍為 open 時 publish job 會 fail closed。

## Release workflow 信任邊界

Release workflow 只能由 `workflow_dispatch` **直接選擇要發布的 signed annotated version tag ref** 啟動，並輸入同一 tag 與完整 lowercase 40-hex source commit。第一個 job 要求 `GITHUB_REF == refs/tags/<tag>`、`GITHUB_SHA == source_sha`，再使用現有 `scripts/verify_release_assets.py --source-only` 驗證 tag 的 GitHub signature、tag 名稱及其精確 commit 綁定；PR 事件不會執行此 workflow。這也讓 GitHub OIDC provenance 的 source ref / source digest 與獨立 verifier 要求的 tag / commit 完全一致。

權限分離如下：

- validate / build / gate：`contents: read`；build 沒有 OIDC、attestation 或 release write。
- verify：`contents: read` + `attestations: read`，只能讀取並驗證既有 provenance，沒有 write/OIDC。
- attest：只有此 job 取得 `id-token: write`、`attestations: write`，另提供目前 `actions/attest` 寫入 artifact metadata 所需的 `artifact-metadata: write`；沒有 `contents: write`。
- publish：只有 gate 成功且使用者明確設定 `publish=true` 才取得 `contents: write`；另以 `issues: read` 確認 #24 與 #43 均已關閉。既有 Release 一律拒絕覆寫。

所有 `uses:` 都釘選完整 40-hex action commit。Buildroot 版本、來源 SHA-256、簽章與 release key 已由 `infra/buildroot.env` 固定；target wheelhouse 由 `infra/wheelhouse-requirements.txt` 與 `infra/wheelhouse.sha256` 固定；Node release runtime 固定為 `24.22.3` 並用各 app 的 `package-lock.json` 執行 `npm ci`。SBOM action 固定 commit，Syft 固定為 `v1.54.0`。

## 建置、attestation 與 publish 順序

流程固定為：

1. signed tag → exact source SHA 驗證。
2. 同一來源做兩次 clean Buildroot image build，`scripts/check_reproducible.sh` 比對 raw `usb-cold-wallet.img` SHA-256。
3. 對第二次 raw image 再確認 digest，使用該 Buildroot 版本所固定的 host `xz`，以 `-6 --threads=1 --check=crc64 --no-sparse` 壓縮兩次並 byte-for-byte 比對。
4. 由最後 root filesystem 產生 SPDX JSON SBOM；建立 `release-metadata.json` 與 `SHA256SUMS`。manifest 只涵蓋最後預定發布的 image、SBOM、metadata。
5. 將這批 candidate bytes 上傳成同一次 workflow 的 immutable Actions artifact；attest job 下載原 bytes 後建立 SLSA Build Provenance，另建立 SBOM attestation。
6. verify job 重新下載同一 candidate artifact，沿用 `verify_release_assets.py --local-dir` 驗證 repository、tag source ref、source SHA、release workflow identity、signer digest、subject digest、manifest 與 metadata。
7. required gate 把 build / attest / verify 的 `skipped`、`cancelled`、`failure` 全部視為失敗。
8. publish job 只下載已通過驗證的 artifact，再做 checksum；**沒有 build、重新壓縮或修改 bytes 的步驟**，接著才建立 GitHub Release。

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

驗證器固定 repository，不接受 URL；它從 GitHub Release 下載 `SHA256SUMS` 與指定 image，重算 SHA-256，再要求 Immutable Release integrity、Release Asset Attestation，以及 `.github/workflows/release.yml` 對相同 tag/source SHA/subject digest 的 SLSA Build Provenance。任一缺失或不一致均 nonzero exit。

`SHA256SUMS` 只能證明 bytes 與 manifest 一致；其本身仍需 GitHub 的 Release integrity / asset verification。signed tag、Immutable Release、Build Provenance 各自提供不同保證，不能互相替代。

## Repository admin 必須人工設定

此 workflow **不會也不能假裝已替 repository 開啟下列管理設定**：

1. **Immutable Releases**：Repository → Settings → General → Releases 啟用 immutable releases。正式發布後執行 `gh release verify <tag> -R ChiJiun/usb-btc-evm-cold-wallet`，失敗就不得宣稱 release integrity 已驗證。
2. **Signed annotated tag**：維護者用受控 GPG/SSH signing identity 建立版本 tag，例如 `git tag -s <tag> <exact-sha>` 後 push；在 GitHub tag 頁確認 `Verified`，並再次核對 tag 指向的 commit。
3. **main / workflow 保護**：以 repository Rulesets 或 branch protection 要求必要 CI、review，並限制可修改 release workflow / 建立版本 tag 的身分。實際規則需在 Settings 中人工確認；本文件不宣稱目前已啟用。
4. 若組織政策提供 deployment environment / required reviewers，可再把 publish job 綁定受保護 environment；目前 workflow 沒有假設該 environment 已存在。

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
