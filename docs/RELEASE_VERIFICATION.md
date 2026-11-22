# GitHub Release provenance 與獨立驗證（#57）

目前專案沒有經 #24／#43 實體安全驗收核准的 production-safe Release。`.github/workflows/release.yml` 已工程化正式供應鏈流程，但 `publish` 預設為 `false`，且 #24 或 #43 仍為 open 時 publish job 會 fail closed。

## Release workflow 信任邊界

`.github/workflows/release.yml` 是**無特權 candidate workflow**。它可由 `workflow_dispatch` 接受 tag、source SHA 與 publish intent，但整個 workflow 都沒有 `contents: write`、OIDC 或 attestation write 權限；即使有人刻意從非 main ref dispatch，也不能直接建立 attestation 或 Release。Candidate 仍要求 `GITHUB_REF == refs/heads/main`，用來拒絕非 main 的正式候選建置，但這項檢查本身不被當成發布權限的信任錨點。

真正有特權的 `.github/workflows/release-finalize.yml` 只由 `workflow_run` 啟動，workflow definition 由 repository default branch 取得。Finalizer 只接受成功完成、event=`workflow_dispatch`、head branch=`main`、workflow path=`.github/workflows/release.yml`、repository/head repository 均為本 repository 的前置 run，並要求觸發 run 的 head SHA 與 finalizer 當下的 protected-main `GITHUB_SHA` 完全相同。main 若在長時間 Buildroot 建置期間前進，finalizer 直接 fail closed，必須從新 main 重新產生 candidate。

Candidate 的 signed annotated tag 必須精確指向 input source SHA；GitHub 必須回報 GPG tag `verified=true` / `reason=valid`，tagger email 必須命中受保護 verifier 內的 release identity allowlist。Validate 固定 annotated tag object SHA；finalizer 在 attestation 前與 publish 前都重新比對。SLSA provenance 的 signer workflow / source identity 綁定 **`release-finalize.yml` 的 protected-main SHA**；實際 release source SHA/tag 則由 signed tag、metadata 與 manifest 獨立綁定。

權限分離如下：

- candidate validate / build / verify / gate：最多 `contents: read`，沒有 OIDC、attestation write 或 release write。
- finalizer preflight：`actions: read` + `contents: read`，只下載並解析前置 run 的 artifact，不執行 artifact 內程式碼。
- finalizer attest：`id-token: write`、`attestations: write`、`artifact-metadata: write`，但沒有 `contents: write`。
- finalizer verify：`contents: read` + `attestations: read`。
- finalizer publish：只有 candidate metadata 明確記錄 `publish_requested=true`、所有 privileged gates 成功、#24/#43（stable 另含 #48）通過時才取得 `contents: write`。既有 Release 一律拒絕覆寫。

所有 `uses:` 都釘選完整 40-hex action commit。Buildroot 版本、來源 SHA-256、簽章與 release key 由 `infra/buildroot.env` 固定；target wheelhouse 由 `infra/wheelhouse-requirements.txt` 與 `infra/wheelhouse.sha256` 固定；Node release runtime 固定為 `24.22.3` 並以 lockfile 執行 `npm ci`。SBOM action 固定 commit，Syft 固定版本。Release host 的 APT 現改用固定 Ubuntu Snapshot ID，並把每個安裝套件解析成 `package=version` 後驗證實際 dpkg version；`build-host-packages.txt` 仍保留作證據。GitHub-hosted `ubuntu-24.04` runner image 與 host kernel 仍是 GitHub 管理的可變輸入，因此目前只能稱為 **APT snapshot-pinned、runner-recorded**，不能宣稱 hermetic build。

## 建置、attestation 與 publish 順序

流程固定為：

1. signed tag → exact source SHA 驗證。
2. 同一來源做兩次 clean Buildroot image build，`scripts/check_reproducible.sh` 比對 raw `usb-cold-wallet.img` SHA-256。
3. 對兩次 raw image 的 SHA-256 再做顯式相等檢查，將共同 digest 寫入 `release-metadata.json`；使用該 Buildroot 版本所固定的 host `xz`，以 `-6 --threads=1 --check=crc64 --no-sparse` 壓縮兩次並 byte-for-byte 比對。
4. 由最後 root filesystem 產生 SPDX JSON SBOM；保存 `build-host-packages.txt`、`release-metadata.json` 與 `SHA256SUMS`。manifest 精確涵蓋最後 image、SBOM、metadata、host dependency evidence。
5. Candidate workflow 將這批 bytes 上傳成名稱綁定 `run_id` / `run_attempt` 的 Actions artifact，並先做無特權的本機 digest／metadata／tag-object 驗證。
6. Default-branch `release-finalize.yml` 由 `workflow_run` 啟動；preflight 重新驗證前置 run 身分、protected main SHA、repository rulesets、唯一 artifact 名稱、signed tag、source SHA、tag object、manifest、SPDX 與 metadata。main 已前進或 artifact/run 不一致即 fail closed。
7. Finalizer attest 對 image、SBOM、metadata、host dependency evidence 建立由 `release-finalize.yml` protected-main SHA 簽發的 SLSA Build Provenance，另對 `SHA256SUMS` 建立 provenance、對 image 建立 SBOM attestation；verify 再逐一驗證 subject digest 與 signer identity。
8. Privileged gate 把 preflight / attest / verify 的 `skipped`、`cancelled`、`failure` 全部視為失敗。publish 只下載同一已驗證 artifact，並在 `gh release create` 前再次確認 current main、前置 workflow run、repository controls、authorized signer、source SHA 與固定 tag object SHA。任何 main/tag/run/artifact 替換都 fail closed。

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
  --commit <independently-verified-40-hex-source-commit> \
  --workflow-sha <independently-verified-40-hex-main-workflow-commit> \
  --asset usb-cold-wallet-v0.1.0-beta.1.img.xz
~~~

驗證器固定 repository，不接受 URL；它從 GitHub Release 下載 `SHA256SUMS`、指定 image、SPDX SBOM、release metadata 與 host dependency evidence，要求 manifest 精確覆蓋全部 payload 並逐一重算 SHA-256，再對每個檔案要求 Immutable Release asset integrity，以及由 `.github/workflows/release-finalize.yml` 在指定 protected-main SHA 簽發的 SLSA Build Provenance。release source tag/SHA 則另外由 signed annotated tag 與 metadata 驗證；任一缺失或不一致均 nonzero exit。

`SHA256SUMS` 只能證明 bytes 與 manifest 一致；其本身仍需 GitHub 的 Release integrity / asset verification。signed tag、Immutable Release、Build Provenance 各自提供不同保證，不能互相替代。

## Repository admin 必須人工設定

此 workflow **不會也不能假裝已替 repository 開啟下列管理設定**：

1. **Immutable Releases**：Repository → Settings → General → Releases 啟用 immutable releases。正式發布後執行 `gh release verify <tag> -R ChiJiun/usb-btc-evm-cold-wallet`。
2. **Release tag ruleset（目前 BLOCKER）**：建立 Active tag ruleset，include 精確設定 `refs/tags/v*`，啟用 **Restrict updates / Restrict deletions**，且 `exclude=[]`、`bypass_actors=[]`。不要啟用 Restrict creations：GitHub 的該規則只允許 bypass actor 建立符合規則的 Tag；本流程改由 GitHub verified GPG signature + signer allowlist 決定哪些新 Tag 可進入 Release Pipeline，並由 update/delete restrictions 鎖住已建立 Tag。
3. **main / workflow trust anchor（目前 BLOCKER）**：現有 `main-protection` 必須至少要求 1 個有效 PR approval、**Require approval of the most recent reviewable push**、required status check `CI / Required`，並禁止 branch deletion 與 non-fast-forward update。符合資格的 main ruleset 必須沒有 ref exclusions 或 bypass actors。Finalizer 會從 Rulesets API fail-closed 驗證這些條件。完成後讀 ruleset detail 確認 `refs/heads/main`、Active、approval count ≥ 1、last-push approval=true、required check 包含 `CI / Required`、deletion / non-fast-forward 規則存在，且 `exclude=[]`、`bypass_actors=[]`。
4. **Authorized signer**：release tag 目前明確限制為 **GPG signed annotated tag**；verifier 同時要求 GitHub `verified=true`、`reason=valid`、PGP signature armor，以及 signed tagger email 命中受保護 main 內的 allowlist。GitHub 對 GPG tag 的 Verified 判定會核對 tagger email、GPG key identity 與該帳號已驗證 email。若未來增加 release maintainer，必須先經受保護 main PR 修改 allowlist。
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
