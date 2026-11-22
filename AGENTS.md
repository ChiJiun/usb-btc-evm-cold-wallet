# Agent development rules — reuse before implementation

Read `docs/OPEN_SOURCE_REFERENCES.md` and `docs/USB_MVP_ACCELERATION_PLAN.md` before starting an issue that overlaps an existing wallet, QR, GUI, or Live USB feature.

## Required reuse-first workflow

1. **Search local code first.** Identify the existing module, public API, tests, and security invariants. Extend the current implementation; do not write a parallel signer, parser, request envelope, policy, or state store.
2. **Find a concrete upstream implementation.** Check the upstream repository at a pinned commit, identify exact source paths/functions and their transitive dependencies, and compare them with the missing feature. A repository-level license or README is not enough to classify a file as copyable. Do not stop at reading an architecture description.
3. **Prefer actual reuse in this order:** import an already pinned, reviewed library; copy a small licensed upstream file/function and adapt it; adapt a small upstream patch; implement locally only if direct reuse is incompatible, unsafe, or more expensive. When copying is viable, **copy the real implementation rather than generating a fresh equivalent from memory**.
4. **Check licensing before copying.** Verify license coverage of the *exact source path* at the *exact upstream commit*, including file headers/SPDX, repository/subdirectory LICENSE, NOTICE/copyright, transitive dependencies, and compatibility with this repository's MIT distribution. Preserve upstream notices. A license on a different subdirectory is not sufficient. GPL/LGPL/community/custom/reference-only code is **not** a copy-and-adapt candidate unless the exact use and distribution obligations have been explicitly reviewed.
5. **Keep the patch minimal.** Pin upstream commit and record source URL/path, copied lines or files, original license, local changes, and why reuse was chosen in the PR. If path-level provenance or licensing is not yet verified, label it **Candidate** or **Reference** and do not copy it. If no code was copied, state that explicitly; distinguish a dependency import from source-copying.
6. **Adapt security boundaries, not just interfaces.** Enforce offline operation, testnet/Sepolia scope, bounded parsing, account/chain/request/digest binding, fail-closed policy, deterministic builds, and untrusted USB/FAT32 assumptions as applicable. Do not replace the existing hardened BTC/EVM signing, vault, policy, or request/response core simply to maximize copied lines.
7. **Verify independently.** Add positive/negative tests for local integration and security invariants; where possible compare with upstream vectors and an independent oracle. Run relevant tests/CI. Do not equate upstream tests with local acceptance.

## PR evidence (required)

- Existing local modules reused:
- Upstream repository + exact commit + source paths examined:
- Reuse method: dependency / copied-and-adapted / patch / architecture reference / original implementation
- License and attribution evidence (for copied code, including exact file/path coverage, SPDX/NOTICE/copyright and relevant transitive dependencies):
- Approximate copied/adapted LOC (do not count dependencies as copied LOC):
- Local adaptations and security constraints:
- Tests and remaining gaps:

See the concrete source-to-feature map in `docs/OPEN_SOURCE_REFERENCES.md`. Existing security review and CI gates take precedence over speed.

## CI / Actions 變更前必讀

修改 `.github/workflows/**`、`scripts/ci_checks.py`、`scripts/ci_workloads.py`、`tests/test_ci_checks.py` 或 Live USB 建置流程前，**先讀 [`docs/CI_PERFORMANCE_AUDIT.md`](docs/CI_PERFORMANCE_AUDIT.md) 的「常見失敗與防止重複浪費 CI 時間」及 [`docs/CI_SECURITY.md`](docs/CI_SECURITY.md)**。重複故障必須記錄 Run URL、根因、最小修正、負向回歸測試與最新 HEAD 驗證結果。先執行 `python -m pytest -q tests/test_ci_checks.py`；未執行不可聲稱通過。不要為了修測試而降低 Required Gate、啟用 `CONFIG_NET` 或重啟重複的昂貴 Live USB Workflow。Draft PR 的單次 Build/QEMU 不代表 Ready PR 的雙次可重現性驗收。
