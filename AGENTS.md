# Agent development rules — reuse before implementation

Read `docs/OPEN_SOURCE_REFERENCES.md` and `docs/USB_MVP_ACCELERATION_PLAN.md` before starting an issue that overlaps an existing wallet, QR, GUI, or Live USB feature.

## Required reuse-first workflow

1. **Search local code first.** Identify the existing module, public API, tests, and security invariants. Extend the current implementation; do not write a parallel signer, parser, request envelope, policy, or state store.
2. **Find a concrete upstream implementation.** Check the upstream repository at a pinned commit, identify exact source paths/functions and their transitive dependencies, and compare them with the missing feature. Do not stop at reading an architecture description.
3. **Prefer actual reuse in this order:** import an already pinned, reviewed library; copy a small licensed upstream file/function and adapt it; adapt a small upstream patch; implement locally only if direct reuse is incompatible, unsafe, or more expensive. When copying is viable, **copy the real implementation rather than generating a fresh equivalent from memory**.
4. **Check licensing before copying.** Verify license coverage of the *exact source path* at the *exact upstream commit*, including NOTICE/copyright, dependencies, and compatibility with this repository's MIT distribution. Preserve upstream notices. A license on a different subdirectory is not sufficient. Reference-only sources must not be copied without clearance.
5. **Keep the patch minimal.** Pin upstream commit and record source URL/path, copied lines or files, original license, local changes, and why reuse was chosen in the PR. If no code was copied, state that explicitly; distinguish a dependency import from source-copying.
6. **Adapt security boundaries, not just interfaces.** Enforce offline operation, testnet/Sepolia scope, bounded parsing, account/chain/request/digest binding, fail-closed policy, deterministic builds, and untrusted USB/FAT32 assumptions as applicable. Do not replace the existing hardened BTC/EVM signing, vault, policy, or request/response core simply to maximize copied lines.
7. **Verify independently.** Add positive/negative tests for local integration and security invariants; where possible compare with upstream vectors and an independent oracle. Run relevant tests/CI. Do not equate upstream tests with local acceptance.

## PR evidence (required)

- Existing local modules reused:
- Upstream repository + exact commit + source paths examined:
- Reuse method: dependency / copied-and-adapted / patch / original implementation
- License and attribution evidence (for copied code):
- Approximate copied/adapted LOC (do not count dependencies as copied LOC):
- Local adaptations and security constraints:
- Tests and remaining gaps:

See the concrete source-to-feature map in `docs/OPEN_SOURCE_REFERENCES.md`. Existing security review and CI gates take precedence over speed.
