# ADR: framebuffer-native offline review POC (Issues #19/#20/#37)

Status: **EXPERIMENTAL / BLOCKED for product integration**. Independent from PR #76.
Baseline: main `3aa32d5f9bd785bd64c83c2b2599d05c59653c6b`; PR #76 `057aed238ceac805a1a90acd297dfc38cd873359` at study time.

## Decision

Investigate direct Linux **fbdev** (`/dev/fb0`) + dedicated kernel virtual terminal (`/dev/tty1`) input using Python stdlib. No `AF_UNIX`, `CONFIG_NET`, X11, Tk, Wayland, SDL or remote IPC. Framebuffer open/mmap and kernel VT keyboard do not require socket syscalls. PSF2 raw bitmap font provided as a separately verified Buildroot image input; no unreviewed font is bundled by this POC. The application rejects incompatible geometry, pixel channel layout, font headers and unsupported format. This implementation is a **POC only**; a production GUI may instead use direct DRM/KMS and evdev, provided corresponding display/input drivers and package provenance are tested.

`src/usb_cold_wallet/framebuffer_poc.py` draws independently generated fields from the existing `ReviewPlan.pages`; no signer, transaction parser, private keys, blockchain library or policy is reimplemented. A caller may use `run_vt(plan, font_path, audit=runtime_audit_callback)` to present review screens and receive **authorization intent only**. It never calls the signing backend.

The existing `review.build_review_plan`, `review.review_policy_decision`, `SignerSession`, `gui.runtime_audit` and `appliance.mount_transfer` remain authoritative. An eventual adapter must independently reparse/rebuild the payload snapshot and revalidate review digest, chain, account, recipient, amount, fee, policy and the current runtime audit **after** UI confirmation and **before** `SignerSession.approve` / `signing`; any mismatch locks/aborts. This POC's return value is not evidence of authorization for a signer. Avoid displaying secrets and never send a private key to the framebuffer renderer.

## Scope and acceptance

- Native framebuffer pixel drawing and left/right page navigation, up/down scroll, Enter per-page acknowledgement and Escape cancellation.
- Every transaction field is wrapped, not ellipsized. Lengthy fields require scrolling to the final line before acknowledgement. The POC does not yet enforce that each byte was visually inspected.
- Runtime audit failure disables approval; terminal errors fail closed. Unrecognized input does not grant approval.
- **Not included:** interactive vault password entry, mouse/evdev, signed output, per-keystroke cryptographic challenge, complete SignerSession wiring, idle timeout, automatic lock on VT change, true QEMU GUI evidence, robust PSF Unicode mapping, and production-ready input protection. These are mandatory integration work, not accepted functionality.
- The raw VT must be protected from kernel console text overwriting framebuffer pixels; verify `KD_GRAPHICS`, VT allocation/release and focus on actual hardware/QEMU. The prototype currently does **not** switch to `KD_GRAPHICS` and so may have fbcon competition. This is an explicit blocker.
- Current `run_vt` handles common escape sequences as one read, not a complete keyboard parser. Malformed or split escape sequences are ignored. Input correctness needs real QEMU/USB testing.

## Why this path

Tk needs X11, whose local protocol uses AF_UNIX unavailable under `CONFIG_NET=n`. A terminal-oriented launcher is a functional fallback but does not prove graphic UI delivery. A direct fbdev POC has no extra GUI runtime dependencies, preserves the present kernel policy and reuses the wallet's existing immutable offline review data model. It also allows a small renderer without copying source from an upstream project.

Upstream source copied: **0 LOC**. Upstream pinned/ported font: **none**. Existing modules reused: `review.ReviewPlan` data contract, `signer_session.SignerSession` integration contract, runtime audit contract. Implementation: new local POC, not a third-party dependency.

## Buildroot integration proposal for PR #76 (do not modify #76 here)

1. Keep `CONFIG_NET=n` and all existing runtime audits. Verify `CONFIG_FB`, `CONFIG_FB_EFI` or simpledrm fbdev emulation, `CONFIG_VT`, `CONFIG_VT_CONSOLE`, USB HID keyboard drivers in the **actual** kernel config and QEMU guest.
2. Add a pinned-license-reviewed ASCII-indexed PSF2 font to the image, with a SHA-256 pinned source and attribution as needed. Copy this module into the existing `usb-wallet-app` package; avoid an entire GUI framework.
3. Replace the tty-only launcher only after a guest integration flow exists: audit -> trusted wallet unlock -> verified request and policy -> ReviewPlan -> controlled framebuffer review -> digest-bound fresh validation -> SignerSession approval/signing -> signed output; always provide a fail-closed lock screen.
4. Add `KD_GRAPHICS` / `KD_TEXT` transitions, strict exclusive VT ownership, mouse optional evdev support, keyboard event framing, secure passphrase entry, fixed visible focus, idle lock, and atomic request observation.
5. Produce QEMU/OVMF screenshot/video of **actual guest pixels**, raw image hash and guest logs; demonstrate keyboard input transitions/cancellation and an audit-failure screen. A static PPM fixture is insufficient.
6. Execute all #76 negative USB identity/mount checks plus the standalone UI cancel, malicious field length, changed-request, stale review, audit failure and lock tests. Require exact-head CI and whole image reproducibility before merge.

## Measurement protocol / presently unavailable measurements

Use the same pinned Buildroot host, QEMU version and fixed 1-vCPU / 512 MiB guest. Record image raw byte count and compressed size both before/after the module+font; inspect guest `/proc/<pid>/status` VmRSS/VmHWM for the UI and system `/proc/meminfo`; timestamp UEFI start, guest init, first framebuffer draw and first interactive input, repeat >=3 clean boots. Also confirm `/proc/config.gz` or compiled config has `CONFIG_NET=n`. **No measured image-size delta, memory RSS or boot time is claimed by this research branch** because no full Buildroot/QEMU build was executed.

## Verification status

Host unit tests provided in `tests/test_framebuffer_poc.py`. No guest framebuffer session, PSF2 font packaging, QEMU/OVMF screenshot, real keyboard/mouse demonstration, two clean builds or security audit has been completed. Therefore **BLOCKED** for the requested true-graphics acceptance gate. Keep PR #76 Draft and do not merge this branch on host tests alone.
