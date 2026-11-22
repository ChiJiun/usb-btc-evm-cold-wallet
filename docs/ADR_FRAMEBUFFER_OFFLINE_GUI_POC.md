# ADR: framebuffer-native offline review POC (Issues #19/#20/#37)

Status: **EXPERIMENTAL / DRAFT — exact-head CI and SignerSession E2E still required**. Independent from PR #76.

## Decision

Ship the reviewed `framebuffer_poc.py` module in the offline image under the existing fail-closed module allowlist, but keep it dormant behind a manual **public test-vector demo**. The normal Live OS continues to boot the text appliance. The POC uses direct Linux fbdev (`/dev/fb0`) plus the active kernel VT (`/dev/tty1`) and therefore needs no `AF_UNIX`, X11, Wayland, SDL, network socket, or `CONFIG_NET`.

The renderer accepts only the existing immutable `review.ReviewPlan`. It does not parse a transaction, build or mutate transaction fields, load a vault, handle wallet secrets, call `SignerSession`, or invoke a signer. The only successful result is `ReviewIntent(review_digest, reviewed=True, reason="reviewed")`; this is explicitly **not signing authorization**.

## Runtime security boundary

- `CONFIG_NET=n` remains mandatory. Buildroot also keeps networking clients absent.
- The framebuffer module imports only Python stdlib plus `ReviewPlan`; it has no `socket`, X11/Tk, subprocess, RPC, or signer dependency.
- Before entering graphics, the caller must pass the existing `gui.runtime_audit()`. The audit is repeated during interaction.
- `/dev/ttyN` must be the active VT. The POC uses `VT_LOCKSWITCH`, switches to `KD_GRAPHICS`, checks the active VT every loop, and fail-closes if focus/audit is lost.
- Cleanup blanks the framebuffer, restores the prior KD mode, unlocks VT switching, and restores termios. Cleanup failure discards a positive intent.
- Keyboard input is raw VT input only. Split ANSI cursor sequences are parsed byte-by-byte; malformed/truncated escape input cancels rather than approves.
- Mouse input is intentionally unsupported in this POC; no `/dev/input` mouse device is opened, so mouse events cannot approve a review.
- Every ReviewPlan field is wrapped without ellipsis. Each page must reach its final wrapped line before Enter can acknowledge it, and every page must be acknowledged.
- Review fields whose key/source suggests mnemonic, passphrase, seed, xprv or private-key material are rejected before rendering. The display plan is capped at 256 KiB and 64 pages.
- The POC never writes transaction data or review contents to logs or disk. QEMU serial evidence contains only fixed status/metrics markers.

## Font provenance

The image includes one deterministic PSF2 font generated from the 1024-byte bitmap table in:

- upstream: `dhepper/font8x8`
- commit: `8e279d2d864e79128e96188a6b9526cfa3fbfef9`
- exact path: `font8x8_basic.h`
- license evidence: the exact file header and upstream README both state **Public Domain**

No executable renderer source is copied. `scripts/generate_framebuffer_font.py` bit-reverses the upstream LSB-left rows, doubles them vertically to 8x16, pads slots 128..255 blank, and emits the single accepted PSF2 layout.

## Actual guest acceptance path

`scripts/verify_framebuffer_qemu.sh` boots the exact generated GPT image through OVMF with `-net none`, waits for the normal audited appliance, and manually selects option 8. The demo uses the repository's published compromised BIP39 test vector and constructs a fixed Sepolia `ReviewPlan` via `exchange.package()` + `review.build_review_plan()`.

Acceptance requires:

1. the normal startup audit to pass with `CONFIG_NET=n`;
2. the POC to reach first framebuffer draw;
3. QEMU HMP `screendump` to capture actual guest pixels, not a host mock/PPM renderer;
4. keyboard navigation plus explicit acknowledgement of all five backend-generated EVM review pages to emit a positive **Review Intent**;
5. a second launch where Escape emits only a cancelled intent;
6. evidence artifact containing the QEMU PPM screenshot, actions log and metrics.

The default appliance never auto-launches this demo.

## Passphrase design

Passphrase entry is **not implemented** in this POC and remains a production blocker. The integration design is: enter on the already locked active VT, disable echo, keep the value only in process memory for the shortest possible unlock call, never place it in `ReviewPlan`, framebuffer text, serial/stdout, environment variables, command-line arguments, crash dumps, swap or persistent files, and clear mutable buffers where possible. Python cannot guarantee complete memory zeroization of immutable string copies, so product integration must minimize copies and treat process lifetime/lock as the stronger boundary.

No screenshot or test evidence may contain a real passphrase. The current QEMU demo does not request one.

## PR #76 integration contract

PR #76 remains authoritative for Live OS media/runtime policy:

- `appliance.mount_transfer()` controls accepted `TX_TRANSFER` mounts.
- `gui.runtime_audit()` controls RAM-root/network/swap/mount/device checks.
- `/run/usb-wallet/lockdown` and `/run/usb-wallet/*-device` identity files remain fail-closed.
- PR #79 must not alter PR #76's branch.

Future real signer integration must load the untrusted request through the existing exchange path, build the `ReviewPlan` in the existing signer backend, render it here, then independently rebuild/revalidate the plan/digest and policy before calling `SignerSession.start_review()` / `approve()` / `signing()`. Any changed request, review digest, account, chain, amount, fee, policy or runtime audit must reset/lock. Until that adapter and full BTC/Sepolia E2E exist, this PR remains Draft and must not merge.

## Performance evidence

The QEMU evidence records:

- exact raw image byte count;
- guest `/proc/uptime` at first framebuffer draw;
- Python process `ru_maxrss` at first draw;
- host QEMU start → appliance ready;
- appliance ready → first GUI frame;
- screenshot SHA-256.

Raw image geometry is fixed by `genimage.cfg`; compressed-size delta versus the last exact-main image is evaluated only after a successful exact-head artifact exists. No performance number is claimed before the workflow actually reports it.

## Remaining acceptance blockers

- exact-head Python CI, Offline Wheel and full Live USB workflows must succeed;
- actual QEMU screenshot/keyboard evidence must be produced by that exact head;
- real BTC and Sepolia requests are not yet connected to this UI;
- `SignerSession`/policy/fresh-plan binding is not yet connected;
- real passphrase entry is not implemented;
- mouse is unsupported rather than security-reviewed as an input method;
- physical USB/UEFI display and keyboard behavior remains separate hardware acceptance.
