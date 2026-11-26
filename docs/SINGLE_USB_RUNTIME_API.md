# Single-USB cold runtime integration contract

PR #76 owns only the cold Live OS boot/runtime boundary for Issues #37, #1 and #34.

## Stable integration surface for PR #75

The transaction UX may consume these existing runtime interfaces without duplicating media policy:

- `usb_cold_wallet.appliance.mount_transfer() -> bool`: mounts only an accepted TX_TRANSFER source with the reviewed VFAT flags.
- `usb_cold_wallet.gui.runtime_audit() -> (bool, findings)`: revalidates the live RAM-root, no-network/no-swap state, vault/transfer mount source/options, sysfs ancestry and boot disk instance.
- `/run/usb-wallet/boot-parent`: boot/vault parent block name selected by boot audit.
- `/run/usb-wallet/boot-device`: exact verified ESP partition; never mount it in the cold runtime.
- `/run/usb-wallet/vault-device`: exact verified vault partition.
- `/run/usb-wallet/transfer-device`: present only for the verified same-parent three-partition layout.
- `/run/usb-wallet/boot-sysfs-path` and `/run/usb-wallet/boot-diskseq`: pinned device-instance identity for replacement/replug detection.
- `/run/usb-wallet/lockdown`: any consumer must fail closed when present.

PR #75 remains responsible for cross-boot request discovery, protocol/state-machine UX, transaction review presentation and signed-response handling. PR #76 must not duplicate that state machine.

## Local display boundary

The kernel remains `CONFIG_NET=n`. This also removes AF_UNIX, so X11/Tk is not a valid local display architecture even with TCP listeners disabled. The image therefore launches the single-purpose signer appliance on kernel VT/fbcon and does not ship Xorg, Xfbdev, xinit or tkinter.

A future graphical frontend must be framebuffer/DRM/input-native and must call the runtime interfaces above. Enabling `CONFIG_NET` requires a separate security ADR and full network-negative re-audit.

## Framebuffer handoff to PR #79

PR #79 may consume the existing `ReviewPlan` and pass `runtime_audit` as the
framebuffer controller's audit callback. Its controller is an approval-intent
surface only: it must never receive wallet keys or perform signing.

The eventual adapter must re-parse/rebuild the reviewed transaction, confirm
the same review digest and policy decision, and run `runtime_audit()` again
immediately before `SignerSession.approve()/signing()`. USB file access must
continue through `mount_transfer()`. PR #76 does not copy or reimplement the
framebuffer frontend.

The ESP's GPT bit 60 is verified exactly and the ESP stays unmounted in the
cold runtime. This metadata is not hardware write protection against a hostile
Windows administrator with raw-disk access.

## Compatibility

The legacy separate TX_TRANSFER USB remains accepted through the existing separate-parent policy. Same-parent TX_TRANSFER is accepted only when boot audit has verified the exact three-partition GPT layout and persisted the exact transfer device. No caller may bypass `mount_transfer()` or `runtime_audit()` to relax this distinction.

The startup audit and every live runtime audit reject an ESP mounted through an alternate path by matching its kernel major:minor, even if mounted read-only. The live audit also rejects unexpected persistent mounts whether read-write or read-only; a missing ESP identity fails closed. `mount_transfer()` refuses lockdown before discovering or mounting media.

### #79 and #75 interface differences (not yet integrated)

- **#79:** `framebuffer_poc.run_vt(plan, font, audit=...)` reads evdev keyboard events and owns VT/fbdev/termios acquisition, restoration, and abort on input removal. `authorize_review_intent(plan, intent, signer_session, rebuild_plan=..., audit=...)` accepts only a revalidated review digest. The `framebuffer-demo.py` entry uses a fixed public test vector, never unlocks a real vault or exports a signed response. PR #76 currently launches `usb-wallet-console` from `usb-wallet-gui-session`, and does not package `framebuffer_poc.py` in its offline wheel; a later integration must review the module allowlist and actual GUI launch separately.
- **#75:** its cross-boot v2 transaction discovery, replay/rollback requirements, response verification and Windows-side identity checks remain external. The Tk-based offline GUI in #75 cannot be launched by the `CONFIG_NET=n` image. A production adapter must revalidate `runtime_audit()`, mount via `mount_transfer()`, rebuild the transaction review and enforce the independent replay anchor before `SignerSession.approve()/signing()`.

**Evidence boundary:** dual clean-image SHA equality, structural GPT and loopback checks, and QEMU/OVMF serial audit establish the independent runtime, not graphical transaction approval, actual v2 signing/export, physical USB security, or rollback resistance. The graphical demo is POC only; these downstream acceptances must not be marked complete by PR #76.


## USB readiness and first physical boot (2026-11-24)

Physical test of d148441789648060d893a72614c4eda1150c0f3d on Acer Aspire
A515-57G / General UDisk (31,457,280,000 bytes), as reported by the operator:
Secure Boot enabled produced Security Boot Fail. Temporarily disabling it
allowed Linux to boot; CONFIG_NET=n, RAM-backed root and no swap passed.
Media identification failed and LOCKDOWN preceded USB descriptor error -110,
mass-storage discovery, sda1/sda2/sda3 and SCSI disk attachment. This ordering
supports delayed enumeration as one cause, not proof that the flashed GPT is
valid. The earlier #76 review independently reproduced failure of unadjusted
larger-capacity media; the runtime must not relax protective MBR or backup GPT
geometry to accommodate it.

Startup now begins locked, waits at most 60 seconds for two identical complete
scans (monotonic deadline and a read-only worker watchdog), and retries only
pending enumeration. Duplicate, malformed and replaced devices fail closed;
a missing or stuck device times out. Each production scan checks kernel block
device numbers, BLKGETDISKSEQ on opened descriptors, ancestry, both GPT copies
and partition/FAT metadata. A changed previously observed identity fails even
while other nodes are still enumerating. The vault starts read-only; the
complete inventory and mount major:minor are checked before remounting the
existing mount read-write and again afterward. Failure retains LOCKDOWN and
attempts to unmount the vault. This detects changes across checked boundaries,
not an atomic hardware guarantee: a malicious controller/firmware, future
hotplug or an uninterruptible kernel mount is outside this guarantee.

The normal exact-image OVMF test is still required. A separate QEMU test boots
the identical embedded kernel/initramfs without mass storage, waits for the
guest readiness marker, then injects USB via host QMP; a second boot with no
USB must time out and lock down. No networking in either guest. These are
simulation evidence only. Secure Boot/authenticated origin, Windows GPT/FAT32
capacity preparation, physical readback and retest remain independent gates.

Reuse: existing identify_media.py GPT/FAT parser and S01airgap policy; Linux
BLKGETDISKSEQ UAPI reference (Linux v6.12 commit
adc218676eef25575469234709c2d87185ca223a, include/uapi/linux/fs.h and
block/ioctl.c); Python standard library only, no upstream code copied.


## Second physical boot attempt (2026-11-26)

Operator video of exact source `76f58b847d4eb01656bf853fc8a01d6fd0109e4f`
on the same Acer/General UDisk shows Linux init, then
`FAIL: boot security audit contained no checks` and LOCKDOWN, before
USB descriptor error -110, mass-storage discovery and sda1/sda2/sda3.
The tested image passed CI run
[45408993902](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/actions/runs/45408993902);
the physical boot failed. The original script creates an empty audit file
and default lock, then writes MEDIA_WAIT to /dev/ttyS0 under set -e before
calling the media helper. A character node is not proof of a working UART.
A failed write or open can terminate init early, matching the observed
empty audit. This is a concrete software defect and a suspected physical
cause, not proof that the Acer UART actually returned an error.

Make all serial marker writes best effort; keep the file-based security
audit authoritative and report unexpected startup exits while locked.
Regression tests execute the real pre-scan prefix and final serial block
with /dev/full, an actual failing character device. No GPT, media identity,
mount, offline or timing gate is relaxed. No third-party source copied.
Exact-head CI, two clean builds, QEMU and a new physical retest remain
required. Power-off after menu option 6 was reported as a black display;
actual power state and shutdown success remain unconfirmed.


## Boot robustness follow-up

Use the existing standalone stdlib media helper for fixed serial markers with
nonblocking open/write and an independent two-second fork watchdog. Both
startup and appliance use it; failure is non-authoritative. Kernel-uptime
INFO stages are stored in the RAM audit log and displayed alongside real
PASS/FAIL lines. Missing mount/swap evidence fails closed; unexpected init
exits preserve the failing phase and attempt vault cleanup.

Only EAGAIN/EBUSY/EINTR/ETIMEDOUT or incomplete enumeration are retryable
during readiness. EIO, removal, malformed GPT/FAT and identity changes
remain permanent; no extra retry is permitted after a complete scan is
lost. Unit tests cover delay/deadline boundaries and UART failure/stall.
The direct-kernel QEMU matrix includes xHCI at 5 and 30 seconds and EHCI
at 15 seconds, plus absent media; OVMF and two independent clean builds
remain required. The normal and locked power-off menu shares explicit
unmount/sync/poweroff checks and keeps the console locked if shutdown
fails. A command accepted by PID 1 is not proof of physical power-off.

No upstream code copied; existing local media parser, watchdog pattern,
appliance, QMP and CI gate reused. Physical controller/firmware faults,
Secure Boot and raw-media provenance remain independent acceptance.


Capacity preparation now uses the existing structural verifier with a read-only
mmap (bounded metadata slices rather than loading a large image into RAM).
The host-only regular-file tool validates the independently pinned raw SHA,
preserves partition data/entries, relocates the secondary GPT to the exact
target end, and records the distinct derived digest. Unit tests cover 8/16/32/64
GiB-class media, and QEMU boots a disposable copy prepared to the actual
31,457,280,000-byte device capacity. QMP presses 6 and Enter in the normal and
locked menus and requires the guest kernel power-down evidence plus clean
QEMU exit. These tests are not physical power-state evidence. EHCI device/bus
configuration reference: QEMU docs at commit
d27e7c359330ba7020bdbed7ed2316cb4cf6ffc1, docs/system/devices/usb.rst;
no upstream source copied.


### Pre-third-boot review: init lifecycle and attended menu

Pinned Buildroot 2026.08.2 `package/initscripts/init.d/rcK` invokes each
S?? script with `stop` (BusyBox `package/busybox/inittab` runs rcK during
shutdown). The previous S01airgap ignored its argument and could perform
fresh media discovery and remount the vault after the console unmounted it.
The stop branch now keeps lockdown, preserves previous audit evidence and
returns before discovery. Only start executes the boot audit; arbitrary
restart is rejected. Upstream source consulted for lifecycle semantics only,
no copied upstream source.

Option 5 now checks live runtime before and after mount, reports success
only if the post-mount audit passes, and emits a fixed public marker via
the same bounded diagnostic helper. The QEMU delayed-media test invokes
option 5 twice before option 6 on every positive boot (including prepared
operator capacity) and checks that discovery did not rerun at shutdown.
An additional regular-file capacity test exercises the actual prepare_image
entry point with source digest, output digest, unchanged source, no-replace
and exact partition entries. Real USB/UEFI, physical shutdown, exact-image
readback and authenticated boot remain separate gates.
