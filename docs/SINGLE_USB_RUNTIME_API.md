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
