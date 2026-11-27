# Attended TX_TRANSFER rescan

This model follows the single-USB text console and the stalled FAT probe
reported against commit `5d744c0c74490bca77219ab1a96a1a4a9759a5f0`.
The report held the sector read open and observed that option 5 returned only
after the read was released.
[PR #76 review](https://github.com/ChiJiun/usb-btc-evm-cold-wallet/pull/76#pullrequestreview-6082904117)

| Model actions | Runtime mapping |
| --- | --- |
| `Start`, `UnmountDone` | `_rescan_transfer` checks the current audit, then calls `unmount_transfer` and checks the kernel mount table. |
| `ProbeDone`, `ProbeTimeout` | `_bounded_transfer_device` accepts a completed read-only result or enters lockdown on timeout. |
| `MountDone`, `CommandTimeout` | `_run_media_command` creates a pending marker before starting a command and locks down after a deadline. |
| `Audit`, `Swap` | `mount_transfer` checks source and VFAT flags and `_rescan_transfer` reruns the live audit before emitting `transfer-ready`. The medium can change between transitions. |
| `LateExit`, `ObserveExit`, `Respawn` | The worker can finish after cancellation was requested. `_media_command_quiescent` requires observed process exit before removing its marker. A new console instance lacks that process handle. |
| `Shutdown`, `CleanupDone`, `CleanupFailed` | `_poweroff` locks wallet operations, checks for a pending command, rechecks the mount table, and requires transfer and vault unmount, sync and OS acceptance of poweroff. |

There are two abstract media identities and an absent state. The model
abstracts the single-USB mount and boot identity checks as one audit decision,
and failed post-mount checks conservatively retain a possible mount until
cleanup. Shutdown steps are summarized by a cleanup action. `Off` represents
acceptance of the shutdown command by the OS. Weak fairness assumes the
console gets CPU time to handle its deadlines and the RAM-root/sysfs mount
audit returns. Worker exit after a timeout is optional. No wall-clock time,
kernel USB behavior, concurrent signer sessions, FAT persistence, device
path reuse with indistinguishable identity, or physical power indication is
verified by this model.

## Reproduce with TLC

Use TLA+ tools v1.7.4 (TLC 2.19), jar SHA-256
`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.
Run from this directory with `TLC_JAR` set to the absolute jar path.

```sh
scratch=$(mktemp -d)
sed 's/ProbeDeadline = TRUE/ProbeDeadline = FALSE/' TransferRescan.cfg > "$scratch/no-deadline.cfg"
sed 's/KeepPending = TRUE/KeepPending = FALSE/' TransferRescan.cfg > "$scratch/no-pending.cfg"
for case in reach-ready reach-off; do
    cp TransferRescan.cfg "$scratch/$case.cfg"
done
printf '\nINVARIANT NoNormalReady\n' >> "$scratch/reach-ready.cfg"
printf '\nINVARIANT NoSafePoweroff\n' >> "$scratch/reach-off.cfg"
java -Xmx256m -XX:+UseParallelGC -cp "$TLC_JAR" tlc2.TLC -workers 1 \
    -metadir "$scratch/good" -config TransferRescan.cfg TransferRescan.tla
for case in no-deadline no-pending reach-ready reach-off; do
    java -Xmx256m -XX:+UseParallelGC -cp "$TLC_JAR" tlc2.TLC -workers 1 \
        -metadir "$scratch/$case" -config "$scratch/$case.cfg" TransferRescan.tla
done
```

| Case | Observed result |
| --- | --- |
| Standard | Exit 0. 758 generated states, 206 distinct, all explored. No counterexample to the three invariants or `ReturnToMenu`. |
| No probe deadline | Exit 13. `Idle → Unmount → Probe`, followed by an indefinite swap loop in `Probe`, violates `ReturnToMenu`. |
| Clear pending marker at deadline | Exit 12. `Idle → Unmount → Locked` leaves a worker active with the marker cleared, violating `PendingIsGuarded`. |
| Reach normal ready | Exit 12 for deliberate `NoNormalReady` assertion. A successful probe, mount and audit reach the transfer-ready result. |
| Reach safe poweroff | Exit 12 for deliberate `NoSafePoweroff` assertion. Successful cleanup and OS acceptance are reachable. |

The executable regression tests are in `tests/test_live_appliance_runtime.py`.
They inject a blocked FAT read using a FIFO, a late mount completion, and
a pending marker after console respawn. No real media or keys are used.

## Boot and live mount audit

`MediaAudit` models the remaining PR #76 findings. `CheckBoot` corresponds to
`identify_media._layout_valid` and `fat_label`. Its single-USB geometry gate
also represents the corresponding check in `scripts/verify_image.py`. The
host verifier supports the three-partition layout. The startup identifier
also supports historical two-partition images that set GPT bits 2 and 60.
`Audit` corresponds to the fresh `gui.runtime_audit` decision after a
mount or superblock becomes read-only. Each of the four writable layers can
change independently. Geometry is an abstract input classification. The
sector arithmetic, GPT decoding and mountinfo parsing are exercised in
`tests/test_boot_media.py` and `tests/test_gui_runtime.py`.

Use the same `scratch` and TLC command with `MediaAudit.tla` and
`MediaAudit.cfg`. Run the three mutations by changing one constant at a time
from `TRUE` to `FALSE` in a temporary copy of the configuration. For the
reachability case, append `INVARIANT NoLiveAcceptance`.

| Case | Observed result |
| --- | --- |
| Standard | Exit 0. 7,968 generated states, 464 distinct, all explored. |
| `RequireGeometry = FALSE` | Exit 12. Label-only single-USB layout passes boot and violates `SingleBootRequiresGeometry`. |
| `RequireBothWritable = FALSE` | Exit 12. The live audit accepts a read-only layer and violates `LiveRequiresAllWritable`. |
| `AllowLegacyBootable = FALSE` | Exit 12. A legacy ESP with bits 2 and 60 is rejected and violates `LegacyEspCompatibility`. |
| Reach live acceptance | Exit 12 for deliberate `NoLiveAcceptance` assertion. Boot admission and a live audit with all four layers writable are reachable. |
