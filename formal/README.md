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
