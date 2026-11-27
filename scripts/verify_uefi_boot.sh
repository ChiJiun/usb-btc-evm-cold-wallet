#!/bin/sh
# Boot the actual generated USB GPT image under OVMF and require the guest
# init security audit to report success. Never attach a network interface.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
IMAGE="$ROOT/build/output/images/usb-cold-wallet.img"
test -s "$IMAGE"
command -v qemu-system-x86_64 >/dev/null
# OVMF_CODE is a firmware code image, not a complete -bios ROM. Supply its
# matching variable-store template as a separate, disposable writable pflash.
# Mixing the 4M and legacy templates can silently fail before GRUB starts.
OVMF_CODE=""
OVMF_VARS=""
for candidate in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd; do
    [ -f "$candidate" ] || continue
    case "$candidate" in
        */OVMF_CODE_4M.fd) vars="${candidate%CODE_4M.fd}VARS_4M.fd" ;;
        */OVMF_CODE.fd) vars="${candidate%CODE.fd}VARS.fd" ;;
    esac
    if [ -f "$vars" ]; then
        OVMF_CODE="$candidate"
        OVMF_VARS="$vars"
        break
    fi
done
if [ -z "$OVMF_CODE" ]; then
    echo "ERROR: matching OVMF_CODE/OVMF_VARS firmware pair not found" >&2
    exit 1
fi

TMP="$(mktemp -d)"
PID=""
# Preserve bounded, public test-image diagnostics before deleting temp logs.
# GitHub's complete multi-hour build job log is too large to download reliably.
DIAGNOSTICS="$ROOT/build/reproducibility/uefi-smoke.log"
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        mkdir -p "$(dirname "$DIAGNOSTICS")" || true
        {
            printf '%s\n' 'UEFI smoke test failed; bounded guest serial and QEMU tail:'
            tail -c 32768 "$TMP/serial.log" 2>/dev/null || true
            printf '\n--- QEMU ---\n'
            tail -c 8192 "$TMP/qemu.log" 2>/dev/null || true
        } > "$DIAGNOSTICS" || true
    fi
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

cp "$OVMF_VARS" "$TMP/ovmf-vars.fd"
chmod 0600 "$TMP/ovmf-vars.fd"

# USB storage is the ONLY mass-storage device; no NIC, persistent host disks,
# host directory mounts, or wallet keys enter the VM.
qemu-system-x86_64 \
    -machine q35,accel=tcg -cpu max -smp 2 -m 1536 \
    -drive if=pflash,unit=0,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,unit=1,format=raw,file="$TMP/ovmf-vars.fd" \
    -display none -monitor none -serial "file:$TMP/serial.log" \
    -net none -no-reboot \
    -device qemu-xhci,id=xhci \
    -drive if=none,id=walletdisk,format=raw,snapshot=on,file="$IMAGE" \
    -device usb-storage,bus=xhci.0,drive=walletdisk,bootindex=1 \
    > "$TMP/qemu.log" 2>&1 &
PID=$!

count=0
while [ "$count" -lt 120 ]; do
    if grep -q 'USB_WALLET_UEFI_AUDIT_LOCKDOWN' "$TMP/serial.log" 2>/dev/null; then
        echo "ERROR: guest booted but startup audit entered LOCKDOWN" >&2
        tail -70 "$TMP/serial.log" >&2 || true
        exit 1
    fi
    if grep -q 'USB_WALLET_UEFI_AUDIT_OK' "$TMP/serial.log" 2>/dev/null \
       && grep -q 'USB_WALLET_CONSOLE_READY' "$TMP/serial.log" 2>/dev/null; then
        # Require the guest's bounded audit evidence, not only a success marker.
        for evidence in \
            'PASS: unique single-USB boot, vault and transfer layout verified' \
            'PASS: boot USB sysfs ancestry and disk sequence pinned' \
            'PASS: single-USB TX_TRANSFER partition bound to verified boot parent' \
            'PASS: boot partition is not mounted in cold runtime' \
            'PASS: COLD_VAULT mounted from verified PARTUUID device as vfat' \
            'PASS: COLD_VAULT restrictive mount options verified' \
            'PASS: /proc/net absent' \
            'PASS: no active swap' \
            'PASS: root filesystem is RAM-backed' \
            'PASS: no unexpected writable persistent filesystem mounted' \
            'PASS: offline startup audit complete'; do
            if ! grep -Fq "$evidence" "$TMP/serial.log"; then
                echo "ERROR: guest audit marker present but required evidence is missing: $evidence" >&2
                tail -100 "$TMP/serial.log" >&2 || true
                exit 1
            fi
        done
        echo "PASS: OVMF booted generated USB GPT image, guest security audit passed, and audited console reached its menu"
        # Separately boot the same embedded initramfs with USB initially absent.
        # The OVMF test above remains required and is never replaced by this.
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
        PID=""
        python3 "$ROOT/scripts/verify_delayed_usb.py"
        exit 0
    fi
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "ERROR: QEMU exited before guest startup audit marker" >&2
        tail -70 "$TMP/serial.log" >&2 || true
        tail -70 "$TMP/qemu.log" >&2 || true
        exit 1
    fi
    count=$((count + 1))
    sleep 2
done
echo "ERROR: UEFI guest boot did not reach startup audit within 240 seconds" >&2
if grep -Eq 'Linux version|Kernel command line|Booting Linux' "$TMP/serial.log" 2>/dev/null; then
    echo "DIAG: Linux emitted serial output; inspect kernel/init/audit" >&2
elif grep -Eq 'Booting |GNU GRUB' "$TMP/serial.log" 2>/dev/null; then
    echo "DIAG: GRUB reached, no Linux serial evidence; inspect EFI handoff and console" >&2
else
    echo "DIAG: no GRUB serial evidence; inspect OVMF/USB boot discovery" >&2
fi
tail -70 "$TMP/serial.log" >&2 || true
tail -70 "$TMP/qemu.log" >&2 || true
exit 1
