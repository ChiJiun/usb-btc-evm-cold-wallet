#!/bin/sh
# Boot the actual generated USB GPT image under OVMF and require the guest
# init security audit to report success. Never attach a network interface.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
IMAGE="$ROOT/build/output/images/usb-cold-wallet.img"
test -s "$IMAGE"
command -v qemu-system-x86_64 >/dev/null
OVMF=""
for candidate in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/ovmf/OVMF.fd; do
    if [ -f "$candidate" ]; then OVMF="$candidate"; break; fi
done
if [ -z "$OVMF" ]; then
    echo "ERROR: OVMF firmware not found" >&2
    exit 1
fi

TMP="$(mktemp -d)"
PID=""
cleanup() {
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

# USB storage is the ONLY mass-storage device; no NIC, persistent host disks,
# host directory mounts, or wallet keys enter the VM.
qemu-system-x86_64 \
    -machine q35,accel=tcg -cpu max -smp 2 -m 1536 \
    -bios "$OVMF" \
    -display none -monitor none -serial "file:$TMP/serial.log" \
    -net none -no-reboot \
    -device qemu-xhci,id=xhci \
    -drive if=none,id=walletdisk,format=raw,file="$IMAGE" \
    -device usb-storage,bus=xhci.0,drive=walletdisk,bootindex=1 \
    > "$TMP/qemu.log" 2>&1 &
PID=$!

count=0
while [ "$count" -lt 120 ]; do
    if grep -q 'USB_WALLET_UEFI_AUDIT_OK' "$TMP/serial.log" 2>/dev/null; then
        echo "PASS: OVMF booted generated USB GPT image and guest startup audit succeeded"
        exit 0
    fi
    if grep -q 'USB_WALLET_UEFI_AUDIT_LOCKDOWN' "$TMP/serial.log" 2>/dev/null; then
        echo "ERROR: guest booted but startup audit entered LOCKDOWN" >&2
        tail -70 "$TMP/serial.log" >&2 || true
        exit 1
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
tail -70 "$TMP/serial.log" >&2 || true
tail -70 "$TMP/qemu.log" >&2 || true
exit 1
