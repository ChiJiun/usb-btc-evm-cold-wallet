#!/bin/sh
# Boot the exact generated USB image with OVMF, manually enter the dormant
# public-vector framebuffer POC, capture actual guest pixels, and exercise both
# positive review intent and cancellation. The guest has no NIC.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
IMAGE="$ROOT/build/output/images/usb-cold-wallet.img"
OUT="$ROOT/build/reproducibility"
SCREENSHOT="$OUT/framebuffer-gui.ppm"
METRICS="$OUT/framebuffer-metrics.txt"
ACTIONS="$OUT/framebuffer-actions.log"
test -s "$IMAGE"
command -v qemu-system-x86_64 >/dev/null
command -v python3 >/dev/null
mkdir -p "$OUT"
rm -f "$SCREENSHOT" "$METRICS" "$ACTIONS"

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
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        {
            echo "framebuffer POC QEMU verification failed"
            echo "--- serial tail ---"
            tail -100 "$TMP/serial.log" 2>/dev/null || true
            echo "--- qemu tail ---"
            tail -80 "$TMP/qemu.log" 2>/dev/null || true
        } >> "$ACTIONS" 2>/dev/null || true
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
START_MS="$(date +%s%3N)"

qemu-system-x86_64 \
    -machine q35,accel=tcg -cpu max -smp 2 -m 1536 \
    -drive if=pflash,unit=0,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,unit=1,format=raw,file="$TMP/ovmf-vars.fd" \
    -display none -serial "file:$TMP/serial.log" \
    -monitor "unix:$TMP/hmp.sock,server=on,wait=off" \
    -net none -no-reboot \
    -device qemu-xhci,id=xhci \
    -drive if=none,id=walletdisk,format=raw,snapshot=on,file="$IMAGE" \
    -device usb-storage,bus=xhci.0,drive=walletdisk,bootindex=1 \
    > "$TMP/qemu.log" 2>&1 &
PID=$!

wait_count() {
    marker="$1"
    expected="$2"
    limit="$3"
    count=0
    while [ "$count" -lt "$limit" ]; do
        found="$(grep -F -c "$marker" "$TMP/serial.log" 2>/dev/null || true)"
        if [ "$found" -ge "$expected" ]; then
            return 0
        fi
        if grep -q 'USB_WALLET_UEFI_AUDIT_LOCKDOWN' "$TMP/serial.log" 2>/dev/null; then
            echo "ERROR: guest startup audit entered LOCKDOWN" >&2
            return 1
        fi
        if ! kill -0 "$PID" 2>/dev/null; then
            echo "ERROR: QEMU exited while waiting for $marker" >&2
            return 1
        fi
        count=$((count + 1))
        sleep 1
    done
    echo "ERROR: timed out waiting for $marker count $expected" >&2
    return 1
}

hmp() {
    python3 - "$TMP/hmp.sock" "$@" <<'PY'
import socket
import sys
import time

path = sys.argv[1]
commands = sys.argv[2:]
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(100):
    try:
        client.connect(path)
        break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.05)
else:
    raise SystemExit("HMP socket unavailable")
client.settimeout(1.0)
try:
    client.recv(65536)
except TimeoutError:
    pass
for command in commands:
    client.sendall((command + "\n").encode("ascii"))
    time.sleep(0.15)
    try:
        client.recv(65536)
    except TimeoutError:
        pass
client.close()
PY
}

wait_count "USB_WALLET_CONSOLE_READY" 1 240
CONSOLE_MS="$(date +%s%3N)"
printf '%s\n' "console ready" >> "$ACTIONS"

hmp "sendkey 8" "sendkey ret"
wait_count "USB_WALLET_FB_POC_READY" 1 30
GUI_MS="$(date +%s%3N)"
READY_LINE="$(grep -F 'USB_WALLET_FB_POC_READY' "$TMP/serial.log" | tail -1)"
printf '%s\n' "$READY_LINE" >> "$ACTIONS"

hmp "screendump $TMP/framebuffer-gui.ppm"
python3 - "$TMP/framebuffer-gui.ppm" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
data = path.read_bytes()
match = re.match(br"P6\s+(\d+)\s+(\d+)\s+255\s", data)
if not match:
    raise SystemExit("invalid QEMU screendump PPM")
width, height = map(int, match.groups())
pixels = data[match.end():]
if width < 320 or height < 240 or len(pixels) != width * height * 3:
    raise SystemExit("unexpected QEMU screendump geometry")
if len(set(pixels)) < 4:
    raise SystemExit("QEMU screendump is visually uniform")
PY
cp "$TMP/framebuffer-gui.ppm" "$SCREENSHOT"
printf '%s\n' "actual QEMU screendump captured" >> "$ACTIONS"

# The fixed EVM ReviewPlan contains five pages. Exercise navigation and explicit
# acknowledgement on every page. DOWN is sent once on each page as an input-path
# smoke; host tests cover long-page mandatory scrolling.
page=1
while [ "$page" -le 5 ]; do
    hmp "sendkey down" "sendkey ret"
    if [ "$page" -lt 5 ]; then
        hmp "sendkey right"
    fi
    page=$((page + 1))
done
wait_count "USB_WALLET_FB_POC_INTENT reviewed=1 reason=reviewed" 1 30
printf '%s\n' "positive review intent observed" >> "$ACTIONS"

# After the demo restores KD_TEXT and returns to the appliance, launch it again
# and prove that Escape yields only a negative intent.
wait_count "USB_WALLET_CONSOLE_READY" 2 30
hmp "sendkey 8" "sendkey ret"
wait_count "USB_WALLET_FB_POC_READY" 2 30
hmp "sendkey esc"
wait_count "USB_WALLET_FB_POC_INTENT reviewed=0 reason=cancelled" 1 30
printf '%s\n' "cancel intent observed" >> "$ACTIONS"

BOOT_MS="$(printf '%s\n' "$READY_LINE" | sed -n 's/.*boot_ms=\([0-9][0-9]*\).*/\1/p')"
RSS_KB="$(printf '%s\n' "$READY_LINE" | sed -n 's/.*rss_kb=\([0-9][0-9]*\).*/\1/p')"
test -n "$BOOT_MS"
test -n "$RSS_KB"
{
    echo "evidence=actual QEMU/OVMF guest framebuffer screendump"
    echo "guest_network=-net none; kernel CONFIG_NET=n verified by image workflow"
    echo "image_bytes=$(wc -c < "$IMAGE" | tr -d ' ')"
    echo "guest_first_frame_boot_ms=$BOOT_MS"
    echo "runtime_maxrss_kb=$RSS_KB"
    echo "host_qemu_start_to_console_ms=$((CONSOLE_MS - START_MS))"
    echo "host_console_to_first_frame_ms=$((GUI_MS - CONSOLE_MS))"
    echo "screenshot_sha256=$(sha256sum "$SCREENSHOT" | awk '{print $1}')"
    echo "positive_intent=PASS"
    echo "cancel_intent=PASS"
} > "$METRICS"

echo "PASS: actual OVMF guest framebuffer POC rendered, reviewed, and cancelled without a guest NIC"
