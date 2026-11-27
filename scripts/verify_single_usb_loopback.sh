#!/bin/sh
# Privileged host-side verification of the generated GPT image. This mounts the
# image read-only only; it never touches a physical USB device.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
IMAGE="${1:-$ROOT/build/output/images/usb-cold-wallet.img}"
test -s "$IMAGE"
command -v losetup >/dev/null
command -v blkid >/dev/null
command -v mount >/dev/null
command -v umount >/dev/null

[ "$(id -u)" -eq 0 ] || {
    echo "ERROR: loopback audit requires root (use sudo on the generated image)" >&2
    exit 1
}

TMP="$(mktemp -d)"
LOOP=""
cleanup() {
    status=$?
    for target in "$TMP/boot" "$TMP/vault" "$TMP/transfer"; do
        mountpoint -q "$target" 2>/dev/null && umount "$target" || true
    done
    [ -z "$LOOP" ] || losetup -d "$LOOP" 2>/dev/null || true
    rm -rf "$TMP"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$TMP/boot" "$TMP/vault" "$TMP/transfer"
LOOP="$(losetup --find --show --partscan --read-only "$IMAGE")"
for _ in 1 2 3 4 5; do
    [ -b "${LOOP}p3" ] && break
    sleep 1
done

for index in 1 2 3; do
    [ -b "${LOOP}p$index" ] || {
        echo "ERROR: missing loop partition p$index" >&2
        exit 1
    }
done
[ ! -b "${LOOP}p4" ] || {
    echo "ERROR: unexpected fourth partition" >&2
    exit 1
}

check_field() {
    device="$1"
    field="$2"
    expected="$3"
    actual="$(blkid -s "$field" -o value "$device" 2>/dev/null || true)"
    [ "$actual" = "$expected" ] || {
        echo "ERROR: $device $field=$actual expected=$expected" >&2
        exit 1
    }
}

check_field "${LOOP}p1" LABEL USBCOLD_EFI
check_field "${LOOP}p2" LABEL COLD_VAULT
check_field "${LOOP}p3" LABEL TX_TRANSFER
check_field "${LOOP}p1" PARTUUID e2bd6d1b-8de5-502d-a897-c53a8e60f46b
check_field "${LOOP}p2" PARTUUID 18f1c36f-d5c0-5052-9cd2-03e9c2a48f00
check_field "${LOOP}p3" PARTUUID 42f6f5d4-9310-5ac3-b5d4-1540cbe7d6b4

# Read-only mounts prove the filesystem boundaries and seeded Windows-visible
# directory layout without mutating the reproducible image.
mount -t vfat -o ro,noexec,nodev,nosuid "${LOOP}p1" "$TMP/boot"
mount -t vfat -o ro,noexec,nodev,nosuid "${LOOP}p2" "$TMP/vault"
mount -t vfat -o ro,noexec,nodev,nosuid "${LOOP}p3" "$TMP/transfer"

test -f "$TMP/boot/bzImage"
test -d "$TMP/transfer/COMPANION"
test -d "$TMP/transfer/TRANSACTIONS"
test -f "$TMP/transfer/COMPANION/README.txt"
test ! -e "$TMP/transfer/COMPANION/usb-cold-companion.exe" || {
    echo "ERROR: unverified Windows executable unexpectedly embedded by base image build" >&2
    exit 1
}

echo "PASS: read-only Linux loopback audit verified boot/vault/transfer boundaries"
