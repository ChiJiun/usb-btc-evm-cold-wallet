#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OUT="$ROOT/build/output"
IMAGE="$OUT/images/usb-cold-wallet.img"
KCONFIG="$(find "$OUT/build" -maxdepth 2 -path '*/linux-*/.config' -print -quit)"

test -n "$KCONFIG"
test -s "$IMAGE"
(
	cd "$OUT/images"
	sha256sum -c usb-cold-wallet.img.sha256
)

grep -q '^# CONFIG_NET is not set$' "$KCONFIG" || {
	echo "ERROR: kernel networking subsystem is not disabled: $KCONFIG" >&2
	echo "Configured network-related kernel symbols:" >&2
	grep -E '^(CONFIG_(NET|INET|UNIX|PACKET|NETDEVICES|SCSI_NETLINK)=|# CONFIG_(NET|INET|UNIX|PACKET|NETDEVICES|SCSI_NETLINK) is not set$)' "$KCONFIG" >&2 || true
	echo "Original network policy:" >&2
	grep -E '^(CONFIG_NET=|# CONFIG_NET is not set$)' "$ROOT/buildroot-external/board/usb-wallet/linux.config" >&2 || true
	exit 1
}
grep -q '^CONFIG_USB_STORAGE=y$' "$KCONFIG"
grep -q '^CONFIG_VFAT_FS=y$' "$KCONFIG"
if grep -Eq '^CONFIG_(ATA|BLK_DEV_NVME|NVME_CORE|MMC|VIRTIO_BLK)=y$' "$KCONFIG"; then
	echo "ERROR: internal/non-USB block storage driver unexpectedly enabled" >&2
	exit 1
fi

test -x "$OUT/target/usr/bin/usb-wallet-console"
test -x "$OUT/target/usr/bin/usb-cold-wallet"
for tool in ip ifconfig route ping wget nc netcat udhcpc telnet; do
	for dir in bin sbin usr/bin usr/sbin; do
		test ! -e "$OUT/target/$dir/$tool" || {
			echo "ERROR: networking tool exists in target: $dir/$tool" >&2
			exit 1
		}
	done
done

python3 "$ROOT/scripts/verify_image.py" "$IMAGE"
echo "Static image verification passed."
