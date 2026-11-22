#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OUT="$ROOT/build/output"
IMAGE="$OUT/images/usb-cold-wallet.img"
# Audit the exact kernel configuration that produced the shipped bzImage.
# Reject missing or ambiguous Linux build directories instead of accepting
# whichever .config `find` happened to return first.
set -- "$OUT"/build/linux-*/.config
if [ "$#" -ne 1 ] || [ ! -s "$1" ]; then
	echo "ERROR: expected exactly one built Linux kernel .config" >&2
	exit 1
fi
KCONFIG="$1"
BUILT_KERNEL="${KCONFIG%/.config}/arch/x86/boot/bzImage"
if [ ! -s "$BUILT_KERNEL" ] || ! cmp -s "$BUILT_KERNEL" "$OUT/images/bzImage"; then
	echo "ERROR: audited kernel .config does not match the shipped bzImage" >&2
	exit 1
fi
printf 'Auditing built kernel config: %s\n' "$KCONFIG"
# The resolved .config is authoritative: the input fragment may be overridden
# by dependency resolution. Print only relevant public build configuration.
grep -E '^(CONFIG_NET=|# CONFIG_NET is not set|CONFIG_USB_STORAGE=|# CONFIG_USB_STORAGE is not set|CONFIG_VFAT_FS=|# CONFIG_VFAT_FS is not set)' "$KCONFIG" || true

BR_CONFIG="$OUT/.config"
test -s "$BR_CONFIG" || { echo "ERROR: missing resolved Buildroot config" >&2; exit 1; }
# Buildroot enables CONFIG_NET in linux.mk when mdev is selected, even if
# the source kernel defconfig requests CONFIG_NET=n. Verify the rootfs device
# manager that actually drove the complete image build.
grep -q '^BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_DEVTMPFS=y$' "$BR_CONFIG" || {
	echo "ERROR: Buildroot is not using devtmpfs-only device management" >&2
	exit 1
}
if grep -Eq '^BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_(MDEV|EUDEV)=y$' "$BR_CONFIG"; then
	echo "ERROR: userspace device manager may re-enable kernel networking" >&2
	exit 1
fi

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
grep -q '^CONFIG_USB_STORAGE=yif grep -Eq '^CONFIG_(ATA|BLK_DEV_NVME|NVME_CORE|MMC|VIRTIO_BLK)=y$' "$KCONFIG"; then
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

# GitHub-hosted Ubuntu runners provide passwordless sudo. Run the privileged
# read-only loopback audit when available without weakening local verification.
if [ "${CI:-}" = "true" ] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
	sudo -n sh "$ROOT/scripts/verify_single_usb_loopback.sh" "$IMAGE"
fi

echo "Static image verification passed."
 "$KCONFIG"
grep -q '^CONFIG_VFAT_FS=yif grep -Eq '^CONFIG_(ATA|BLK_DEV_NVME|NVME_CORE|MMC|VIRTIO_BLK)=y$' "$KCONFIG"; then
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

# GitHub-hosted Ubuntu runners provide passwordless sudo. Run the privileged
# read-only loopback audit when available without weakening local verification.
if [ "${CI:-}" = "true" ] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
	sudo -n sh "$ROOT/scripts/verify_single_usb_loopback.sh" "$IMAGE"
fi

echo "Static image verification passed."
 "$KCONFIG"

# The native framebuffer frontend (#79) consumes /dev/fb0 plus kernel input
# events directly. Audit the resolved kernel that produced the shipped bzImage,
# rather than trusting only the source config fragment.
for symbol in \
    CONFIG_INPUT CONFIG_INPUT_KEYBOARD CONFIG_KEYBOARD_ATKBD CONFIG_INPUT_EVDEV \
    CONFIG_HID CONFIG_HID_GENERIC CONFIG_USB_HID \
    CONFIG_VT CONFIG_VT_CONSOLE CONFIG_FRAMEBUFFER_CONSOLE CONFIG_FB \
    CONFIG_DRM CONFIG_DRM_SIMPLEDRM CONFIG_DRM_FBDEV_EMULATION; do
	grep -q "^$symbol=y$" "$KCONFIG" || {
		echo "ERROR: required local display/input kernel capability missing: $symbol" >&2
		exit 1
	}
done
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

# GitHub-hosted Ubuntu runners provide passwordless sudo. Run the privileged
# read-only loopback audit when available without weakening local verification.
if [ "${CI:-}" = "true" ] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
	sudo -n sh "$ROOT/scripts/verify_single_usb_loopback.sh" "$IMAGE"
fi

echo "Static image verification passed."
