#!/bin/sh
set -eu

BOARD_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

# Install a stdlib-only, offline GPT/FAT media identifier. The BusyBox
# blkid applet does not implement util-linux's -t/-o/-s options.
mkdir -p "$TARGET_DIR/usr/libexec"
install -m 0755 "$BOARD_DIR/identify_media.py" \
    "$TARGET_DIR/usr/libexec/usb-wallet-identify-media"
install -m 0755 "$BOARD_DIR/framebuffer-demo.py" \
    "$TARGET_DIR/usr/libexec/usb-wallet-framebuffer-demo"

mkdir -p "$BINARIES_DIR/efi-part/EFI/BOOT"
cp "$BOARD_DIR/grub.cfg" "$BINARIES_DIR/efi-part/EFI/BOOT/grub.cfg"

# Replace Buildroot's login/getty with a single-purpose console. BusyBox sh
# remains for init scripts but is not presented as the normal user interface.
if [ -f "$TARGET_DIR/etc/inittab" ]; then
	sed -i '/tty[1-9].*getty/d' "$TARGET_DIR/etc/inittab"
	printf '\ntty1::respawn:/usr/bin/usb-wallet-console\n' >> "$TARGET_DIR/etc/inittab"
fi

# Build-time guardrail: no common networking clients may survive in the image.
for tool in ip ifconfig route ping ping6 wget nc netcat udhcpc udhcpd telnet ftpget ftpput; do
	if [ -e "$TARGET_DIR/bin/$tool" ] || [ -e "$TARGET_DIR/sbin/$tool" ] || \
	   [ -e "$TARGET_DIR/usr/bin/$tool" ] || [ -e "$TARGET_DIR/usr/sbin/$tool" ]; then
		echo "ERROR: networking tool survived image construction: $tool" >&2
		exit 1
	fi
done

# No persisted shell history or pre-created wallet data in release image.
rm -f "$TARGET_DIR/root/.ash_history" "$TARGET_DIR/root/.bash_history"
if find "$TARGET_DIR" -type f \( -name '*.vault' -o -name '*.seed' -o -name '*.mnemonic' -o -name '*.key' \) | grep -q .; then
	echo "ERROR: secret-looking file included in target rootfs" >&2
	exit 1
fi
