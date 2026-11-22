#!/bin/sh
set -eu

BOARD_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

# Install a stdlib-only, offline GPT/FAT media identifier. The BusyBox
# blkid applet does not implement util-linux's -t/-o/-s options.
mkdir -p "$TARGET_DIR/usr/libexec"
install -m 0755 "$BOARD_DIR/identify_media.py"     "$TARGET_DIR/usr/libexec/usb-wallet-identify-media"

mkdir -p "$BINARIES_DIR/efi-part/EFI/BOOT"
cp "$BOARD_DIR/grub.cfg" "$BINARIES_DIR/efi-part/EFI/BOOT/grub.cfg"

# CONFIG_NET=n removes AF_UNIX, so an X11/Tk session cannot work even with
# -nolisten tcp. tty1 is rendered by the kernel VT/fbcon stack and needs no
# socket family. Keep the operator on the single-purpose audited appliance.
if [ -f "$TARGET_DIR/etc/inittab" ]; then
	# Remove every interactive login shell/getty, not only tty1. A root shell
	# would bypass the attended appliance UX even though the signer CLI itself
	# still has confirmation gates.
	sed -i -E '/getty|:(askfirst|respawn):.*\/bin\/(a|ba|z)?sh/d' "$TARGET_DIR/etc/inittab"
	printf '\ntty1::respawn:/usr/bin/usb-wallet-gui-session\n' >> "$TARGET_DIR/etc/inittab"
	if grep -Eq 'getty|:(askfirst|respawn):.*\/bin\/(a|ba|z)?sh' "$TARGET_DIR/etc/inittab"; then
		echo "ERROR: interactive getty or shell survived appliance lockdown" >&2
		grep -E 'getty|:(askfirst|respawn):.*\/bin\/(a|ba|z)?sh' "$TARGET_DIR/etc/inittab" >&2 || true
		exit 1
	fi
fi

for required in \
    "$TARGET_DIR/usr/bin/usb-wallet-console" \
    "$TARGET_DIR/usr/bin/usb-wallet-gui-session"; do
	if [ ! -x "$required" ]; then
		echo "ERROR: required appliance launcher missing or not executable: $required" >&2
		ls -l "$required" 2>/dev/null || true
		exit 1
	fi
done

# Fail the build if the impossible X11/Tk path is accidentally reintroduced.
for path in     "$TARGET_DIR/usr/bin/xinit"     "$TARGET_DIR/usr/bin/Xfbdev"     "$TARGET_DIR/usr/bin/Xorg"; do
	if [ -e "$path" ]; then
		echo "ERROR: X11 runtime present while CONFIG_NET=n: $path" >&2
		exit 1
	fi
done
if find "$TARGET_DIR/usr/lib/python3.14" -name '_tkinter*.so' -print -quit 2>/dev/null | grep -q .; then
	echo "ERROR: tkinter extension present while CONFIG_NET=n" >&2
	exit 1
fi

# Build-time guardrail: no common networking clients may survive in the image.
for tool in ip ifconfig route ping ping6 wget nc netcat udhcpc udhcpd telnet ftpget ftpput; do
	if [ -e "$TARGET_DIR/bin/$tool" ] || [ -e "$TARGET_DIR/sbin/$tool" ] || 	   [ -e "$TARGET_DIR/usr/bin/$tool" ] || [ -e "$TARGET_DIR/usr/sbin/$tool" ]; then
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
