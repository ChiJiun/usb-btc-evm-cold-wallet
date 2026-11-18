#!/bin/sh
set -eu

BOARD_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set for reproducible image generation}"

# The files copied into the EFI FAT filesystem otherwise inherit build-time
# mtimes. Normalize them before genimage/mtools serializes directory entries.
find "$BINARIES_DIR/efi-part" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
touch -h -d "@$SOURCE_DATE_EPOCH" "$BINARIES_DIR/bzImage"

support/scripts/genimage.sh -c "$BOARD_DIR/genimage.cfg"

IMAGE="$BINARIES_DIR/usb-cold-wallet.img"
test -s "$IMAGE"
sha256sum "$IMAGE" > "$BINARIES_DIR/usb-cold-wallet.img.sha256"
sha256sum "$BINARIES_DIR/bzImage" > "$BINARIES_DIR/bzImage.sha256"

echo "Built: $IMAGE"
cat "$BINARIES_DIR/usb-cold-wallet.img.sha256"
