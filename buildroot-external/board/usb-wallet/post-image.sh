#!/bin/sh
set -eu

BOARD_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set for reproducible image generation}"

# The files copied into FAT filesystems otherwise inherit build-time mtimes.
# Normalize them before genimage/mtools serializes directory entries.
mkdir -p "$BINARIES_DIR/transfer-part/COMPANION" "$BINARIES_DIR/transfer-part/TRANSACTIONS"
cat > "$BINARIES_DIR/transfer-part/COMPANION/README.txt" <<'EOF'
USB BTC+EVM Cold Wallet — Windows Portable Companion location

Expected artifact path:
  COMPANION/usb-cold-companion.exe

This image intentionally does not synthesize or download the Windows executable.
The verified Portable Companion artifact is inserted by the release/artifact
integration pipeline after its own packaging checks. TRANSACTIONS/ is the only
shared transaction exchange directory used across Windows and the cold OS.

TESTNET DEVELOPMENT BUILD. A normal USB is writable by a hostile/admin Windows
host and does not provide Secure Boot or hardware write protection.
EOF
find "$BINARIES_DIR/efi-part" "$BINARIES_DIR/transfer-part" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
touch -h -d "@$SOURCE_DATE_EPOCH" "$BINARIES_DIR/bzImage"

support/scripts/genimage.sh -c "$BOARD_DIR/genimage.cfg"

IMAGE="$BINARIES_DIR/usb-cold-wallet.img"
test -s "$IMAGE"
sha256sum "$IMAGE" > "$BINARIES_DIR/usb-cold-wallet.img.sha256"
sha256sum "$BINARIES_DIR/bzImage" > "$BINARIES_DIR/bzImage.sha256"

echo "Built: $IMAGE"
cat "$BINARIES_DIR/usb-cold-wallet.img.sha256"
