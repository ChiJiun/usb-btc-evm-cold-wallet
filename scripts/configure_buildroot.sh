#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$ROOT/infra/reproducible.env"
"$ROOT/scripts/check_host.sh"
BR="$("$ROOT/scripts/fetch_buildroot.sh")"
OUT="$ROOT/build/output"
DL="$ROOT/build/dl"
EXT="$ROOT/buildroot-external"
mkdir -p "$OUT" "$DL"

SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" BR2_DL_DIR="$DL" \
	make -C "$BR" O="$OUT" BR2_EXTERNAL="$EXT" usb_wallet_x86_64_defconfig

echo "Buildroot configuration: $OUT/.config"
