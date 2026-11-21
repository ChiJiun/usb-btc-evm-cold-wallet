#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
"$ROOT/scripts/fetch_wheelhouse.sh"
"$ROOT/scripts/configure_buildroot.sh"

BR="$ROOT/build/buildroot"
OUT="$ROOT/build/output"
DL="$ROOT/build/dl"
EXT="$ROOT/buildroot-external"

BR2_DL_DIR="$DL" make -C "$BR" O="$OUT" BR2_EXTERNAL="$EXT" source

echo "All Buildroot sources fetched into: $DL"
echo "You may now disconnect networking before scripts/build_image.sh."
