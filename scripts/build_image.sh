#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
MODE="$*"
[ -n "$MODE" ] || MODE="build"

"$ROOT/scripts/fetch_wheelhouse.sh"
"$ROOT/scripts/configure_buildroot.sh"

BR="$ROOT/build/buildroot"
OUT="$ROOT/build/output"
DL="$ROOT/build/dl"
EXT="$ROOT/buildroot-external"

case "$MODE" in
	--download-only)
		BR2_DL_DIR="$DL" make -C "$BR" O="$OUT" BR2_EXTERNAL="$EXT" source
		exit 0
		;;
	build)
		;;
	*)
		echo "usage: $0 [--download-only]" >&2
		exit 2
		;;
esac

BR2_DL_DIR="$DL" make -C "$BR" O="$OUT" BR2_EXTERNAL="$EXT"
"$ROOT/scripts/verify_image.sh"
