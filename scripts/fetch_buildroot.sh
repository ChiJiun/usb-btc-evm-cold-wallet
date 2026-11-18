#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$ROOT/infra/buildroot.env"

CACHE="$ROOT/build/cache"
DEST="$ROOT/build/buildroot"
ARCHIVE="$CACHE/buildroot-$BUILDROOT_VERSION.tar.xz"
mkdir -p "$CACHE"

if [ ! -f "$ARCHIVE" ]; then
	curl -fL "$BUILDROOT_URL" -o "$ARCHIVE"
fi
printf '%s  %s\n' "$BUILDROOT_SHA256" "$ARCHIVE" | sha256sum -c -

if [ ! -f "$DEST/Makefile" ]; then
	rm -rf "$DEST"
	mkdir -p "$DEST"
	tar -xJf "$ARCHIVE" --strip-components=1 -C "$DEST"
fi

printf '%s\n' "$DEST"
