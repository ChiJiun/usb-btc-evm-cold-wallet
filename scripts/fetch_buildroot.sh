#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$ROOT/infra/buildroot.env"

CACHE="$ROOT/build/cache"
DEST="$ROOT/build/buildroot"
ARCHIVE="$CACHE/buildroot-$BUILDROOT_VERSION.tar.xz"
SIGNATURE="$ARCHIVE.sign"
KEY="$ROOT/infra/buildroot-release-key.asc"
mkdir -p "$CACHE"

if [ ! -f "$ARCHIVE" ]; then
	curl -fL "$BUILDROOT_URL" -o "$ARCHIVE"
fi
if [ ! -f "$SIGNATURE" ]; then
	curl -fL "$BUILDROOT_SIG_URL" -o "$SIGNATURE"
fi

printf '%s  %s\n' "$BUILDROOT_SIG_SHA256" "$SIGNATURE" | sha256sum -c - >&2
printf '%s  %s\n' "$BUILDROOT_RELEASE_KEY_SHA256" "$KEY" | sha256sum -c - >&2

KEY_FINGERPRINT="$(
	gpg --batch --with-colons --import-options show-only --import "$KEY" 2>/dev/null |
		awk -F: '$1 == "fpr" { print $10; exit }'
)"
if [ "$KEY_FINGERPRINT" != "$BUILDROOT_RELEASE_KEY_FINGERPRINT" ]; then
	echo "ERROR: Buildroot release-key fingerprint mismatch" >&2
	exit 1
fi

VERIFY_DIR="$(mktemp -d "$CACHE/buildroot-gpgv.XXXXXX")"
trap 'rm -rf "$VERIFY_DIR"' 0 HUP INT TERM
gpg --batch --dearmor < "$KEY" > "$VERIFY_DIR/keyring.gpg"
gpgv --keyring "$VERIFY_DIR/keyring.gpg" "$SIGNATURE"

# The .sign file is a clear-signed release manifest, not a detached signature
# over the archive itself. Only trust its SHA-256 after gpgv succeeds.
SIGNED_SHA256="$(
	awk -v file="buildroot-$BUILDROOT_VERSION.tar.xz" 		'$1 == "SHA256:" && $3 == file { print $2; exit }' "$SIGNATURE"
)"
if [ "$SIGNED_SHA256" != "$BUILDROOT_SHA256" ]; then
	echo "ERROR: signed Buildroot SHA-256 does not match pinned SHA-256" >&2
	exit 1
fi
printf '%s  %s\n' "$SIGNED_SHA256" "$ARCHIVE" | sha256sum -c - >&2

if [ ! -f "$DEST/Makefile" ]; then
	rm -rf "$DEST"
	mkdir -p "$DEST"
	tar -xJf "$ARCHIVE" --strip-components=1 -C "$DEST"
fi

printf '%s\n' "$DEST"
