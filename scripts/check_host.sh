#!/bin/sh
set -eu

missing=""
for tool in make gcc g++ patch rsync perl tar cpio file bc awk sed grep gzip bzip2 xz python3 curl wget sha256sum; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		missing="$missing $tool"
	fi
done

if [ -n "$missing" ]; then
	echo "Missing Buildroot host tools:$missing" >&2
	echo "Install them on the BUILD HOST only; do not install anything into the cold-wallet target image." >&2
	echo "Ubuntu/Debian reference: build-essential make gcc g++ patch rsync perl tar cpio file bc gawk gzip bzip2 xz-utils python3 python3-venv curl wget" >&2
	exit 1
fi
