#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$ROOT/infra/reproducible.env"

OUT1="$ROOT/build/output-repro-1"
OUT2="$ROOT/build/output"
RESULTS="$ROOT/build/reproducibility"
mkdir -p "$RESULTS"

snapshot() {
	run="$1"
	out="$2"
	(
		cd "$out/images"
		sha256sum usb-cold-wallet.img bzImage
	) > "$RESULTS/run-$run.sha256"
}

build_once() {
	run="$1"
	out="$2"
	rm -rf "$out"
	BUILD_OUTPUT_DIR="$out" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" "$ROOT/scripts/build_image.sh"
	snapshot "$run" "$out"
}

if [ "$OUT1" = "$OUT2" ]; then
	echo "ERROR: reproducibility builds must use distinct Buildroot output directories" >&2
	exit 1
fi

echo "Reproducibility check: two clean builds with separate Buildroot O= directories"
rm -rf "$OUT1" "$OUT2"
build_once 1 "$OUT1"
build_once 2 "$OUT2"

if ! cmp -s "$RESULTS/run-1.sha256" "$RESULTS/run-2.sha256"; then
	echo "ERROR: clean builds are not bit-for-bit reproducible" >&2
	diff -u "$RESULTS/run-1.sha256" "$RESULTS/run-2.sha256" >&2 || true
	exit 1
fi

cat "$RESULTS/run-2.sha256"
rm -rf "$OUT1"
echo "PASS: usb-cold-wallet.img and bzImage are bit-for-bit reproducible across separate output directories"
