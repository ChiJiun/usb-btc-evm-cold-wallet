#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$ROOT/infra/reproducible.env"

OUT="$ROOT/build/output"
RESULTS="$ROOT/build/reproducibility"
mkdir -p "$RESULTS"

snapshot() {
	run="$1"
	(
		cd "$OUT/images"
		sha256sum usb-cold-wallet.img bzImage
	) > "$RESULTS/run-$run.sha256"
}

build_once() {
	run="$1"
	rm -rf "$OUT"
	test ! -e "$OUT"
	SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" "$ROOT/scripts/build_image.sh"
	snapshot "$run"
}

echo "Reproducibility check: two independent clean rebuilds at canonical Buildroot O=build/output"
build_once 1
build_once 2

if ! cmp -s "$RESULTS/run-1.sha256" "$RESULTS/run-2.sha256"; then
	echo "ERROR: clean builds are not bit-for-bit reproducible" >&2
	diff -u "$RESULTS/run-1.sha256" "$RESULTS/run-2.sha256" >&2 || true
	exit 1
fi

cat "$RESULTS/run-2.sha256"
echo "PASS: usb-cold-wallet.img and bzImage are bit-for-bit reproducible across independent clean rebuilds"
