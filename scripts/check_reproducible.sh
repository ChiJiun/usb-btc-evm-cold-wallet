#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$ROOT/infra/reproducible.env"

OUT="$ROOT/build/output"
OUT1="$ROOT/build/output-repro-1"
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

build_clean() {
	run="$1"
	rm -rf "$OUT"
	test ! -e "$OUT"
	SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" "$ROOT/scripts/build_image.sh"
	snapshot "$run" "$OUT"
}

echo "Reproducibility check: two isolated clean output trees built at canonical O=build/output"
rm -rf "$OUT1"
build_clean 1

# Preserve the complete first generated tree, then make the canonical O= path
# absent before the second build. Both builds therefore see the same absolute
# build path without sharing any generated Buildroot state.
mv "$OUT" "$OUT1"
test ! -e "$OUT"
(
	cd "$OUT1/images"
	sha256sum -c "$RESULTS/run-1.sha256"
)

build_clean 2

if ! cmp -s "$RESULTS/run-1.sha256" "$RESULTS/run-2.sha256"; then
	echo "ERROR: clean builds are not bit-for-bit reproducible" >&2
	diff -u "$RESULTS/run-1.sha256" "$RESULTS/run-2.sha256" >&2 || true
	exit 1
fi

cat "$RESULTS/run-2.sha256"
rm -rf "$OUT1"
echo "PASS: usb-cold-wallet.img and bzImage are bit-for-bit reproducible across isolated clean output trees"
