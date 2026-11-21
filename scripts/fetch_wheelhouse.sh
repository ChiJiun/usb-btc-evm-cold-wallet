#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$ROOT/infra/embit.env"

VENV="$ROOT/build/bootstrap-venv"
WHEELHOUSE="$ROOT/build/wheelhouse"
mkdir -p "$ROOT/build" "$WHEELHOUSE"

if (
	cd "$WHEELHOUSE" 2>/dev/null &&
	sha256sum -c "$ROOT/infra/wheelhouse.sha256" >/dev/null 2>&1
); then
	echo "Hash-locked target wheelhouse already verified: $WHEELHOUSE"
	exit 0
fi

if [ ! -x "$VENV/bin/python" ]; then
	python3 -m venv "$VENV"
fi
rm -rf "$WHEELHOUSE"
mkdir -p "$WHEELHOUSE"

"$VENV/bin/python" -m pip download \
	--disable-pip-version-check \
	--require-hashes \
	--no-deps \
	--only-binary=:all: \
	--platform manylinux2014_x86_64 \
	--implementation cp \
	--python-version 3.14 \
	--abi cp314 \
	-r "$ROOT/infra/wheelhouse-requirements.txt" \
	-d "$WHEELHOUSE"

curl -fL "$EMBIT_URL" -o "$WHEELHOUSE/embit-$EMBIT_VERSION.tar.gz"
printf '%s  %s\n' "$EMBIT_SHA256" "$WHEELHOUSE/embit-$EMBIT_VERSION.tar.gz" | sha256sum -c -

(
	cd "$WHEELHOUSE"
	sha256sum -c "$ROOT/infra/wheelhouse.sha256"
)
echo "Hash-locked target wheelhouse ready: $WHEELHOUSE"
