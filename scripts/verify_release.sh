#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <tag> <source-sha> <workflow-sha> <asset>" >&2
    exit 2
fi

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
command -v gh >/dev/null 2>&1 || {
    echo "ERROR: gh is required" >&2
    exit 1
}
command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: python3 is required" >&2
    exit 1
}

exec python3 "$ROOT/scripts/verify_release_assets.py" \
    --tag "$1" \
    --commit "$2" \
    --workflow-sha "$3" \
    --asset "$4"
