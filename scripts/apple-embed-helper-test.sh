#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/release"
printf 'helper' > "$work/release/hasp-nmh"
chmod +x "$work/release/hasp-nmh"

embed() {
  CONFIGURATION=Release CODE_SIGNING_ALLOWED=NO BUILT_PRODUCTS_DIR="$work/out" CONTENTS_FOLDER_PATH=c \
    HASP_NMH_BINARY="$1" bash "$root/scripts/apple-embed-helper.sh" >/dev/null 2>&1
}

embed "$work/release/hasp-nmh"
cp "$work/release/hasp-nmh" "$work/dev"
printf 'gchilemfcapcihefglfdhgihpcjcdogp' >> "$work/release/hasp-nmh"
if embed "$work/release/hasp-nmh"; then echo "release embedded a dev-extension helper" >&2; exit 1; fi
if embed "$work/dev"; then echo "release embedded a non-release helper" >&2; exit 1; fi
