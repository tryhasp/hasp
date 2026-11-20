#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

status=0
for package in hasp-crypto hasp-proto hasp-core hasp-uniffi hasp-wasm hasp-boundary hasp-server hasp-cli hasp-nmh hasp-replay; do
  if cargo tree --locked -e normal,build,features -p "$package" | grep -qw 'testing'; then
    echo "the testing feature is enabled in a production build of $package" >&2
    status=1
  fi
done
exit $status
