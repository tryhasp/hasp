#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
today=$(date -u +%F)
status=0
while read -r date; do
  if [[ "$date" < "$today" ]]; then
    echo "deny.toml: an entry expired on $date" >&2
    status=1
  fi
done < <(grep -oE 'expires [0-9]{4}-[0-9]{2}-[0-9]{2}' "$root/deny.toml" | cut -d' ' -f2)
exit $status
