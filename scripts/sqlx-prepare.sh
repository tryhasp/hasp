#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

scratch="$root/run/sqlx-prepare"
rm -rf "$scratch" apps/server/.sqlx
mkdir -p "$scratch" apps/server/.sqlx
for migration in apps/server/migrations/*.sql; do
  sqlite3 "$scratch/dev.db" < "$migration"
done

touch apps/server/src/lib.rs
DATABASE_URL="sqlite://$scratch/dev.db" SQLX_OFFLINE_DIR="$root/apps/server/.sqlx" \
  cargo check -p hasp-server --all-targets --all-features --locked
rm -rf "$scratch"
