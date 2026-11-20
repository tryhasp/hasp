#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
target=${CARGO_TARGET_DIR:-$root/target}
out=$root/packages/wasm/generated

cd "$root"
CARGO_PROFILE_RELEASE_STRIP=debuginfo cargo build --locked --release -p hasp-wasm --features "${HASP_FEATURES-replay}" --target wasm32-unknown-unknown
rm -rf "$out"
wasm-bindgen --target web --typescript --out-dir "$out" --out-name hasp_wasm \
  "$target/wasm32-unknown-unknown/release/hasp_wasm.wasm"
