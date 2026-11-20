#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
package=$root/apps/apple/Packages/Hasp
target=${CARGO_TARGET_DIR:-$root/target}
work=$root/run/apple-xcframework
slices=(aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim)

cd "$root"
rm -rf "$work"
mkdir -p "$work/headers"

cargo build --locked -p hasp-uniffi --features bindgen --bin uniffi-bindgen
cargo build --locked -p hasp-uniffi --features "${HASP_FEATURES-replay}"
"$target/debug/uniffi-bindgen" generate \
  --library "$target/debug/libhasp_uniffi.a" \
  --language swift \
  --out-dir "$work/generated"

for slice in "${slices[@]}"; do
  CARGO_PROFILE_RELEASE_OPT_LEVEL=z cargo build --locked --release -p hasp-uniffi --features "${HASP_FEATURES-replay}" --target "$slice"
done

cp "$work/generated/hasp_uniffiFFI.h" "$work/headers/"
cp "$work/generated/hasp_uniffiFFI.modulemap" "$work/headers/module.modulemap"
mkdir -p "$package/Sources/HaspFFI/Generated"
cp "$work/generated/hasp_uniffi.swift" "$package/Sources/HaspFFI/Generated/hasp_uniffi.swift"

rm -rf "$package/Frameworks/HaspFFIBinary.xcframework"
mkdir -p "$package/Frameworks"
args=()
for slice in "${slices[@]}"; do
  args+=(-library "$target/$slice/release/libhasp_uniffi.a" -headers "$work/headers")
done
xcodebuild -create-xcframework "${args[@]}" -output "$package/Frameworks/HaspFFIBinary.xcframework"
