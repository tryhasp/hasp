#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${HASP_SHOTS_OUT:-$root/run/m2-shots/app}
work=$root/run/apple-shots
derived=$root/run/dd-mac

rm -rf "$work" "$out"
mkdir -p "$work" "$out"

xcodegen generate --spec "$root/apps/apple/project.yml" >/dev/null
xcodebuild build -project "$root/apps/apple/Hasp.xcodeproj" -scheme Hasp -configuration Debug \
  -destination 'generic/platform=macOS' -derivedDataPath "$derived" CODE_SIGNING_ALLOWED=NO >"$work/build.log" 2>&1 \
  || { tail -30 "$work/build.log" >&2; exit 1; }

defaults delete kr.jmo.hasp hasp.quickAccessIntroSeen 2>/dev/null || true
trap '"$root/scripts/apple-ui-fixture.sh" stop "$work/fixture"' EXIT
"$root/scripts/apple-ui-fixture.sh" start "$work/fixture" seed >/dev/null

HASP_SHOTS_NATIVE=${HASP_SHOTS_NATIVE:-1} HASP_DATA_DIR="$work/data" HASP_MEMORY_STORE=1 HASP_FIXTURE="$work/fixture/fixture.json" HASP_SHOTS_DIR="$out" \
  "$derived/Build/Products/Debug/Hasp.app/Contents/MacOS/Hasp" -AppleLanguages "(ko)" -AppleLocale ko_KR \
  -hasp.quickAccessIntroSeen NO &
app=$!
for _ in $(seq 1 180); do
  kill -0 "$app" 2>/dev/null || break
  sleep 1
done
kill "$app" 2>/dev/null || true
ls "$out"
