#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$root/run/apple-ui
derived=$root/run/dd-mac

rm -rf "$work"
mkdir -p "$work"

xcodegen generate --spec "$root/apps/apple/project.yml" >/dev/null

trap '"$root/scripts/apple-ui-fixture.sh" stop "$work/fixture"' EXIT
"$root/scripts/apple-ui-fixture.sh" start "$work/fixture" >/dev/null

TEST_RUNNER_HASP_UITEST_FIXTURE="$work/fixture/fixture.json" \
TEST_RUNNER_HASP_SHOTS_DIR="${HASP_SHOTS_OUT:-$work/shots}" \
  xcodebuild test -project "$root/apps/apple/Hasp.xcodeproj" -scheme Hasp \
  -destination 'platform=macOS' -derivedDataPath "$derived" \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= \
  -parallel-testing-enabled NO
