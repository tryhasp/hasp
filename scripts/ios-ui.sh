#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$root/run/ios-ui
derived=${HASP_IOS_DERIVED:-$root/run/dd-ios}
device=${HASP_IOS_DEVICE:-iPhone 18 Pro}
shots=${HASP_SHOTS_OUT:-$root/run/m3-shots/ios}

rm -rf "$work"
mkdir -p "$work" "$shots"

xcodegen generate --spec "$root/apps/apple/project.yml" >/dev/null

trap '"$root/scripts/apple-ui-fixture.sh" stop "$work/fixture"' EXIT
"$root/scripts/apple-ui-fixture.sh" start "$work/fixture" seed >/dev/null

TEST_RUNNER_HASP_UITEST_FIXTURE="$work/fixture/fixture.json" \
TEST_RUNNER_HASP_SHOTS_DIR="$shots" \
  xcodebuild test -project "$root/apps/apple/Hasp.xcodeproj" -scheme HaspPhone \
  -destination "platform=iOS Simulator,name=$device" -derivedDataPath "$derived" \
  -parallel-testing-enabled NO CODE_SIGNING_ALLOWED=NO
