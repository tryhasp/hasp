#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root/apps/apple"
paths=(Packages/Hasp/Package.swift Packages/Hasp/Sources/HaspQuickAccessCore Packages/Hasp/Sources/HaspDesign Packages/Hasp/Sources/HaspKit Packages/Hasp/Sources/HaspPlatform Packages/Hasp/Sources/HaspUI Packages/Hasp/Sources/HaspProvider Packages/Hasp/Sources/HaspProviderUI Packages/Hasp/Tests App UITests PhoneUITests)

swift format lint --strict -r "${paths[@]}"

comments=$(grep -rnE '^[[:space:]]*//([^/]|$)' "${paths[@]}" | grep -vE '// (Why: |swift-tools-version|swift-format-ignore)' || true)
if [ -n "$comments" ]; then
  echo "$comments" >&2
  exit 1
fi

if grep -rnE '\b(print|dump|NSLog|debugPrint)\(|// MARK|TODO|FIXME' "${paths[@]}"; then
  exit 1
fi
