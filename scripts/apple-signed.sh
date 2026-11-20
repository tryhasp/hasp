#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
target=${CARGO_TARGET_DIR:-$root/target}
derived=${HASP_DERIVED:-$root/run/dd-signed}

team=${APPLE_TEAM_ID:-$(security find-certificate -c "Apple Development" -p \
  | openssl x509 -noout -subject -nameopt multiline | sed -n 's/^ *organizationalUnitName *= //p')}
[ -n "$team" ] || { echo "no Apple Development certificate in the keychain" >&2; exit 1; }

cd "$root"
HASP_TEAM_ID=$team cargo build --locked -p hasp-nmh --features dev-extension
xcodegen generate --spec apps/apple/project.yml >/dev/null

build=(xcodebuild build -project apps/apple/Hasp.xcodeproj -scheme Hasp -configuration Debug
  -destination 'platform=macOS,arch=arm64' -derivedDataPath "$derived" APPLE_TEAM_ID="$team" DEVELOPMENT_TEAM="$team"
  HASP_NMH_BINARY="$target/debug/hasp-nmh")

if ! "${build[@]}" -allowProvisioningUpdates HASP_ENTITLEMENTS_SUFFIX=-Signed; then
  echo "note: no development profile for the keychain access group (this Mac is not a registered device)." >&2
  echo "note: falling back to the Apple Development identity with the app group only; the Keychain store" >&2
  echo "note: is then the login keychain (password-only unlock, no Touch ID)." >&2
  "${build[@]}" HASP_ENTITLEMENTS_SUFFIX=-Group CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="Apple Development"
fi

app=$derived/Build/Products/Debug/Hasp.app
codesign --verify --deep --strict "$app"
codesign -d --entitlements - "$app" 2>&1 | grep -E 'application-groups|keychain-access-groups' -A2 || true
echo "$app"
