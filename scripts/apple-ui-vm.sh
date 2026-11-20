#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
tart=${TART:-$(command -v tart || echo "$HOME/.local/bin/tart")}
vm=${HASP_UI_VM:-hasp-ui}
image=${HASP_UI_VM_IMAGE:-ghcr.io/cirruslabs/macos-tahoe-base:latest}
bin=${HASP_BIN_DIR:-${CARGO_TARGET_DIR:-$root/target}/debug}
work=$root/run/apple-ui-vm
share=$work/share
guest_share="/Volumes/My Shared Files/share"
guest_xcode="/Volumes/My Shared Files/xcode/Contents/Developer"
developer=$(xcode-select -p)
xcode_app=${developer%/Contents/Developer}
out=${HASP_VM_OUT:-$work/out}
shots=${HASP_VM_SHOTS:-$root/run/m2-shots/vm}

exec_vm() { "$tart" exec "$vm" "$@"; }

stop_vm() {
  "$tart" stop "$vm" >/dev/null 2>&1 || true
  [ -z "${runner:-}" ] || wait "$runner" 2>/dev/null || true
}

if ! "$tart" list --quiet | grep -qx "$vm"; then
  "$tart" clone "$image" "$vm"
fi

mkdir -p "$work" "$share/bin"
rm -rf "$out" "$share/dd" "$share/shots" "$share/result.xcresult" "$share/fixture"
mkdir -p "$out" "$shots"

xcodegen generate --spec "$root/apps/apple/project.yml" >/dev/null
xcodebuild build-for-testing -project "$root/apps/apple/Hasp.xcodeproj" -scheme Hasp -configuration Debug \
  -destination 'platform=macOS,arch=arm64' -derivedDataPath "$share/dd" \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= >"$work/build.log" 2>&1 \
  || { tail -30 "$work/build.log" >&2; exit 1; }
cp "$bin/haspd" "$bin/hasp" "$share/bin/"
cp "$root/scripts/apple-ui-fixture.sh" "$share/"
mkdir -p "$share/scripts"
mv "$share/apple-ui-fixture.sh" "$share/scripts/"

"$tart" run "$vm" --no-graphics --dir="xcode:$xcode_app:ro" --dir="share:$share" >"$work/vm.log" 2>&1 &
runner=$!
trap stop_vm EXIT

for _ in $(seq 1 120); do
  exec_vm true >/dev/null 2>&1 && break
  sleep 2
done
exec_vm true

until exec_vm test -x "$guest_xcode/usr/bin/xcodebuild"; do sleep 2; done
exec_vm sudo ln -sfn "/Volumes/My Shared Files/xcode" /Applications/Xcode.app
exec_vm sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
exec_vm sudo xcodebuild -license accept </dev/null
exec_vm sudo DevToolsSecurity -enable </dev/null >/dev/null
exec_vm sudo automationmodetool enable-automationmode-without-authentication </dev/null >/dev/null
exec_vm xcodebuild -runFirstLaunch </dev/null

xctestrun=$(cd "$share/dd/Build/Products" && ls ./*.xctestrun | head -1)
status=0
exec_vm bash -c "
  set -e
  cd '$guest_share'
  export HASP_BIN_DIR='$guest_share/bin'
  rm -rf /tmp/hasp-ui && mkdir -p /tmp/hasp-ui
  trap 'scripts/apple-ui-fixture.sh stop /tmp/hasp-ui/fixture' EXIT
  scripts/apple-ui-fixture.sh start /tmp/hasp-ui/fixture seed >/dev/null
  TEST_RUNNER_HASP_UITEST_FIXTURE=/tmp/hasp-ui/fixture/fixture.json \
      xcodebuild test-without-building -xctestrun 'dd/Build/Products/$xctestrun' \
    -destination 'platform=macOS' -resultBundlePath '$guest_share/result.xcresult' -parallel-testing-enabled NO
" || status=$?

[ ! -d "$share/result.xcresult" ] || cp -R "$share/result.xcresult" "$out/"
if [ -d "$out/result.xcresult" ]; then
  rm -rf "$work/attachments"
  xcrun xcresulttool export attachments --path "$out/result.xcresult" --output-path "$work/attachments" >/dev/null
  python3 -I - "$work/attachments" "$shots" <<'PY'
import json, shutil, sys
src, dst = sys.argv[1:]
for test in json.load(open(f"{src}/manifest.json")):
    for item in test["attachments"]:
        name = item["suggestedHumanReadableName"]
        if name.endswith(".png") and "_0_" in name and not item["isAssociatedWithFailure"]:
            shutil.copy(f"{src}/{item['exportedFileName']}", f"{dst}/{name.split('_0_')[0]}.png")
PY
fi
exit "$status"
