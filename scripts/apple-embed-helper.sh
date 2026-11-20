#!/usr/bin/env bash
set -euo pipefail

source=${HASP_NMH_BINARY:-}
if [ -z "$source" ] || [ ! -x "$source" ]; then
  echo "note: HASP_NMH_BINARY not set, native messaging helper not embedded"
  exit 0
fi

dev_markers=(hasp-nmh-dev-extension-build gchilemfcapcihefglfdhgihpcjcdogp hasp-dev@hasp.app)
if [ "${CONFIGURATION:-Debug}" = "Release" ]; then
  case "$source" in
    */release/*) ;;
    *) echo "error: a Release app must embed a release-profile helper, got $source" >&2; exit 1 ;;
  esac
  for marker in "${dev_markers[@]}"; do
    if grep -aqF "$marker" "$source"; then
      echo "error: the helper was built with the dev-extension feature ($marker found)" >&2
      exit 1
    fi
  done
  timestamp=(--timestamp)
else
  timestamp=(--timestamp=none)
fi

destination="$BUILT_PRODUCTS_DIR/$CONTENTS_FOLDER_PATH/Helpers"
mkdir -p "$destination"
cp "$source" "$destination/hasp-nmh"

if [ "${CODE_SIGNING_ALLOWED:-YES}" = "YES" ] && [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then
  codesign --force --options runtime "${timestamp[@]}" --sign "$EXPANDED_CODE_SIGN_IDENTITY" \
    --identifier kr.jmo.hasp.nmh "$destination/hasp-nmh"
fi
