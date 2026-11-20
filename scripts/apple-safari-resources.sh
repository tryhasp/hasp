#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
source=$root/apps/extension/.output/safari-mv3

if [ ! -f "$source/manifest.json" ]; then
  echo "error: $source is missing; run 'mise run ext-safari' first" >&2
  exit 1
fi

destination="$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH"
mkdir -p "$destination"

if [ "$PLATFORM_NAME" = macosx ]; then
  rsync -a --delete "$source/" "$destination/"
  exit 0
fi

# Why: on iOS the bundle is flat, so the extension shares its root with Info.plist and the executable; only files this script copied earlier may be removed.
listing=$DERIVED_FILE_DIR/safari-resources.list
if [ -f "$listing" ]; then
  while IFS= read -r relative; do
    rm -f "${destination:?}/$relative"
  done <"$listing"
fi
(cd "$source" && find . -type f | sed 's|^\./||') >"$listing.new"
rsync -a "$source/" "$destination/"
mv "$listing.new" "$listing"
