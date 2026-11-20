#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root/apps/apple"

check() {
python3 -I - "$1" "$2" <<'PY'
import json, pathlib, re, sys

catalog = json.load(open(sys.argv[1]))["strings"]
missing = [k for k, v in catalog.items() if not all(l in v["localizations"] for l in ("ko", "en"))]
call = re.compile(r'(?:Text|Button|Label|Toggle|Picker|TextField|SecureField|LabeledContent|Section|CommandMenu)\(\s*"([^"]+)"|String\(localized: "([^"]+)"\)|accessibilityLabel\("([^"]+)"\)')
used = set()
for path in pathlib.Path(sys.argv[2]).rglob("*.swift"):
    for match in call.finditer(path.read_text()):
        key = next(g for g in match.groups() if g)
        key = re.sub(r"\\\(([^)]*\.formatted\([^)]*\)|[^)]*\.count)\)", "%lld", key)
        key = re.sub(r"\\\([^)]*\)", "%lld", key)
        used.add(key)
absent = sorted(k for k in used if k not in catalog and k.replace("%lld", "%@") not in catalog and "." in k)
if missing or absent:
    print("missing ko/en:", missing, "\nmissing keys:", absent)
    sys.exit(1)
PY
}

check App/Mac/Resources/Localizable.xcstrings Packages/Hasp/Sources/HaspUI
check App/CredentialProvider/Resources/Localizable.xcstrings Packages/Hasp/Sources/HaspProviderUI
