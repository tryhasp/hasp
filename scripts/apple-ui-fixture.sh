#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
bin=${HASP_BIN_DIR:-${CARGO_TARGET_DIR:-$root/target}/debug}
work=${2:?work directory}
password="correct horse battery staple"
login="ui@example.com"

stop() {
  if [ -f "$work/haspd.pid" ]; then
    kill -TERM "$(cat "$work/haspd.pid")" 2>/dev/null || true
    rm -f "$work/haspd.pid"
  fi
}

start() {
  mkdir -p "$work/data" "$work/cli"
  port=$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
  origin="http://127.0.0.1:$port"
  export HASP_DATA_DIR="$work/data" HASP_PUBLIC_URL="$origin" HASP_LISTEN="127.0.0.1:$port" HASP_LOG=warn
  export HASP_LIMIT_LOGIN_PER_PEER=100000 HASP_LIMIT_REGISTER_PER_PEER=100000 HASP_LIMIT_GENERAL_PER_SUBJECT=10000000
  init=$("$bin/haspd" init)
  fingerprint=$(printf '%s\n' "$init" | sed -n 's/^fingerprint: //p')
  code=$(printf '%s\n' "$init" | sed -n 's/^first signup code (makes you the admin): //p')
  "$bin/haspd" serve >"$work/haspd.log" 2>&1 &
  echo $! >"$work/haspd.pid"
  for _ in $(seq 1 200); do
    curl -fsS "$origin/healthz" >/dev/null 2>&1 && break
    sleep 0.1
  done
  signup=$(printf '%s\n%s\n' "$code" "$password" | "$bin/hasp" --data-dir "$work/cli" --json --password-stdin --reveal signup \
    --origin "$origin" --login "$login" --code-stdin --server-fingerprint "$fingerprint")
  secret=$(printf '%s' "$signup" | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["data"]["secret_key"])')
  [ -n "$secret" ] || { echo "no Secret Key in signup output" >&2; stop; exit 1; }
  printf '{"origin":"%s","login":"%s","secretKey":"%s","password":"%s","fingerprint":"%s"}\n' \
    "$origin" "$login" "$secret" "$password" "$fingerprint" >"$work/fixture.json"
}

seed() {
  hasp_item() {
    printf '%s\n' "$password" | "$bin/hasp" --data-dir "$work/cli" --json --password-stdin --no-input item create "$@" >/dev/null
  }
  while IFS='|' read -r title url user favourite; do
    extra=()
    if [ "$title" = "네이버" ]; then
      extra=(--field "otp=JBSWY3DPEHPK3PXP" --tag 개인 --tag 메일 --notes "2단계 인증 켜짐")
    fi
    hasp_item --title "$title" --url "$url" --subtitle "$user" --field "username=$user" --generate-password \
      --favourite "$favourite" ${extra[@]+"${extra[@]}"}
  done <<'ITEMS'
쿠팡|https://www.coupang.com|mino@example.com|true
네이버|https://nid.naver.com|mino.dev|true
카카오뱅크|https://www.kakaobank.com|mino@example.com|false
GitHub|https://github.com|octocat|false
토스|https://toss.im|mino@example.com|false
ITEMS
  hasp_item --category credit-card --title 신한카드 --subtitle "•••• 4821" --field "number=4111111111114821" --field "cardholder=홍길동"
  hasp_item --category wireless-router --title "집 와이파이" --subtitle "HomeNet" --field "network-name=HomeNet" --field "wireless-password=correct-horse-wifi"
  hasp_item --category ssh-key --title "서버 SSH 키" --subtitle "ed25519"
}

case "${1:?start or stop}" in
  start) start; [ "${3:-}" = "seed" ] && seed; true ;;
  stop) stop ;;
  *) exit 2 ;;
esac
