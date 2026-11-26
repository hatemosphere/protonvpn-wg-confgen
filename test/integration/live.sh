#!/usr/bin/env bash
# Live run against the real Proton API with a dedicated free account: login
# with 2FA, then the generated key driving Gluetun (the flow its ProtonVPN page
# documents). Kept minimal because Proton rate limits certificate creation
# (code 2028); a run makes two. Every certificate on the account is revoked on
# exit, so never point this at an account you use.
#
# Needs PWG_USERNAME, PWG_PASSWORD and PWG_TOTP (otpauth URI or base32 seed),
# and docker, jq, curl, python3. Usage: live.sh [binary]
set -euo pipefail

bin=$(realpath "${1:-build/protonvpn-wg-confgen}")
work=$(mktemp -d)
cd "$work"
export HOME=$work # the session file dies with the run

gluetun=qmcgaw/gluetun:v3.41.3@sha256:fa19cc76b2af13d57a8d3dc3066f2ada061b1c761b8aecf989b3877c0486e027
step() { echo "== $*"; }
pwg() { "$bin" --username "$PWG_USERNAME" --password "$PWG_PASSWORD" "$@"; }

totp() {
  python3 -I - "$PWG_TOTP" <<'EOF'
import base64, hmac, struct, sys, time, urllib.parse
s = sys.argv[1]
if s.startswith("otpauth://"):
    s = urllib.parse.parse_qs(urllib.parse.urlparse(s).query)["secret"][0]
s = s.replace(" ", "").upper()
key = base64.b32decode(s + "=" * (-len(s) % 8))
mac = hmac.digest(key, struct.pack(">Q", int(time.time()) // 30), "sha1")
o = mac[-1] & 15
print("%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000))
EOF
}

cleanup() {
  docker rm -f pwg-gluetun >/dev/null 2>&1 || true
  pwg --list-configs --with-sessions --json 2>/dev/null | jq -r '.[].serial' |
    while read -r serial; do pwg --revoke-serial "$serial" >/dev/null 2>&1 || true; done
  rm -rf "$work"
}
trap cleanup EXIT

step "login with 2FA"
if ! out=$(totp | pwg --list-configs 2>&1); then
  if grep -q "code 9001" <<<"$out"; then
    echo "::warning::Proton asked for a CAPTCHA, skipping the live run"
    exit 0
  fi
  echo "$out"
  exit 1
fi

step "persistent config drives Gluetun"
pwg --countries NL --free-only --duration 1h --output persist.conf 2>&1
WIREGUARD_PRIVATE_KEY=$(awk -F' = ' '/^PrivateKey/ {print $2}' persist.conf)
export WIREGUARD_PRIVATE_KEY
docker run -d --name pwg-gluetun --cap-add NET_ADMIN --device /dev/net/tun \
  -e VPN_SERVICE_PROVIDER=protonvpn -e VPN_TYPE=wireguard -e WIREGUARD_PRIVATE_KEY \
  -e FREE_ONLY=on -e SERVER_COUNTRIES=Netherlands "$gluetun" >/dev/null
for _ in $(seq 60); do
  health=$(docker inspect -f '{{.State.Health.Status}}' pwg-gluetun)
  [ "$health" = healthy ] && break
  sleep 3
done
if [ "$health" != healthy ]; then
  docker logs --tail 40 pwg-gluetun 2>&1
  exit 1
fi
vpn_ip=$(docker logs pwg-gluetun 2>&1 | sed -n 's/.*Public IP address is \([0-9.]*\).*/\1/p' | head -1)
direct_ip=$(curl -fsS --max-time 20 https://api.ipify.org)
echo "through Gluetun $vpn_ip, direct $direct_ip"
[ -n "$vpn_ip" ] && [ "$vpn_ip" != "$direct_ip" ]
echo "live run passed"
