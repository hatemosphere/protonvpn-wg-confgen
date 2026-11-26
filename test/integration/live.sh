#!/usr/bin/env bash
# Live run against the real Proton API with a dedicated free account: login
# with 2FA, generate one config, then connect through Gluetun twice with it:
# once with only the private key (the flow Gluetun's ProtonVPN page documents)
# and once with the whole profile. Kept minimal because Proton rate limits
# certificate creation (code 2028); a run makes two. Every certificate on the
# account is revoked on exit, so never point this at an account you use.
#
# The logs are public: IP addresses, certificate serials and the device name
# are redacted, and the private key is never printed.
#
# Needs PWG_USERNAME, PWG_PASSWORD and PWG_TOTP (otpauth URI or base32 seed),
# and docker, jq, curl, python3. Usage: live.sh [binary]
set -euo pipefail

bin=$(realpath "${1:-build/protonvpn-wg-confgen}")
work=$(mktemp -d)
cd "$work"
export HOME=$work # the session file dies with the run

image=qmcgaw/gluetun:v3.41.3@sha256:fa19cc76b2af13d57a8d3dc3066f2ada061b1c761b8aecf989b3877c0486e027
step() { echo "== $*"; }
pwg() { "$bin" --username "$PWG_USERNAME" --password "$PWG_PASSWORD" "$@"; }
redact() {
  sed -E -e 's/[0-9]{1,3}(\.[0-9]{1,3}){3}/<ip>/g' -e 's/[0-9]{8,}/<serial>/g' \
    -e 's/(Device name:? )[^ ]+/\1<device>/'
}
mask() { [ -z "${GITHUB_ACTIONS:-}" ] || echo "::add-mask::$1"; }

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
  echo "== cleanup: revoking every certificate on the account"
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
  redact <<<"$out"
  exit 1
fi
redact <<<"$out"

step "generate a persistent config (free tier, NL)"
pwg --countries NL --free-only --duration 1h --device-name live-test --output persist.conf 2>&1 | redact
key=$(awk -F' = ' '/^PrivateKey/ {print $2}' persist.conf)
mask "$key"
grep -qE '^Endpoint = [0-9.]+:51820$' persist.conf
direct_ip=$(curl -fsS --max-time 20 https://api.ipify.org)
mask "$direct_ip"

# gluetun <name> <docker run args...>: starts it, waits for its healthcheck and
# checks that traffic leaves through the VPN, not the runner's own address.
gluetun() {
  local name=$1 start=$SECONDS health=
  shift
  docker run -d --name pwg-gluetun --cap-add NET_ADMIN --device /dev/net/tun "$@" "$image" >/dev/null
  for _ in $(seq 60); do
    health=$(docker inspect -f '{{.State.Health.Status}}' pwg-gluetun)
    [ "$health" = healthy ] && break
    sleep 3
  done
  if [ "$health" != healthy ]; then
    echo "$name: no healthy tunnel after $((SECONDS - start))s, last Gluetun logs:"
    docker logs --tail 40 pwg-gluetun 2>&1 | redact
    exit 1
  fi
  local vpn_ip
  vpn_ip=$(docker exec pwg-gluetun wget -qO- https://api.ipify.org)
  mask "$vpn_ip"
  docker rm -f pwg-gluetun >/dev/null
  if [ -z "$vpn_ip" ] || [ "$vpn_ip" = "$direct_ip" ]; then
    echo "$name: traffic did not go through the VPN"
    exit 1
  fi
  echo "$name: tunnel up in $((SECONDS - start))s, traffic exits through the VPN"
}

docker pull -q "$image" >/dev/null

step "Gluetun, protonvpn provider with the private key"
WIREGUARD_PRIVATE_KEY=$key gluetun "key only" -e WIREGUARD_PRIVATE_KEY \
  -e VPN_SERVICE_PROVIDER=protonvpn -e VPN_TYPE=wireguard -e FREE_ONLY=on -e SERVER_COUNTRIES=Netherlands

step "Gluetun, custom provider with the whole profile"
gluetun "whole profile" -v "$work/persist.conf:/gluetun/wireguard/wg0.conf:ro" \
  -e VPN_SERVICE_PROVIDER=custom -e VPN_TYPE=wireguard

echo "live run passed"
