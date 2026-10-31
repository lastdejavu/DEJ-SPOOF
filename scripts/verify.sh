#!/usr/bin/env bash
# End-to-end check for an iran-spoof-tunnel setup.
# Run it on either side. It answers three questions:
#   1. is the tunnel itself alive?          (ping + TCP through the tunnel)
#   2. does real internet traffic flow?     (bulk download/upload through the tunnel)
#   3. does the public inbound port work?   (TCP connect to the public IP, optional)
#
#   sudo ./verify.sh --peer-tun 10.100.100.1 --ports 9044,9033
#   sudo ./verify.sh --peer-tun 10.100.100.1 --ports 9044 --public-ip 1.2.3.4

set -uo pipefail

PEER_TUN="10.100.100.1"
PORTS="9044"
PUBLIC_IP=""
MB="20"

while [ $# -gt 0 ]; do
  case "$1" in
    --peer-tun)  PEER_TUN="${2:-}"; shift 2 ;;
    --ports)     PORTS="${2:-}";    shift 2 ;;
    --public-ip) PUBLIC_IP="${2:-}";shift 2 ;;
    --mb)        MB="${2:-}";       shift 2 ;;
    -h|--help)   sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option $1"; exit 1 ;;
  esac
done

ok()   { printf '  \033[32mOK\033[0m   %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
note() { printf '  --   %s\n' "$*"; }

echo "== tunnel interface =="
ip -br a show tun0 2>/dev/null || bad "tun0 does not exist - is spoof-tunnel running?"
echo

echo "== liveness =="
if ping -c 5 -W 2 "$PEER_TUN" >/dev/null 2>&1; then
  rtt=$(ping -c 5 -W 2 "$PEER_TUN" 2>/dev/null | tail -1 | awk -F'/' '{print $5}')
  ok "ping $PEER_TUN (avg ${rtt:-?} ms)"
else
  bad "ping $PEER_TUN - tunnel peer unreachable"
fi

for p in $(echo "$PORTS" | tr ',' ' '); do
  n=0
  for i in 1 2 3; do
    timeout 6 bash -c "</dev/tcp/$PEER_TUN/$p" 2>/dev/null && n=$((n+1))
  done
  [ "$n" -eq 3 ] && ok "tcp $PEER_TUN:$p ($n/3)" || bad "tcp $PEER_TUN:$p ($n/3) - nothing listening or forward blocked"
done
echo

echo "== bulk traffic through the tunnel =="
TARGET=$(getent ahostsv4 speed.cloudflare.com 2>/dev/null | awk 'NR==1{print $1}')
if [ -z "$TARGET" ]; then
  note "could not resolve speed.cloudflare.com, skipping"
else
  ip route add "$TARGET/32" dev tun0 2>/dev/null || true
  res=$(curl -s -o /dev/null -m 60 -w '%{http_code} %{size_download} %{speed_download}' \
        "https://speed.cloudflare.com/__down?bytes=$((MB*1000000))" --resolve "speed.cloudflare.com:443:$TARGET" || true)
  code=$(echo "$res" | awk '{print $1}')
  speed=$(echo "$res" | awk '{print $3}')
  if [ "$code" = "200" ]; then
    ok "download ${MB}MB -> $(awk -v s="$speed" 'BEGIN{printf "%.1f", s*8/1e6}') Mbit/s"
  else
    bad "download failed (http=$code)"
    note "if the tunnel pings fine but no data moves, check on the SERVER side:"
    note "  iptables -S FORWARD | grep tun0          (must be ACCEPT, not DROP)"
    note "  iptables -t nat -S POSTROUTING | grep 10.100.100   (MASQUERADE must exist)"
  fi
  ip route del "$TARGET/32" dev tun0 2>/dev/null || true
fi
echo

if [ -n "$PUBLIC_IP" ]; then
  echo "== public inbound =="
  for p in $(echo "$PORTS" | tr ',' ' '); do
    n=0
    for i in 1 2 3; do
      timeout 8 bash -c "</dev/tcp/$PUBLIC_IP/$p" 2>/dev/null && n=$((n+1))
    done
    [ "$n" -eq 3 ] && ok "public $PUBLIC_IP:$p ($n/3)" || bad "public $PUBLIC_IP:$p ($n/3)"
  done
  note "a TCP connect only proves the path; authenticate with a real client for the full test"
fi
