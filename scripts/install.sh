#!/usr/bin/env bash
# iran-spoof-tunnel installer
# Sets up a Layer-3 IP-spoofing UDP tunnel between an Iranian server and a
# foreign (kharej) server, and forwards panel inbound ports through it.
#
#   Server side (foreign / kharej):  sudo ./install.sh --role server --peer <IRAN_IP>
#   Client side (Iran):              sudo ./install.sh --role client --peer <FOREIGN_IP> --forward 9044,9033
#
# Tested on Ubuntu 22.04 / 24.04 with spoof-tunnel v6.3.1.

set -euo pipefail

ROLE=""
PEER=""
SPOOF=""
PEER_SPOOF=""
PORT="2080"
MTU="1440"
IFACE=""
FORWARD=""
TAG="v6.3.1"
NET="10.100.100"     # tunnel subnet; server .1, client .2

die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  sudo ./install.sh --role server --peer <IRAN_PUBLIC_IP>       [options]
  sudo ./install.sh --role client --peer <FOREIGN_PUBLIC_IP>    [options]

Options:
  --role      server | client            (server = foreign/kharej box)
  --peer      public IP of the other side (required)
  --spoof     source IP this side spoofs in the tunnel (default: server -> x.x.x.100 in own /24, client -> own public IP)
  --peer-spoof source IP the other side spoofs (default: the peer's real public IP)
  --port      tunnel UDP port (default 2080)
  --forward   comma separated ports to forward (client only, e.g. 9044,9033)
  --mtu       tunnel MTU (default 1440; lower it to 1360/1300 if the path filters big packets)
  --iface     override the auto-detected network interface
  --tag       spoof-tunnel release tag (default v6.3.1)
  -h, --help  this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --role)       ROLE="${2:-}";       shift 2 ;;
    --peer)       PEER="${2:-}";       shift 2 ;;
    --spoof)      SPOOF="${2:-}";      shift 2 ;;
    --peer-spoof) PEER_SPOOF="${2:-}"; shift 2 ;;
    --port)       PORT="${2:-}";       shift 2 ;;
    --forward)    FORWARD="${2:-}";    shift 2 ;;
    --mtu)        MTU="${2:-}";        shift 2 ;;
    --iface)      IFACE="${2:-}";      shift 2 ;;
    --tag)        TAG="${2:-}";        shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root"
[ "$ROLE" = "server" ] || [ "$ROLE" = "client" ] || die "--role must be server or client"
[ -n "$PEER" ] || die "--peer is required"

# ---------- network detection ----------
IFACE="${IFACE:-$(ip -o -4 route show default | awk '{print $5; exit}')}"
[ -n "$IFACE" ] || die "could not detect the default interface; pass --iface"
OUR_IP="$(ip -o -4 addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -1)"
[ -n "$OUR_IP" ] || die "no IPv4 on $IFACE"

if [ "$ROLE" = "server" ]; then
  LOCAL_TUN="$NET.1"; PEER_TUN="$NET.2"
  [ -n "$SPOOF" ] || SPOOF="$(echo "$OUR_IP" | awk -F. '{print $1"."$2"."$3".100"}')"
else
  LOCAL_TUN="$NET.2"; PEER_TUN="$NET.1"
  [ -n "$SPOOF" ] || SPOOF="$OUR_IP"
fi
[ -n "$PEER_SPOOF" ] || PEER_SPOOF="$PEER"

echo "== iran-spoof-tunnel installer =="
echo "  role        : $ROLE"
echo "  interface   : $IFACE ($OUR_IP)"
echo "  peer        : $PEER  (udp/$PORT)"
echo "  tunnel IPs  : $LOCAL_TUN  <->  $PEER_TUN   mtu $MTU"
echo "  spoof list  : $SPOOF, $PEER_SPOOF"
[ -n "$FORWARD" ] && echo "  forward     : $FORWARD"
echo

# ---------- dependencies ----------
export DEBIAN_FRONTEND=noninteractive
echo ">> installing build deps"
apt-get update -qq >/dev/null 2>&1 || true
apt-get install -y -qq gcc make curl iptables iproute2 >/dev/null 2>&1 || die "apt install failed"
command -v gcc >/dev/null || die "gcc missing"

# ---------- config (the upstream installer refuses to run without it) ----------
echo ">> writing /etc/spoof-tunnel/config.yaml"
mkdir -p /etc/spoof-tunnel
[ -f /etc/spoof-tunnel/config.yaml ] && cp -f /etc/spoof-tunnel/config.yaml "/etc/spoof-tunnel/config.yaml.bak.$(date +%s)"

if [ "$ROLE" = "server" ]; then
  ROLE_ORDER="$SPOOF
    - $PEER_SPOOF"
else
  ROLE_ORDER="$SPOOF
    - $PEER_SPOOF"
fi

cat > /etc/spoof-tunnel/config.yaml <<EOF
tunnel:
  role: $ROLE
  outer: udp
  peer_address: $PEER
  listen_port: $PORT
  peer_port: $PORT

spoof:
  addresses:
    - $SPOOF
    - $PEER_SPOOF
  loss_threshold: 2.0
  failover_intervals: 999

network:
  interface: $IFACE
  tun_name: tun0
  local_tun_ip: $LOCAL_TUN
  peer_tun_ip: $PEER_TUN
  mtu: $MTU

performance:
  rate_mbps: 1000
  flow_limit: 0
  batch_size: 16
  rx_ring_blocks: 32
  tx_cpu: -1
  rx_cpu: -1

monitoring:
  metric_interval: 5
  json_metrics: true
  prometheus_enabled: false
  prometheus_dir: /var/lib/prometheus/node-exporter
  qdisc_monitor_interval: 60
  log_retention_days: 30

advanced:
  sysctl_tune: true
  watchdog_sec: 30
EOF

if [ "$ROLE" = "client" ] && [ -n "$FORWARD" ]; then
  {
    echo ""
    echo "forwarding:"
    echo "  ports:"
    echo "$FORWARD" | tr ',' '\n' | sed '/^$/d;s/^/    - /'
  } >> /etc/spoof-tunnel/config.yaml
fi

# ---------- install / upgrade ----------
if [ -x /usr/local/bin/spoof-tunnel ] && [ -f /etc/spoof-tunnel/tunnel.env ]; then
  echo ">> spoof-tunnel already installed, restarting with the new config"
else
  echo ">> installing spoof-tunnel $TAG"
  set +e
  curl -fsSL https://raw.githubusercontent.com/imanxboy/spoof-tunnel/main/scripts/install.sh | INSTALL_TAG="$TAG" bash >/tmp/spoof-install.log 2>&1
  rc=$?
  set -e
  [ -x /usr/local/bin/spoof-tunnel ] || { tail -30 /tmp/spoof-install.log; die "spoof-tunnel install failed"; }
fi

systemctl daemon-reload
systemctl enable spoof-tunnel >/dev/null 2>&1
systemctl restart spoof-tunnel
sleep 4
systemctl is-active --quiet spoof-tunnel || die "spoof-tunnel did not stay up (journalctl -u spoof-tunnel -n 50)"

# ---------- forwarding / NAT for the tunnel subnet ----------
echo ">> applying FORWARD + MASQUERADE rules"
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw "net.ipv4.conf.${IFACE}.rp_filter=0"
sysctl -qw net.ipv4.conf.tun0.rp_filter=0

iptables -C FORWARD -i tun0 -o "$IFACE" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i tun0 -o "$IFACE" -j ACCEPT
iptables -C FORWARD -i "$IFACE" -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -i "$IFACE" -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -s "$NET.0/24" -o "$IFACE" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$NET.0/24" -o "$IFACE" -j MASQUERADE

# client side: mirror the public ports onto the tunnel peer
if [ "$ROLE" = "client" ] && [ -n "$FORWARD" ]; then
  for p in $(echo "$FORWARD" | tr ',' ' '); do
    for proto in tcp udp; do
      iptables -t nat -C PREROUTING -p "$proto" --dport "$p" -j DNAT --to-destination "$PEER_TUN:$p" 2>/dev/null \
        || iptables -t nat -I PREROUTING -p "$proto" --dport "$p" -j DNAT --to-destination "$PEER_TUN:$p"
    done
    echo "   forward $p -> $PEER_TUN:$p"
  done
fi

# persist rules across reboots
cp -f "$0" /usr/local/sbin/iran-spoof-tunnel-install.sh 2>/dev/null || true
cat > /usr/local/sbin/spoof-tunnel-nat.sh <<NAT
#!/bin/sh
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.${IFACE}.rp_filter=0
sysctl -qw net.ipv4.conf.tun0.rp_filter=0
iptables -C FORWARD -i tun0 -o ${IFACE} -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i tun0 -o ${IFACE} -j ACCEPT
iptables -C FORWARD -i ${IFACE} -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i ${IFACE} -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -s ${NET}.0/24 -o ${IFACE} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${NET}.0/24 -o ${IFACE} -j MASQUERADE
NAT
chmod +x /usr/local/sbin/spoof-tunnel-nat.sh

cat > /etc/systemd/system/spoof-tunnel-nat.service <<UNIT
[Unit]
Description=spoof-tunnel FORWARD/MASQUERADE rules
After=network-online.target spoof-tunnel.service
Wants=network-online.target
Requires=spoof-tunnel.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/spoof-tunnel-nat.sh
RemainAfterExit=yes
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now spoof-tunnel-nat.service >/dev/null 2>&1

# ---------- verify ----------
echo
echo ">> verifying the tunnel"
ip -br a show tun0 || true
if ping -c 4 -W 2 "$PEER_TUN" >/dev/null 2>&1; then
  echo "   ping $PEER_TUN : OK"
else
  echo "   ping $PEER_TUN : FAILED  (peer not up yet? check the other side, the UDP port, and the spoof list)"
fi
if [ -n "$FORWARD" ]; then
  for p in $(echo "$FORWARD" | tr ',' ' '); do
    if timeout 6 bash -c "</dev/tcp/$PEER_TUN/$p" 2>/dev/null; then
      echo "   tcp $PEER_TUN:$p : OK"
    else
      echo "   tcp $PEER_TUN:$p : FAILED  (is anything listening on the peer?)"
    fi
  done
fi

echo
echo "Done. Useful commands:"
echo "  spoofctl status                 # live status"
echo "  journalctl -u spoof-tunnel -f   # live log"
echo "  scripts/verify.sh --peer <IP>   # full check incl. bulk throughput"
