# iran-spoof-tunnel

One-command installer for a **layer-3 IP-spoofing tunnel** between an Iranian server and a foreign relay, used to carry a panel inbound port (e.g. `9044`) out of the country.

Built on top of [imanxboy/spoof-tunnel](https://github.com/imanxboy/spoof-tunnel).

> فارسی: [README.md](README.md)

```
client (v2rayNG)
      │
      ▼
┌──────────────┐     UDP 2080, spoofed source      ┌──────────────┐
│ Iran server  │ ─────────────────────────────────► │ Foreign VPS  │
│ 10.100.100.2 │ ◄───────────────────────────────── │ 10.100.100.1 │
│ (client)     │                                    │ (server)     │
└──────────────┘                                    └──────────────┘
      │                                                    │
      └── DNAT :9044 ──────────────────► xray/panel on :9044 ┘
```

## Requirements

* Two Ubuntu 22.04/24.04 servers (one in Iran, one abroad), root access
* One free UDP port on both sides (default `2080`)
* Optionally, a spare IP on the foreign server's subnet to spoof as (`x.x.x.100`)

## Install (one line, no clone needed)

On the **foreign** server:

```bash
curl -fsSL https://raw.githubusercontent.com/lastdejavu/DEJ-SPOOF/main/scripts/install.sh -o /tmp/tun.sh \
  && sudo bash /tmp/tun.sh --role server --peer <IRAN_IP>
```

On the **Iranian** server:

```bash
curl -fsSL https://raw.githubusercontent.com/lastdejavu/DEJ-SPOOF/main/scripts/install.sh -o /tmp/tun.sh \
  && sudo bash /tmp/tun.sh --role client --peer <FOREIGN_IP> --forward 9044,9033
```

Verify:

```bash
curl -fsSL https://raw.githubusercontent.com/lastdejavu/DEJ-SPOOF/main/scripts/verify.sh -o /tmp/v.sh \
  && sudo bash /tmp/v.sh --peer-tun 10.100.100.1 --ports 9044,9033 --public-ip <IRAN_IP>
```

### Or clone it

```bash
git clone https://github.com/lastdejavu/DEJ-SPOOF.git && cd DEJ-SPOOF
sudo ./scripts/install.sh --role server --peer <IRAN_IP>
sudo ./scripts/install.sh --role client --peer <FOREIGN_IP> --forward 9044,9033
```

The installer auto-detects the interface, writes `/etc/spoof-tunnel/config.yaml`, installs spoof-tunnel v6.3.1, applies `FORWARD` + `MASQUERADE` + `rp_filter` rules, and makes all of it survive a reboot (`spoof-tunnel-nat.service`).

## Options

| Flag | Meaning | Default |
| :--- | :--- | :--- |
| `--role` | `server` (foreign) or `client` (Iran) | required |
| `--peer` | public IP of the other side | required |
| `--spoof` | source IP this side spoofs | server: `x.x.x.100` of its own /24 · client: its real IP |
| `--peer-spoof` | source IP the peer spoofs | peer's real IP |
| `--port` | tunnel UDP port | `2080` |
| `--forward` | inbound ports (client only) | — |
| `--mtu` | tunnel MTU | `1440` |
| `--iface` | override interface detection | auto |

## Day-to-day

```bash
spoofctl status
journalctl -u spoof-tunnel -f
systemctl restart spoof-tunnel
ping -c 4 10.100.100.1
spoofctl forward add 9033
```

## Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md). The most common failure: **the tunnel pings but no traffic flows** — the foreign server's `FORWARD` chain is `DROP` and/or there is no `MASQUERADE` for `10.100.100.0/24`. The installer handles both.

If the tunnel drops 50–90% of packets, the international path is filtering large UDP packets. Retry with `--mtu 1360`, then `1300`. If that fails, that path cannot carry this tunnel — use a third relay or plain TCP forwarding instead.

## License

[MIT](LICENSE)
