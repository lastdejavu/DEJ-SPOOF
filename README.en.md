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

## Before anything: can my server spoof?

Run this 30-second check **before** installing the tunnel. On one server listen, on the other send.

```bash
curl -fsSL https://raw.githubusercontent.com/lastdejavu/DEJ-SPOOF/main/scripts/spoof-test.py -o /tmp/spoof-test.py
sudo python3 /tmp/spoof-test.py listen --port 2390
# on the other server:
sudo python3 /tmp/spoof-test.py send --peer <SERVER_IP> --port 2390 --spoof 1.2.3.100
```

| Listener sees | Meaning |
| :--- | :--- |
| `SPF0: arrived as 1.2.3.100` | spoofing works - install with that IP |
| `SPF0: arrived as <your real IP>` | packet left but the source was rewritten - no spoofing |
| nothing at all | packets with foreign sources are dropped upstream |
| no `CTRL` either | the two servers cannot reach each other on UDP at all |

It also sends a size ladder (200..1472 B): if large sizes vanish, the path filters big UDP packets and no tunnel will survive there, spoofing or not.

### Iranian servers may spoof too - test, do not assume

It is widely repeated that Iranian servers can never spoof. **That is not a rule.** Some providers forward packets with foreign sources. The tool can try several addresses in your own /24 automatically:

```bash
sudo python3 spoof-test.py send --peer <PEER_IP> --port 2390 --spoof auto
```

If one of them arrives with the spoofed address, the Iranian side can spoof as well. In that case put the **peer's** address in the Iranian spoof list (not its own real IP) and add the same address on the foreign side.

What we measured on three different Iranian providers (8 candidate addresses each, own /24):

| side | control packets | spoofed packets |
| :--- | :--- | :--- |
| Iran #1 | 6/6 arrived | none arrived |
| Iran #2 | 6/6 arrived | none arrived |
| Iran #3 | 6/6 arrived | none arrived |
| foreign | healthy | arrived with the spoofed IP |

So on those three the provider's anti-spoof filter is active - but since this differs per provider, every new server must be tested.

---

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
