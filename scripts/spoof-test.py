#!/usr/bin/env python3
"""
spoof-test.py - check whether a server can spoof source IPs, BEFORE installing a tunnel.

Run it on both servers. One side listens, the other sends.

  # 1) on the foreign (kharej) server
  sudo ./spoof-test.py listen --port 2390

  # 2) on the Iranian server
  sudo ./spoof-test.py send --peer <FOREIGN_IP> --port 2390 --spoof 1.2.3.100

  # 3) swap roles to test the other direction
  sudo ./spoof-test.py listen --port 2390          # on Iran
  sudo ./spoof-test.py send --peer <IRAN_IP> --port 2390 --spoof <SPOOF_IP>   # on foreign

What you get, for each spoofed source you try:

  ARRIVED AS THE SPOOF IP   -> egress spoofing works, use it
  ARRIVED AS YOUR REAL IP   -> the packet left but someone rewrote the source
                               (hypervisor / NAT); spoofing is NOT available
  NEVER ARRIVED             -> packets with foreign sources are dropped
                               (upstream anti-spoof filter or path filtering)

The size ladder (200 .. 1472 bytes) also tells you whether the path silently
drops large UDP packets - that is a separate failure that breaks tunnels even
when spoofing works.

No dependencies beyond python3. Root is required for raw sockets.
"""

import argparse
import json
import os
import random
import socket
import struct
import sys
import time

MAGIC = b"DEJSPFTEST1"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _unbuffer():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def need_root():
    if os.geteuid() != 0:
        die("raw sockets need root - run with sudo")


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_packet(src_ip, dst_ip, src_port, dst_port, payload):
    """IPv4 + UDP with an arbitrary source address."""
    total_len = 20 + 8 + len(payload)
    ip_id = random.randint(1, 65535)

    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,            # version 4, IHL 5
        0x00,            # DSCP/ECN
        total_len,
        ip_id,
        0x0000,          # flags/fragment (DF off: lets it fragment if needed)
        64,              # TTL
        socket.IPPROTO_UDP,
        0,               # checksum placeholder
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip_hdr = ip_hdr[:10] + struct.pack("!H", checksum(ip_hdr)) + ip_hdr[12:]

    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)  # checksum 0 = allowed

    return ip_hdr + udp_hdr + payload


def make_payload(tag, size, index):
    """MAGIC|tag|size|index|padding"""
    head = b"%s|%s|%d|%d|" % (MAGIC, tag.encode(), size, index)
    if len(head) >= size:
        return head[:size]
    return head + b"." * (size - len(head))


def parse_payload(data):
    try:
        if not data.startswith(MAGIC):
            return None
        parts = data.split(b"|", 4)
        if len(parts) < 5:
            return None
        return parts[1].decode(errors="replace"), int(parts[2]), int(parts[3])
    except Exception:
        return None


def split_tag(tag):
    """'iran5__SPF0' -> ('iran5', 'SPF0')"""
    if "__" in tag:
        lab, kind = tag.rsplit("__", 1)
        return lab, kind
    return "", tag


def real_ip_towards(peer):
    """Local source IP the kernel would use to reach peer."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((peer, 9))
        return s.getsockname()[0]
    finally:
        s.close()


def auto_candidates(my_real, extra_peer=None):
    """Spoof candidates that are most likely to survive a provider filter."""
    base = ".".join(my_real.split(".")[:3])
    cands = []
    for last in ("100", "1", "2", "50", "200", "254", "10", "20"):
        ip = f"{base}.{last}"
        if ip != my_real and ip not in cands:
            cands.append(ip)
    return cands


def default_iface():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fld = line.split()
                if fld[1] == "00000000":
                    return fld[0]
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------- #
# listen mode
# --------------------------------------------------------------------------- #
def cmd_listen(args):
    need_root()
    _unbuffer()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((args.bind, args.port))
    except OSError as exc:
        die(f"cannot bind {args.bind}:{args.port} - {exc}")
    s.settimeout(1.0)

    print(f"listening on udp/{args.port} for {args.duration}s")
    print("run this on the OTHER server now:")
    print(f"  sudo ./spoof-test.py send --peer <THIS_SERVER_IP> --port {args.port} --spoof <IP_TO_TRY>")
    print()

    # tag -> { (observed_src, sent_size) -> count }
    seen = {}
    order = []
    end = time.time() + args.duration

    while time.time() < end:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        parsed = parse_payload(data)
        if not parsed:
            continue
        tag, sent_size, _idx = parsed
        key = (tag, sent_size)
        if key not in seen:
            seen[key] = {}
            order.append(key)
        seen[key][addr[0]] = seen[key].get(addr[0], 0) + 1
    s.close()

    if not seen:
        print("NOTHING ARRIVED.")
        print("  - wrong IP/port, or a firewall between the two servers,")
        print("  - or the sender used a source IP your provider drops before it leaves.")
        print("  Try the plain control test first: send without --spoof.")
        return

    # ---------- report ----------
    groups = {}
    for tag, size in order:
        groups.setdefault(tag, []).append((size, seen[(tag, size)]))

    print("=" * 78)
    print(f"{'tag':<16}{'size':>6}{'recv':>6}  observed source ip")
    print("=" * 78)
    for tag in sorted(groups):
        for size, srcs in sorted(groups[tag]):
            total = sum(srcs.values())
            src_txt = ", ".join(f"{ip} x{n}" for ip, n in sorted(srcs.items()))
            print(f"{tag:<16}{size:>6}{total:>6}  {src_txt}")
    print()

    # ---------- verdict ----------
    labels = sorted({split_tag(t)[0] for t in groups})
    overall_ok = False

    for lab in labels:
        title = lab if lab else "sender"
        my_tags = [t for t in groups if split_tag(t)[0] == lab]

        def srcs_of(kind_pred):
            out = {}
            for t in my_tags:
                _, kind = split_tag(t)
                if kind_pred(kind):
                    for size, s_ in groups[t]:
                        for ip, n in s_.items():
                            out[ip] = out.get(ip, 0) + n
            return out

        ctrl = srcs_of(lambda k: k == "CTRL")
        print("=" * 78)
        print(f"VERDICT - {title}")
        print("=" * 78)

        if not ctrl:
            print("  control packets never arrived -> the two servers cannot reach")
            print("  each other on this UDP port. Fix reachability/firewall first.")
            print()
            continue

        real_set = set(ctrl)
        print(f"  path works: control arrived from {', '.join(sorted(real_set))}")

        spoof_kinds = [k for k in (split_tag(t)[1] for t in my_tags) if k.startswith("SPF")]
        if not spoof_kinds:
            print("  no spoofed packet arrived at all -> packets with a foreign")
            print("  source are dropped before leaving this host or upstream.")
            print("  -> this side is NOT spoof-capable on those addresses.")
        else:
            for kind in sorted(spoof_kinds):
                srcs = srcs_of(lambda k, kk=kind: k == kk)
                if not srcs:
                    print(f"  {kind}: nothing arrived")
                elif set(srcs) <= real_set:
                    print(f"  {kind}: arrived as {', '.join(sorted(srcs))}"
                          f"  -> rewritten, spoof NOT available")
                else:
                    good = sorted(set(srcs) - real_set)
                    print(f"  {kind}: arrived as {', '.join(good)}  <-- SPOOF WORKS")
                    overall_ok = True

        ladder = {}
        for t in my_tags:
            _, kind = split_tag(t)
            if kind.startswith("SZ"):
                for size, s_ in groups[t]:
                    ladder[size] = ladder.get(size, 0) + sum(s_.values())
        print()
        if not ladder:
            print("  size ladder: nothing arrived for any size -> the path drops")
            print("  these packets entirely (source filter, not size filter).")
        else:
            print("  size ladder (large UDP must survive or tunnels break):")
            for size in sorted(ladder):
                print(f"    {size:>5} B payload : {ladder[size]} arrived")
            vals = [v for v in ladder.values()]
            if min(vals) == 0:
                print("    >>> a size arrived ZERO times - the path filters large UDP.")
                print("        Lower the tunnel MTU, or this path cannot carry the tunnel.")
            elif max(vals) > 2 * min(vals):
                print("    >>> delivery drops with size - likely size filtering.")
                print("        Try --mtu 1360 or 1300 before giving up on this path.")
        print()

    print("=" * 78)
    print("HOW TO READ THIS")
    print("=" * 78)
    print("  arrived as the spoofed address  -> that side can spoof, use it")
    print("  arrived as the sender's real ip -> packet left, source was rewritten")
    print("  nothing arrived                 -> dropped upstream (anti-spoof filter)")
    print()
    if overall_ok:
        print("at least one side can spoof. install with the working address:")
        print("  sudo ./scripts/install.sh --role server --peer <PEER> --spoof <WORKING_IP>")
    else:
        print("no spoofing observed from these addresses.")
        print("  If this was an Iranian server: that is common but NOT universal -")
        print("  some providers allow it. Try --spoof auto, and if that fails too,")
        print("  let the foreign side do the spoofing (the installer default).")


# --------------------------------------------------------------------------- #
# send mode
# --------------------------------------------------------------------------- #
def cmd_send(args):
    need_root()
    _unbuffer()

    peer_real = None
    try:
        peer_real = args.peer
        socket.inet_aton(peer_real)
    except OSError:
        die(f"--peer must be an IPv4 address, got {args.peer!r}")

    my_real = real_ip_towards(peer_real)
    iface = default_iface()

    raw_spoof = (args.spoof or "").strip()
    if raw_spoof.lower() in ("auto", "guess"):
        spoofs = auto_candidates(my_real)
        print(f"auto mode: trying {len(spoofs)} candidate sources in {my_real.rsplit('.', 1)[0]}.0/24")
    else:
        spoofs = [x.strip() for x in raw_spoof.split(",") if x.strip()]

    label = (args.label or "").strip()
    pre = f"{label}__" if label else ""
    print(f"local interface : {iface}")
    print(f"local real ip   : {my_real}")
    print(f"peer            : {peer_real}:{args.port}")
    print(f"label           : {label or '(none)'}")
    print(f"spoof sources   : {', '.join(spoofs) if spoofs else '(none, control only)'}")
    print()

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def fire(src_ip, tag, size, idx):
        payload = make_payload(tag, size, idx)
        pkt = build_packet(src_ip, peer_real, random.randint(20000, 60000), args.port, payload)
        try:
            s.sendto(pkt, (peer_real, 0))
            return True
        except OSError as exc:
            print(f"  send failed for {tag}: {exc}")
            return False

    def burst(src_ip, tag, size, count, gap):
        sent = 0
        for i in range(count):
            if fire(src_ip, tag, size, i):
                sent += 1
            time.sleep(gap)
        return sent

    print(f"1) control burst with the real source ({my_real})")
    c = burst(my_real, pre + "CTRL", 200, args.count, args.gap)
    print(f"   sent {c}/{args.count}")

    for idx, ip in enumerate(spoofs):
        tag = pre + f"SPF{idx}"
        print(f"2.{idx + 1}) spoof burst with source {ip}  (tag {tag})")
        n = burst(ip, tag, 200, args.count, args.gap)
        print(f"   sent {n}/{args.count}")
        # if the kernel/hypervisor rejects the spoof, it usually still reports success,
        # so the listener's view is the real answer.

    print(f"3) size ladder from {spoofs[0] if spoofs else my_real} (looking for path filtering)")
    src = spoofs[0] if spoofs else my_real
    for size in args.sizes:
        n = burst(src, pre + f"SZ{size}", size, max(3, args.count // 2), args.gap)
        print(f"   {size:>5} B payload -> sent {n}")

    s.close()
    print()
    print("done. check the output on the LISTENING server now.")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="Test whether this server can spoof source IPs before installing a tunnel.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser("listen", help="receive the test packets on the peer")
    lp.add_argument("--port", type=int, default=2390)
    lp.add_argument("--bind", default="0.0.0.0")
    lp.add_argument("--duration", type=int, default=120, help="seconds to listen (default 120)")
    lp.add_argument("--label", default="", help="only used for display; senders label themselves")
    lp.set_defaults(func=cmd_listen)

    sp = sub.add_parser("send", help="send test packets towards the peer")
    sp.add_argument("--peer", required=True, help="public IP of the listening server")
    sp.add_argument("--port", type=int, default=2390)
    sp.add_argument("--spoof", default="",
                    help="comma separated source IPs, or 'auto' to try several in your own /24")
    sp.add_argument("--label", default="", help="prefix so several senders are told apart in one listener")
    sp.add_argument("--count", type=int, default=10, help="packets per test (default 10)")
    sp.add_argument("--gap", type=float, default=0.15, help="seconds between packets")
    sp.add_argument("--sizes", default="200,600,1000,1300,1472",
                    help="size ladder, comma separated payload bytes")
    sp.set_defaults(func=cmd_send)

    args = ap.parse_args()
    if getattr(args, "sizes", None) and isinstance(args.sizes, str):
        args.sizes = [int(x) for x in args.sizes.split(",") if x.strip()]
    args.func(args)


if __name__ == "__main__":
    main()
