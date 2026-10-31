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


def real_ip_towards(peer):
    """Local source IP the kernel would use to reach peer."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((peer, 9))
        return s.getsockname()[0]
    finally:
        s.close()


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
    print(f"{'tag':<8}{'size':>6}{'received':>10}  observed source ip")
    print("=" * 78)
    for tag in sorted(groups):
        for size, srcs in sorted(groups[tag]):
            total = sum(srcs.values())
            src_txt = ", ".join(f"{ip} x{n}" for ip, n in sorted(srcs.items()))
            print(f"{tag:<8}{size:>6}{total:>10}  {src_txt}")
    print()

    # ---------- verdict ----------
    def observed(tag, size):
        return seen.get((tag, size), {})

    ctrl_srcs = {}
    for (tag, size), srcs in seen.items():
        if tag == "CTRL":
            for ip, n in srcs.items():
                ctrl_srcs[ip] = ctrl_srcs.get(ip, 0) + n

    print("=" * 78)
    print("VERDICT")
    print("=" * 78)

    if not ctrl_srcs:
        print("control packets never arrived -> the two servers cannot reach each")
        print("other on this UDP port at all. Fix reachability/firewall first.")
        return

    print(f"path works: control packets arrived from {', '.join(ctrl_srcs)}")

    any_ok = False
    spoof_tags = [t for t in sorted(groups) if t not in ("CTRL",) and not t.startswith("SZ")]
    if not spoof_tags:
        print("no spoofed packet arrived at all.")
        print("  the packets either left with your real source (see table) or were")
        print("  dropped upstream because the source address is not yours.")
        print("  -> treat this side as NOT spoof-capable.")
    for tag in spoof_tags:
        srcs = {}
        for size, s_ in groups[tag]:
            for ip, n in s_.items():
                srcs[ip] = srcs.get(ip, 0) + n
        if not srcs:
            print(f"{tag}: nothing arrived -> spoofed packets are dropped on the way out")
            continue
        only_peer_real = set(srcs) <= set(ctrl_srcs)
        if only_peer_real:
            print(f"{tag}: arrived as the sender's REAL ip -> spoofing is rewritten/blocked")
        else:
            print(f"{tag}: arrived as {', '.join(sorted(set(srcs) - set(ctrl_srcs)))}  <-- SPOOF WORKS")
            any_ok = True

    # ---------- size ladder ----------
    ladder = {}
    for (tag, size), srcs in seen.items():
        if tag.startswith("SZ"):
            ladder[size] = ladder.get(size, 0) + sum(srcs.values())
    if not ladder:
        print()
        print("size ladder: nothing arrived for any size -> the path drops these")
        print("  packets entirely (source filter, not size filter).")
    if ladder:
        print()
        print("size ladder (large UDP must survive or tunnels break under load):")
        worst = 1.0
        for size in sorted(ladder):
            got = ladder[size]
            # the sender sends max(3, count//2) packets of each size; we only
            # know what arrived, so report raw counts and flag suspicious gaps
            print(f"  {size:>5} B payload : {got} arrived")
            if got == 0:
                worst = 0.0
        if worst == 0.0:
            print("  >>> some sizes arrived in ZERO - the path filters large UDP packets.")
            print("      Lower the tunnel MTU, or this path cannot carry the tunnel.")
        elif min(ladder.values()) < max(ladder.values()) / 2:
            print("  >>> delivery drops with size - likely size filtering.")
            print("      Try --mtu 1360 or 1300 before giving up on this path.")

    print()
    print("next step:")
    if any_ok:
        print("  spoofing is available - install the tunnel with the working IP:")
        print("    sudo ./scripts/install.sh --role server --peer <PEER> --spoof <WORKING_IP>")
    else:
        print("  spoofing is NOT available from this side. That is normal for the")
        print("  Iranian server: put its real IP in the spoof list and let the foreign")
        print("  side do the spoofing (the installer defaults do exactly this).")


# --------------------------------------------------------------------------- #
# send mode
# --------------------------------------------------------------------------- #
def cmd_send(args):
    need_root()
    _unbuffer()

    spoofs = []
    for item in (args.spoof or "").split(","):
        item = item.strip()
        if item:
            spoofs.append(item)

    peer_real = None
    try:
        peer_real = args.peer
        socket.inet_aton(peer_real)
    except OSError:
        die(f"--peer must be an IPv4 address, got {args.peer!r}")

    my_real = real_ip_towards(peer_real)
    iface = default_iface()
    print(f"local interface : {iface}")
    print(f"local real ip   : {my_real}")
    print(f"peer            : {peer_real}:{args.port}")
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
    c = burst(my_real, "CTRL", 200, args.count, args.gap)
    print(f"   sent {c}/{args.count}")

    for idx, ip in enumerate(spoofs):
        tag = f"SPF{idx}"
        print(f"2.{idx + 1}) spoof burst with source {ip}  (tag {tag})")
        n = burst(ip, tag, 200, args.count, args.gap)
        print(f"   sent {n}/{args.count}")
        # if the kernel/hypervisor rejects the spoof, it usually still reports success,
        # so the listener's view is the real answer.

    print(f"3) size ladder from {spoofs[0] if spoofs else my_real} (looking for path filtering)")
    src = spoofs[0] if spoofs else my_real
    for size in args.sizes:
        n = burst(src, f"SZ{size}", size, max(3, args.count // 2), args.gap)
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
    lp.set_defaults(func=cmd_listen)

    sp = sub.add_parser("send", help="send test packets towards the peer")
    sp.add_argument("--peer", required=True, help="public IP of the listening server")
    sp.add_argument("--port", type=int, default=2390)
    sp.add_argument("--spoof", default="", help="comma separated source IPs to try")
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
