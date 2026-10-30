"""
Stress test for the TCP reassembly logic: take a real 2 KB post-quantum Chrome ClientHello,
cut it into small segments, shuffle them, inject retransmissions, and check the JA4 is identical
to the clean capture and that the connection is counted exactly once.

    python tests/test_reassembly.py
"""
import random
import socket
import sys
import tempfile
from pathlib import Path

import dpkt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ja4lab.extract import process_pcap, Direction  # noqa: E402

SRC = Path(__file__).resolve().parents[1] / "third_party/ja4-main/pcap/sigalg-grease.pcapng"


def client_hello_bytes() -> bytes:
    """Rebuild the client->server byte stream of the first TLS connection in the sample."""
    with open(SRC, "rb") as f:
        r = dpkt.pcapng.Reader(f)
        lt = r.datalink()
        flows = {}
        for _, buf in r:
            eth = dpkt.ethernet.Ethernet(buf) if lt == 1 else None
            ip = eth.data if eth else None
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)) or not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            t = ip.data
            if t.dport == 443 and t.data:
                d = flows.setdefault((t.sport,), Direction())
                d.add(t.seq, bytes(t.data))
        for d in flows.values():
            data, _ = d.contiguous()
            if data[:1] == b"\x16" and len(data) > 1500:
                return data
    raise SystemExit("no large ClientHello found")


def write_pcap(path, ch: bytes, seg=300, shuffle=False, retrans=0, seed=1):
    rnd = random.Random(seed)
    c, s = socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2")
    isn, sisn = 1000, 5000

    def pkt(src, dst, sp, dp, seq, ack, flags, data=b"", opts=b""):
        t = dpkt.tcp.TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags, win=64240,
                         opts=opts, data=data)
        t.off = (20 + len(opts)) // 4
        ip = dpkt.ip.IP(src=src, dst=dst, p=6, ttl=64, data=t)
        ip.len = len(ip)
        return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x11" * 6, type=0x0800, data=ip))

    synopts = bytes.fromhex("020405b40402080a0000000000000000010303")
    synopts += b"\x00" * ((4 - len(synopts) % 4) % 4)
    frames = [pkt(c, s, 40000, 443, isn, 0, dpkt.tcp.TH_SYN, opts=synopts),
              pkt(s, c, 443, 40000, sisn, isn + 1, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)]
    segs = [(isn + 1 + i, ch[i:i + seg]) for i in range(0, len(ch), seg)]
    order = segs[:]
    if shuffle:
        rnd.shuffle(order)
    for _ in range(retrans):
        order.insert(rnd.randrange(len(order) + 1), rnd.choice(segs))
    frames += [pkt(c, s, 40000, 443, q, sisn + 1, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, d) for q, d in order]
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for i, fr in enumerate(frames):
            w.writepkt(fr, ts=1_700_000_000 + i * 0.001)


def main():
    ch = client_hello_bytes()
    tmp = Path(tempfile.mkdtemp())
    ok = True
    base = None
    for name, kw in [("clean_1seg", dict(seg=4000)), ("clean_7seg", dict(seg=300)),
                     ("shuffled", dict(seg=300, shuffle=True)),
                     ("shuffled+5retrans", dict(seg=300, shuffle=True, retrans=5)),
                     ("tiny_segments+retrans", dict(seg=64, shuffle=True, retrans=10, seed=7))]:
        p = tmp / f"{name}.pcap"
        write_pcap(p, ch, **kw)
        rows, _ = process_pcap(str(p), {})
        tls = [r for r in rows if r.get("kind") == "tls"]
        fp = tls[0]["ja4"] if tls else None
        base = base or fp
        good = len(tls) == 1 and fp == base
        ok &= good
        print(f"{name:24s} connections={len(tls)} ja4={fp} segments={tls[0]['ch_tcp_segments'] if tls else '-'}"
              f" retrans_seen={tls[0]['c_retrans_segments'] if tls else '-'}  {'PASS' if good else 'FAIL'}")
    print("ALL PASS" if ok else "SOME FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
