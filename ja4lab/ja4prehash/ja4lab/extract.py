"""
PCAP -> one row per TCP connection with JA4 / JA4S / JA4T / JA4TS / JA4H and all pre-hash parts.

Robustness features (these matter and are worth a paragraph in the paper):
  * TCP reassembly: modern ClientHellos (e.g. Chrome with the post-quantum X25519MLKEM768
    key share, ~1.7 KB) span 2+ TCP segments. Per-packet parsers silently miss them.
  * Retransmission / duplicate-segment handling: a retransmitted ClientHello is counted
    ONCE per connection, not once per packet (this is why per-packet counting inflates
    "unique fingerprint" numbers).
  * Out-of-order segments are placed by sequence number.
  * TLS handshake messages split across several TLS records are joined.
  * Link types: Ethernet (+VLAN), Linux SLL/SLL2, raw IP, BSD loopback.

Usage:
    python -m ja4lab.extract --pcap-root data/raw --out data/interim/connections.csv --workers 4
Folder convention (label comes from the path, see README):
    data/raw/<benign|malicious>/<source>/<family_or_app>/<file>.pcap(ng)
"""
from __future__ import annotations

import argparse
import csv
import os
import socket
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import dpkt

from . import tlsparse as tp

MAX_BYTES_PER_DIR = 24_000     # enough for a ClientHello / ServerHello even with big key shares
MAX_DATA_PKTS_PER_DIR = 256   # tiny-MSS / fragmented handshakes need many segments
PCAP_EXT = {".pcap", ".pcapng", ".cap", ".dmp"}


# ----------------------------------------------------------------------------- reading

def _open_reader(f):
    magic = f.read(4)
    f.seek(0)
    if magic == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(f)
    return dpkt.pcap.Reader(f)


def _to_ip(buf: bytes, linktype: int):
    try:
        if linktype == 1:                                   # Ethernet
            eth = dpkt.ethernet.Ethernet(buf)
            return eth.data if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
        if linktype == 113:                                 # Linux cooked v1
            return dpkt.sll.SLL(buf).data
        if linktype == 276:                                 # Linux cooked v2
            return dpkt.sll2.SLL2(buf).data
        if linktype in (0, 108):                            # BSD loopback / NULL
            fam = int.from_bytes(buf[:4], "little")
            b = buf[4:]
            return dpkt.ip6.IP6(b) if fam in (24, 28, 30) else dpkt.ip.IP(b)
        if linktype in (101, 12, 14, 228, 229):             # raw IP
            return dpkt.ip6.IP6(buf) if (buf[0] >> 4) == 6 else dpkt.ip.IP(buf)
    except Exception:
        return None
    return None


def _addr(ip) -> str:
    if isinstance(ip, dpkt.ip6.IP6):
        return socket.inet_ntop(socket.AF_INET6, ip.src), socket.inet_ntop(socket.AF_INET6, ip.dst)
    return socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)


# ----------------------------------------------------------------------------- reassembly

class Direction:
    __slots__ = ("isn", "segs", "npkts", "retrans", "done", "nbytes")

    def __init__(self):
        self.isn = None          # first payload byte sequence number
        self.segs = {}           # rel_seq -> bytes
        self.npkts = 0
        self.retrans = 0
        self.done = False
        self.nbytes = 0

    def add(self, seq: int, payload: bytes):
        if self.done or not payload:
            return False
        if self.isn is None:
            self.isn = seq
        rel = (seq - self.isn) & 0xFFFFFFFF
        if rel > 0x7FFFFFFF:          # segment before our assumed start (out-of-order first pkt)
            shift = (self.isn - seq) & 0xFFFFFFFF
            self.segs = {k + shift: v for k, v in self.segs.items()}
            self.isn, rel = seq, 0
        if rel >= MAX_BYTES_PER_DIR:
            return False
        if rel in self.segs:
            self.retrans += 1
            if len(payload) <= len(self.segs[rel]):
                return False
        self.segs[rel] = payload
        self.npkts += 1
        self.nbytes += len(payload)
        if self.npkts >= MAX_DATA_PKTS_PER_DIR:
            self.done = True
        return True

    def contiguous(self) -> tuple[bytes, int]:
        """Return the contiguous byte stream from offset 0, and the number of segments used."""
        out, pos, used = bytearray(), 0, 0
        for k in sorted(self.segs):
            v = self.segs[k]
            if k > pos:
                break
            if k + len(v) > pos:
                out += v[pos - k:]
                pos = k + len(v)
                used += 1
        return bytes(out), used


def first_handshake_msg(stream: bytes, want_type: int):
    """Walk TLS records, join handshake fragments, return (body, n_records) of first msg of type."""
    i, hs, nrec = 0, bytearray(), 0
    while i + 5 <= len(stream):
        ctype, rlen = stream[i], int.from_bytes(stream[i + 3:i + 5], "big")
        if ctype not in (20, 21, 22, 23) or stream[i + 1] != 3:
            return None, nrec, "not_tls"
        if i + 5 + rlen > len(stream):
            break
        if ctype == 22:
            hs += stream[i + 5:i + 5 + rlen]
            nrec += 1
        i += 5 + rlen
        j = 0
        while j + 4 <= len(hs):
            mtype, mlen = hs[j], int.from_bytes(hs[j + 1:j + 4], "big")
            if j + 4 + mlen > len(hs):
                break
            if mtype == want_type:
                return bytes(hs[j + 4:j + 4 + mlen]), nrec, i
            j += 4 + mlen
        if ctype != 22 and not hs:
            return None, nrec, "no_handshake"
    return None, nrec, "incomplete"


class Conn:
    __slots__ = ("key", "cli", "srv", "ts", "c", "s", "syn", "synack", "ttl",
                 "ch", "sh", "http", "ch_segments", "ch_records", "tunnel_offset")

    def __init__(self, key, ts):
        self.key = key
        self.cli = self.srv = None
        self.ts = ts
        self.c, self.s = Direction(), Direction()
        self.syn = self.synack = None
        self.ttl = None
        self.ch = self.sh = self.http = None
        self.ch_segments = self.ch_records = 0
        self.tunnel_offset = 0


def _try_parse(conn: Conn):
    if conn.ch is None and conn.http is None and conn.c.segs:
        data, used = conn.c.contiguous()
        if not data:
            pass                        # first segment not seen yet (out of order): wait
        elif tp.looks_like_http_request(data):
            h = tp.ja4h_from_request(data)
            if h:
                conn.http = h
                conn.c.done = True
        elif data[:1] == b"\x16":
            body, nrec, st = first_handshake_msg(data, 1)
            if body is not None:
                try:
                    conn.ch = tp.parse_client_hello(body)
                    conn.ch_segments = sum(1 for k in conn.c.segs if k < st)
                    conn.ch_records = nrec
                except ValueError:
                    pass
                conn.c.done = True
            elif st == "not_tls":
                conn.c.done = True
        else:
            # Tunnelled TLS (SOCKS4/5 etc.): look for a TLS handshake record a little later
            off = data.find(b"\x16\x03", 0, 1024)
            if off > 0:
                body, nrec, st = first_handshake_msg(data[off:], 1)
                if body is not None:
                    try:
                        conn.ch = tp.parse_client_hello(body)
                        conn.ch_segments = sum(1 for k in conn.c.segs if k < st + off)
                        conn.ch_records = nrec
                        conn.tunnel_offset = off
                    except ValueError:
                        pass
                    conn.c.done = True
            elif len(data) > 1024 or conn.c.npkts > 6:
                conn.c.done = True
    if conn.ch is not None and conn.sh is None and conn.s.segs:
        data, _ = conn.s.contiguous()
        if not data:
            return
        if data[:1] != b"\x16":
            off = data.find(b"\x16\x03", 0, 1024)
            if off < 0:
                if len(data) > 1024 or conn.s.npkts > 6:
                    conn.s.done = True
                return
            data = data[off:]
        body, _, st = first_handshake_msg(data, 2)
        if body is not None:
            try:
                conn.sh = tp.parse_server_hello(body)
            except ValueError:
                pass
            conn.s.done = True
        elif st == "not_tls":
            conn.s.done = True


def process_pcap(path: str, meta: dict) -> tuple[list[dict], dict]:
    conns: dict = {}
    stats = {"packets": 0, "tcp": 0, "udp443": 0, "errors": 0}
    with open(path, "rb") as f:
        try:
            rdr = _open_reader(f)
        except Exception as e:
            return [], {"error": f"cannot read: {e}"}
        linktype = rdr.datalink()
        try:
            for ts, buf in rdr:
                stats["packets"] += 1
                ip = _to_ip(buf, linktype)
                if ip is None:
                    continue
                l4 = ip.data
                if isinstance(l4, dpkt.udp.UDP):
                    if 443 in (l4.sport, l4.dport):
                        stats["udp443"] += 1          # QUIC: see README (use ja4plus for QUIC)
                    continue
                if not isinstance(l4, dpkt.tcp.TCP):
                    continue
                stats["tcp"] += 1
                src, dst = _addr(ip)
                a, b = (src, l4.sport), (dst, l4.dport)
                key = (a, b) if a < b else (b, a)
                conn = conns.get(key)
                syn = bool(l4.flags & dpkt.tcp.TH_SYN)
                ack = bool(l4.flags & dpkt.tcp.TH_ACK)
                if syn and not ack:
                    if conn is not None and (conn.ch is not None or conn.http is not None) \
                            and conn.cli == a:
                        pass   # port reuse / SYN retransmit after data: keep first connection
                    if conn is None:
                        conn = conns[key] = Conn(key, ts)
                    if conn.syn is None:
                        conn.cli, conn.srv = a, b
                        conn.syn = tp.ja4t(l4.win, bytes(l4.opts))
                        conn.c.isn = (l4.seq + 1) & 0xFFFFFFFF
                        conn.ttl = getattr(ip, "ttl", getattr(ip, "hlim", None))
                    continue
                if syn and ack:
                    if conn is None:
                        conn = conns[key] = Conn(key, ts)
                        conn.cli, conn.srv = b, a
                    if conn.synack is None:
                        conn.synack = tp.ja4t(l4.win, bytes(l4.opts))
                        if conn.s.isn is None:
                            conn.s.isn = (l4.seq + 1) & 0xFFFFFFFF
                    continue
                if not l4.data:
                    continue
                if conn is None:
                    conn = conns[key] = Conn(key, ts)
                if conn.cli is None:
                    # no handshake seen: whoever sends a ClientHello / HTTP request is the client
                    p = bytes(l4.data)
                    if p[:1] == b"\x16" and len(p) > 5 and p[5:6] == b"\x01" or \
                            tp.looks_like_http_request(p):
                        conn.cli, conn.srv = a, b
                    elif p[:1] == b"\x16" and p[5:6] == b"\x02":
                        conn.cli, conn.srv = b, a
                    else:
                        conn.cli, conn.srv = (a, b) if l4.sport > l4.dport else (b, a)
                d = conn.c if a == conn.cli else conn.s
                if d.add(l4.seq, bytes(l4.data)):
                    _try_parse(conn)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError) as e:
            stats["errors"] += 1
            stats["truncated_at_packet"] = stats["packets"]

    rows = []
    for conn in conns.values():
        if conn.ch is None and conn.http is None:
            continue
        r = dict(meta)
        r.update({
            "ts": round(conn.ts, 6),
            "src_ip": conn.cli[0], "src_port": conn.cli[1],
            "dst_ip": conn.srv[0], "dst_port": conn.srv[1],
            "ttl": conn.ttl if conn.ttl is not None else "",
            "ja4t": conn.syn["fp"] if conn.syn else "",
            "tcp_window": conn.syn["window"] if conn.syn else "",
            "tcp_options": conn.syn["options"] if conn.syn else "",
            "tcp_mss": conn.syn["mss"] if conn.syn else "",
            "tcp_wscale": conn.syn["wscale"] if conn.syn else "",
            "ja4ts": conn.synack["fp"] if conn.synack else "",
            "c_retrans_segments": conn.c.retrans,
        })
        if conn.ch is not None:
            r["kind"] = "tls"
            r.update(tp.ja4_from_ch(conn.ch))
            r.update(tp.ja3_from_ch(conn.ch))
            r.update(tp.ch_to_row(conn.ch))
            r["ch_tcp_segments"] = conn.ch_segments
            r["ch_tls_records"] = conn.ch_records
            r["tunnel_offset"] = conn.tunnel_offset
            if conn.sh is not None:
                r.update(tp.ja4s_from_sh(conn.sh))
                r.update(tp.sh_to_row(conn.sh))
        if conn.http is not None:
            r["kind"] = "http"
            r.update(conn.http)
        rows.append(r)
    stats["connections_with_fp"] = len(rows)
    return rows, stats


# ----------------------------------------------------------------------------- driver

def meta_from_path(p: Path, root: Path) -> dict:
    parts = p.relative_to(root).parts
    label = parts[0] if len(parts) > 1 else "unknown"
    return {
        "pcap": str(p.relative_to(root)),
        "label": label,                                   # benign | malicious
        "source": parts[1] if len(parts) > 2 else "unknown",
        "family": parts[2] if len(parts) > 3 else (parts[1] if len(parts) > 2 else "unknown"),
    }


def _job(args):
    path, meta = args
    rows, st = process_pcap(path, meta)
    return path, rows, st


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    a = ap.parse_args(argv)
    root = Path(a.pcap_root)
    files = sorted(p for p in root.rglob("*") if p.suffix.lower() in PCAP_EXT)
    if not files:
        sys.exit(f"No pcaps under {root}")
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    fieldnames, all_rows, log = None, [], []
    jobs = [(str(p), meta_from_path(p, root)) for p in files]
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(_job, j) for j in jobs]
        for i, fu in enumerate(as_completed(futs), 1):
            path, rows, st = fu.result()
            all_rows += rows
            log.append({"pcap": path, **st})
            print(f"[{i}/{len(files)}] {path}: {st}", flush=True)
    keys = []
    for r in all_rows:
        for k in r:
            if k not in keys:
                keys.append(k)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(all_rows)
    with open(Path(a.out).with_suffix(".log.csv"), "w", newline="") as f:
        lk = sorted({k for l in log for k in l})
        w = csv.DictWriter(f, fieldnames=lk)
        w.writeheader()
        w.writerows(log)
    print(f"Wrote {len(all_rows)} connection rows -> {a.out}")


if __name__ == "__main__":
    main()
