"""
Sensor tests that only real captures exercise (the synthetic corpus bypasses
pcap parsing through replay_records, so none of these can fail there).

Run:  python3 tests/test_real_pcap_sensor.py
Optional full JA4 check against FoxIO's reference captures:
      git clone https://github.com/FoxIO-LLC/ja4 /tmp/ja4
      FOXIO_JA4_DIR=/tmp/ja4 python3 tests/test_real_pcap_sensor.py
"""
import glob
import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from idps.ja4 import (compute_ja4, parse_client_hello, stack_key,  # noqa: E402
                      synth_client_hello)
from idps.module2_sensor.flow import FlowTable  # noqa: E402
from idps.module2_sensor.sources import _iter_frames, _parse_frame  # noqa: E402


def _eth_ip_tcp(src, dst, sport, dport, payload=b"", flags=0x18, pad=0):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
                     bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp + payload + b"\x00" * pad


def _hello(sig_algs=(0x0403, 0x0804, 0x0401), big=False):
    """A ClientHello with chosen signature algorithms; `big` adds a 1.8 kB extension."""
    body = struct.pack("!H", 0x0303) + bytes(32) + b"\x00"
    cs = struct.pack("!HHH", 0x1301, 0x1302, 0xC02B)
    body += struct.pack("!H", len(cs)) + cs + b"\x01\x00"
    sa = b"".join(struct.pack("!H", a) for a in sig_algs)
    exts = struct.pack("!HH", 0x000D, len(sa) + 2) + struct.pack("!H", len(sa)) + sa
    exts += struct.pack("!HH", 0x002B, 3) + b"\x02\x03\x04"
    if big:
        exts += struct.pack("!HH", 0x0033, 1800) + bytes(1800)
    exts += struct.pack("!HH", 0x0017, 0)
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def test_ethernet_padding_is_not_payload():
    frame = _eth_ip_tcp("10.0.0.5", "93.184.216.34", 50000, 443, b"", flags=0x10, pad=6)
    parsed = _parse_frame(frame)
    assert parsed is not None and parsed[4] == 0 and parsed[5] == b""


def test_direction_does_not_depend_on_address_order():
    """Client 192.168.1.9 sorts AFTER server 104.16.0.1 as a string."""
    for cli, srv in (("192.168.1.9", "104.16.0.1"), ("10.0.0.5", "93.184.216.34")):
        t = FlowTable()
        t.observe(cli, 50000, srv, 443, 0.0, 0, b"", syn=True)
        t.observe(srv, 443, cli, 50000, 0.01, 0, b"", syn=True, ack=True)
        h = _hello()
        f = t.observe(cli, 50000, srv, 443, 0.02, len(h), h)
        t.observe(srv, 443, cli, 50000, 0.03, 100, b"\x16" + bytes(99))
        assert (f.src_ip, f.src_port, f.dst_ip, f.dst_port) == (cli, 50000, srv, 443)
        assert f.client_hello is not None
        assert [p.forward for p in f.packets] == [True, False]


def test_block_target_is_the_client_not_the_server():
    t = FlowTable()
    t.observe("192.168.1.9", 50000, "104.16.0.1", 443, 0.0, 0, b"", syn=True)
    f = t.observe("104.16.0.1", 443, "192.168.1.9", 50000, 0.01, 50, bytes(50))
    assert f.src_ip == "192.168.1.9" and f.dst_ip == "104.16.0.1"


def test_midflow_capture_falls_back_then_corrects():
    t = FlowTable()
    f = t.observe("104.16.0.1", 443, "192.168.1.9", 50000, 0.0, 50, bytes(50))
    assert f.src_ip == "192.168.1.9" and f.packets[0].forward is False
    t2 = FlowTable()                       # server on a high port, client hello decides
    f2 = t2.observe("10.0.0.1", 60000, "10.0.0.2", 1024, 0.0, 10, bytes(10))
    assert f2.src_ip == "10.0.0.1"
    h = _hello()
    t2.observe("10.0.0.2", 1024, "10.0.0.1", 60000, 0.1, len(h), h)
    assert f2.src_ip == "10.0.0.2" and [p.forward for p in f2.packets] == [False, True]


def test_ja4_c_keeps_signature_algorithm_order_and_separator():
    a = parse_client_hello(_hello((0x0403, 0x0804, 0x0401)))
    b = parse_client_hello(_hello((0x0804, 0x0403, 0x0401)))
    assert compute_ja4(a) != compute_ja4(b)          # order matters
    import hashlib
    want = hashlib.sha256(b"000d,0017,002b_0403,0804,0401").hexdigest()[:12]
    assert compute_ja4(a).split("_")[2] == want
    assert stack_key(a) == "t13_" + "_".join(compute_ja4(a).split("_")[1:])


def test_truncated_client_hello_is_refused():
    h = _hello(big=True)
    assert parse_client_hello(h) is not None
    assert parse_client_hello(h[:1400]) is None


def test_split_client_hello_is_reassembled():
    h = _hello(big=True)
    whole = compute_ja4(parse_client_hello(h))
    t = FlowTable()
    t.observe("10.0.0.5", 50000, "93.184.216.34", 443, 0.0, 0, b"", syn=True)
    f = t.observe("10.0.0.5", 50000, "93.184.216.34", 443, 0.01, 1400, h[:1400])
    assert f.client_hello is None
    t.observe("10.0.0.5", 50000, "93.184.216.34", 443, 0.01, 1400, h[:1400])   # retransmit
    t.observe("10.0.0.5", 50000, "93.184.216.34", 443, 0.02, len(h) - 1400, h[1400:])
    assert f.client_hello == h and compute_ja4(parse_client_hello(f.client_hello)) == whole


def test_synthetic_hello_still_parses():
    info = parse_client_hello(synth_client_hello("chrome"))
    assert info is not None and info.has_ech and compute_ja4(info).startswith("t13i")


def test_foxio_reference_captures():
    """JA4 from the sensor's own pcap path vs FoxIO's published outputs."""
    repo = os.environ.get("FOXIO_JA4_DIR")
    if not repo:
        print("  (skipped: set FOXIO_JA4_DIR to a clone of FoxIO-LLC/ja4)")
        return
    ok = wrong = missing = 0
    bad = []
    for exp_f in sorted(glob.glob(os.path.join(repo, "python/test/testdata/*.json"))):
        pcap = os.path.join(repo, "pcap", os.path.basename(exp_f)[:-5])
        want = {(r["src"], int(r["srcport"]), r["dst"], int(r["dstport"])): r["JA4.1"]
                for r in json.load(open(exp_f))
                if r.get("JA4.1", "").startswith("t") and ":" not in r.get("src", ":")}
        if not want or not os.path.exists(pcap):
            continue
        t = FlowTable(idle_timeout=1e12)
        for src, sport, dst, dport, ts, size, payload, syn, ack in _iter_frames(pcap):
            t.observe(src, sport, dst, dport, ts, size, payload, syn=syn, ack=ack)
        got = {}
        for f in t.flows.values():
            info = parse_client_hello(f.client_hello) if f.client_hello else None
            if info is not None:
                got[(f.src_ip, f.src_port, f.dst_ip, f.dst_port)] = compute_ja4(info)
        for k, w in want.items():
            if k not in got:
                missing += 1
            elif got[k] == w:
                ok += 1
            else:
                wrong += 1
                bad.append((os.path.basename(pcap), k, w, got[k]))
    print(f"  FoxIO reference: {ok} correct, {wrong} wrong, {missing} not parsed (IPv4/TCP rows)")
    for b in bad[:10]:
        print("   WRONG", b)
    assert wrong == 0 and ok >= 100


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except Exception as e:  # noqa: BLE001
                fails += 1
                print("FAIL", name, repr(e))
    sys.exit(1 if fails else 0)
