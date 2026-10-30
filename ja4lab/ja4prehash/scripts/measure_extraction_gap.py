"""
Quantify what a NAIVE per-packet ClientHello parser gets wrong compared to our reassembling
extractor. Gives you a small but concrete "data-quality" table for the paper:

  - ClientHellos missed because they span several TCP segments (post-quantum key shares!)
  - Connections counted twice because of retransmitted ClientHellos
  - Inflation of "unique fingerprint" counts when counting per packet / per run

    python scripts/measure_extraction_gap.py --pcap-root data/raw --out results/extraction_gap.csv
"""
import argparse
import sys
from pathlib import Path

import dpkt
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ja4lab import tlsparse as tp  # noqa: E402
from ja4lab.extract import PCAP_EXT, _open_reader, _to_ip, process_pcap  # noqa: E402


def naive(path):
    """Per-packet: parse a ClientHello only if it is complete inside ONE TCP payload."""
    hits, partial = [], 0
    with open(path, "rb") as f:
        r = _open_reader(f)
        lt = r.datalink()
        try:
            for _, buf in r:
                ip = _to_ip(buf, lt)
                if ip is None or not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                p = bytes(ip.data.data)
                if len(p) < 9 or p[0] != 0x16 or p[5] != 0x01:
                    continue
                rlen = int.from_bytes(p[3:5], "big")
                hlen = int.from_bytes(p[6:9], "big")
                if len(p) < 5 + rlen or rlen < 4 + hlen:
                    partial += 1
                    continue
                try:
                    ch = tp.parse_client_hello(p[9:9 + hlen])
                    hits.append(tp.ja4_from_ch(ch)["ja4"])
                except ValueError:
                    partial += 1
        except Exception:
            pass
    return hits, partial


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-root", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rows = []
    for p in sorted(x for x in Path(a.pcap_root).rglob("*") if x.suffix.lower() in PCAP_EXT):
        hits, partial = naive(str(p))
        ours, _ = process_pcap(str(p), {})
        tls = [r for r in ours if r.get("kind") == "tls"]
        rows.append({
            "pcap": str(p),
            "naive_clienthello_packets": len(hits),
            "naive_missed_split_or_truncated": partial,
            "reassembled_connections": len(tls),
            "reassembled_multi_segment": sum(int(r["ch_tcp_segments"]) > 1 for r in tls),
            "connections_with_retransmitted_data": sum(int(r["c_retrans_segments"]) > 0 for r in tls),
            "naive_unique_ja4": len(set(hits)),
            "reassembled_unique_ja4": len({r["ja4"] for r in tls}),
        })
    df = pd.DataFrame(rows)
    tot = df.drop(columns=["pcap"]).sum()
    tot["pcap"] = "TOTAL (unique counts are per-file sums)"
    df = pd.concat([df, tot.to_frame().T], ignore_index=True)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(a.out, index=False)
    print(df.tail(1).T.to_string())


if __name__ == "__main__":
    main()
