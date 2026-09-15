#!/usr/bin/env python3
"""
Step 4 -- the live demo.

Replays the demo PCAP through the real sensor path and walks a few flows all
the way through the system: verdict, dissonance statistic, TreeSHAP receipt,
and the attribution-driven mitigation decision. This is the thing to run in
front of an examiner -- it shows the whole pipeline working on one screen.

Usage:
    python3 scripts/04_demo.py
    python3 scripts/04_demo.py --show 5    # walk 5 caught flows in full
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from idps.module2_sensor.sources import read_pcap
from idps.module4_xai.treeshap import format_receipt
from idps.pipeline import build


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default=str(ROOT / "artifacts" / "demo.pcap"))
    ap.add_argument("--show", type=int, default=3,
                    help="how many caught flows to walk through in full")
    args = ap.parse_args()

    if not Path(args.pcap).exists():
        sys.exit(f"No demo PCAP at {args.pcap}. Run scripts/01_generate_dataset.py first.")

    print("Building the system from trained artifacts...")
    idps = build(log_path=str(ROOT / "results" / "incidents.jsonl"))
    print("Replaying flows through the real Module 2 sensor path "
          f"(from {Path(args.pcap).name})\n")

    walked = 0
    total = 0
    caught = 0
    for rec in read_pcap(args.pcap):
        total += 1
        result = idps.process(rec)
        v = result.verdict
        if v.is_malicious:
            caught += 1

        # Walk the first few *caught* flows through the whole pipeline so the
        # examiner sees a verdict, a receipt and a mitigation together.
        if v.is_malicious and result.attribution is not None and walked < args.show:
            walked += 1
            print("#" * 74)
            print(f"CAUGHT FLOW #{walked}: {rec.src_ip} -> {rec.dst_ip}:{rec.dst_port}")
            print("#" * 74)
            print(format_receipt(result.attribution, v))
            if result.incident:
                dec = result.incident.decision
                print("\nMITIGATION DECISION (Module 5, attribution-driven):")
                print(f"  scope     : {dec['scope']}")
                print(f"  mechanism : {dec['mechanism']}")
                print(f"  TTL       : {dec['ttl_seconds']}s")
                print(f"  target    : {dec['target']}")
                if dec["escalation_blocked"]:
                    print("  NOTE      : a harsher (source-wide) block was VETOED "
                          "because the")
                    print("              evidence was not endpoint-intrinsic enough "
                          "to justify it.")
                print(f"  rationale : {dec['rationale']}")
            print()

    print("=" * 74)
    print("RUN SUMMARY")
    print("=" * 74)
    s = idps.soar.summary()
    print(f"  flows processed        : {total}")
    print(f"  flagged malicious      : {caught}")
    print(f"  kernel-map drops (XDP) : {s['xdp_drops']}")
    print(f"  connection resets (RST): {s['rst']}")
    print(f"  alert-only             : {s['alert_only']}")
    print(f"  escalations vetoed     : {s['escalations_blocked']}  "
          f"<- innocent co-tenants protected")
    print(f"  data-plane blocklist   : {s['blocklist_size']} entries")
    print(f"\n  by tier   : {s['by_tier']}")
    print(f"  by scope  : {s['by_scope']}")
    print(f"\nIncident log written to results/incidents.jsonl")
    print("Every decision there is auditable and can be contested after the fact.")


if __name__ == "__main__":
    main()
