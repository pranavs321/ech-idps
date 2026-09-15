#!/usr/bin/env python3
"""
Step 1 -- build the ECH-era mimicry corpus.

Generates flows, runs them through the real Module 2 extractor, and writes:

    artifacts/dataset.npz    feature matrix, labels, declared class, JA4,
                             population, shaping level and the measured
                             attacker costs
    artifacts/demo.pcap      a real capture file for the live demo, so the
                             sensor path gets exercised off the wire

Usage:
    python3 scripts/01_generate_dataset.py
    python3 scripts/01_generate_dataset.py --benign 20000 --mimicry 8000
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

import numpy as np

from datasets.generator import generate, to_pcap
from idps.features import FEATURE_NAMES
from idps.module2_sensor.extractor import extract


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", type=int, default=24000)
    ap.add_argument("--naive", type=int, default=2600)
    ap.add_argument("--mimicry", type=int, default=10800)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--pcap-flows", type=int, default=600,
                    help="how many flows to also write out as a real PCAP")
    ap.add_argument("--out", default=str(ROOT / "artifacts"))
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    print(f"generating flows  benign={args.benign} naive={args.naive} "
          f"mimicry={args.mimicry}")
    flows = generate(n_benign=args.benign, n_malware_naive=args.naive,
                     n_malware_mimicry=args.mimicry, seed=args.seed)
    print(f"  {len(flows)} flows in {time.time() - t0:.1f}s")

    print("extracting 14-D vectors through the Module 2 sensor path")
    X, y, declared, ja4s, pops, shaping, phis, latency, overhead = [], [], [], [], [], [], [], [], []
    dropped = 0
    for gf in flows:
        rec = extract(gf.flow)
        if rec is None:
            dropped += 1
            continue
        X.append(rec.features)
        y.append(gf.label)
        declared.append(rec.declared)
        ja4s.append(rec.ja4 or "")
        pops.append(gf.population)
        shaping.append(gf.shaping)
        phis.append(gf.phi)
        latency.append(gf.added_latency_ms)
        overhead.append(gf.padding_overhead)

    X = np.asarray(X, dtype=np.float32)
    y = np.asarray(y, dtype=np.int8)
    print(f"  {len(X)} records, {dropped} flows too short to score")

    path = out / "dataset.npz"
    np.savez_compressed(
        path, X=X, y=y,
        declared=np.array(declared), ja4=np.array(ja4s),
        population=np.array(pops), shaping=np.asarray(shaping, dtype=np.float32),
        phi=np.asarray(phis, dtype=np.float32),
        latency_ms=np.asarray(latency, dtype=np.float32),
        overhead=np.asarray(overhead, dtype=np.float32),
        feature_names=np.array(FEATURE_NAMES))
    print(f"wrote {path}  ({path.stat().st_size / 1e6:.1f} MB)")

    if args.pcap_flows > 0:
        pcap = out / "demo.pcap"
        print(f"writing {args.pcap_flows} flows to {pcap}")
        to_pcap(flows, str(pcap), limit=args.pcap_flows)
        print(f"wrote {pcap}  ({pcap.stat().st_size / 1e6:.1f} MB)")

    print("\nclass balance")
    for pop in sorted(set(pops)):
        n = sum(1 for p in pops if p == pop)
        print(f"  {pop:<20s} {n:6d}  ({n / len(pops) * 100:5.1f}%)")
    print(f"\ndone in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
