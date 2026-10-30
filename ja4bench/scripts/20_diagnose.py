#!/usr/bin/env python3
"""Audit one or more canonical tables before any training.

  python scripts/20_diagnose.py --in data/canonical/matousek2024.csv.gz --out results/audit_matousek
"""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ja4bench.diagnostics import audit, to_markdown  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--in", dest="inp", nargs="+", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--domain-col", default="platform")
ap.add_argument("--tcp-only", action="store_true", help="drop QUIC rows (project scope is TCP/TLS)")
ap.add_argument("--exclude-flag", action="append", default=[], help="drop rows where this 0/1 column is 1")
a = ap.parse_args()

df = pd.concat([pd.read_csv(p, low_memory=False) for p in a.inp], ignore_index=True)
if a.tcp_only:
    df = df[df["proto"] == "tcp"]
for f in a.exclude_flag:
    df = df[df[f].fillna(0).astype(int) == 0]
r = audit(df, a.domain_col)
out = Path(a.out)
out.mkdir(parents=True, exist_ok=True)
(out / "AUDIT.md").write_text(to_markdown(r))
scalars = {k: v for k, v in r.items() if not isinstance(v, pd.DataFrame)}
(out / "audit.json").write_text(json.dumps(scalars, indent=2, default=str))
print(to_markdown(r))
