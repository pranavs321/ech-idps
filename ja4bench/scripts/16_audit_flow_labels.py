#!/usr/bin/env python3
"""Audit flow-level labels against the capture's OWN published IOC list.

A flow labelled ioc_c2 is accepted only if its dst_ip or SNI appears in the IOC text file mapped to
that capture. Exits 1 if the match rate is below --min-match (default 1.0) or if no flow at all is
left unlabelled (honest IOC labelling always leaves unknown flows).

  python scripts/16_audit_flow_labels.py --flows data/interim/mta2024_flows_labelled.csv \
     --capture-col pcap --dst-col dst_ip --sni-col sni --ioc-map data/meta/ioc_map.csv
ioc_map.csv: columns capture,ioc_file   (ioc_file absolute, or relative to --ioc-dir)
Build the map from the real IOC manifest AFTER printing its header; never from the flows themselves.
"""
import argparse
import re
import sys
from pathlib import Path

import pandas as pd

ap = argparse.ArgumentParser()
ap.add_argument("--flows", required=True)
ap.add_argument("--capture-col", required=True)
ap.add_argument("--dst-col", required=True)
ap.add_argument("--sni-col", required=True)
ap.add_argument("--ioc-map", required=True)
ap.add_argument("--ioc-dir", default=".")
ap.add_argument("--min-match", type=float, default=1.0)
a = ap.parse_args()

IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOM = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b")
FILE_EXT = {"exe", "dll", "zip", "js", "bat", "ps1", "txt", "doc", "docx", "xls", "xlsx", "lnk", "iso",
            "msi", "vbs", "hta", "pdf", "png", "jpg", "php", "html", "htm", "dat", "tmp", "sys", "cab"}


def norm(t: str) -> str:
    t = t.lower().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("hxxp", "http")
    return t


def load_ioc(p: Path):
    t = norm(p.read_text(errors="ignore"))
    ips = set(IP.findall(t))
    doms = {d for d in DOM.findall(t) if d.rsplit(".", 1)[-1] not in FILE_EXT and d not in ips}
    return ips, doms


def dom_match(sni, doms):
    s = str(sni).lower().strip(".")
    return bool(s) and s != "nan" and any(s == d or s.endswith("." + d) for d in doms)


fl = pd.read_csv(a.flows, dtype=str, low_memory=False)
mp = pd.read_csv(a.ioc_map, dtype=str)
for df, cols, n in [(fl, [a.capture_col, a.dst_col, a.sni_col, "label_flow", "label_flow_basis"], a.flows),
                    (mp, ["capture", "ioc_file"], a.ioc_map)]:
    miss = [c for c in cols if c not in df.columns]
    if miss:
        sys.exit(f"columns {miss} not in {n}; columns are {list(df.columns)}")

key = lambda x: Path(str(x)).name
iocs, missing_files = {}, []
for r in mp.itertuples():
    p = Path(r.ioc_file) if Path(r.ioc_file).is_absolute() else Path(a.ioc_dir) / r.ioc_file
    if p.exists():
        iocs[key(r.capture)] = load_ioc(p)
    else:
        missing_files.append(str(p))

pos = fl[fl["label_flow"] == "1"].copy()
pos["cap"] = pos[a.capture_col].map(key)
pos["has_ioc"] = pos["cap"].isin(iocs)
pos["match"] = [bool(c in iocs and (d in iocs[c][0] or dom_match(s, iocs[c][1])))
                for c, d, s in zip(pos["cap"], pos[a.dst_col], pos[a.sni_col])]
rate = pos["match"].mean() if len(pos) else float("nan")

print("label_flow_basis counts:\n", fl["label_flow_basis"].value_counts().to_string())
print(f"\nioc_c2 flows: {len(pos)}; captures with an IOC file: {pos.has_ioc.groupby(pos.cap).first().sum()}"
      f" of {pos.cap.nunique()}; IOC files listed in map but missing on disk: {len(missing_files)}")
print(f"flows whose dst_ip or SNI appears in their capture's IOC list: {pos.match.sum()} / {len(pos)}"
      f" = {rate:.3f}")
bad = pos[~pos.match]
if len(bad):
    print("\nUNMATCHED label_flow==1 rows (first 25):")
    print(bad[["cap", a.dst_col, a.sni_col, "has_ioc"]].head(25).to_string(index=False))
unk = fl["label_flow_basis"].isin(["unlabelled", "unknown"]).sum()
fail = []
if not (rate >= a.min_match):
    fail.append(f"match rate {rate:.3f} < {a.min_match}")
if unk == 0:
    fail.append("zero unlabelled/unknown flows: IOC labelling always leaves unknown flows; "
                "labels were probably derived from 'everything not background'")
print("\nRESULT:", "FAIL — " + "; ".join(fail) if fail else "PASS")
sys.exit(1 if fail else 0)
