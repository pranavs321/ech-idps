#!/usr/bin/env python3
"""Add FLOW-level labels to a ja4lab flow table using the IOC tracing already done for MTA 2024.

Why: host-level labels put the victim's own browsing into the malicious class (the top "malicious"
JA4 in ja4lab was a Chrome fingerprint). Flow-level labels fix that AND create an environment-matched
test inside every capture: same host, same OS, same minutes.

Rule (append-only; existing label columns are never touched):
  label_flow =  1  (basis ioc_c2)        src == IOC-verified victim AND (dst_ip in the capture's matched
                                         C2 IPs OR sni equals / is a subdomain of a matched C2 domain)
  label_flow =  0  (basis os_background) src == victim AND sni is an OS/browser background domain
                                         (list in ja4bench/adapters/matousek.py, kept short on purpose)
  label_flow = -1  (basis unlabelled)    everything else, including captures without an IOC victim

  python scripts/15_flow_labels_from_iocs.py \
     --flows ../ja4lab/data/interim/connections.csv --capture-col pcap --src-col src_ip \
     --dst-col dst_ip --sni-col sni \
     --hosts ../ja4lab/data/meta/infected_hosts.csv --hosts-capture-col path \
     --victim-col ioc_victim_ip --c2-col ioc_c2_matched \
     --out data/interim/mta2024_flows_labelled.csv
Column names above are examples: print the real headers first (head -1) and pass those.
"""
import argparse
import re
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ja4bench.adapters.matousek import OS_BACKGROUND_SUFFIXES  # noqa: E402

ap = argparse.ArgumentParser()
for k in ["flows", "capture-col", "src-col", "dst-col", "sni-col", "hosts", "hosts-capture-col",
          "victim-col", "c2-col", "out"]:
    ap.add_argument(f"--{k}", required=True)
a = ap.parse_args()

flows = pd.read_csv(a.flows, dtype=str, low_memory=False)
hosts = pd.read_csv(a.hosts, dtype=str)
for df, cols, name in [(flows, [a.capture_col, a.src_col, a.dst_col, a.sni_col], a.flows),
                       (hosts, [a.hosts_capture_col, a.victim_col, a.c2_col], a.hosts)]:
    missing = [c for c in cols if c not in df.columns]
    if missing:
        sys.exit(f"columns {missing} not in {name}. Columns are: {list(df.columns)}")
for c in ["label_flow", "label_flow_basis"]:
    if c in flows.columns:
        sys.exit(f"{c} already exists in {a.flows}; refusing to overwrite (append-only rule)")


def key(x):
    return Path(str(x)).name


def parse_c2(s):
    toks = [t.strip().lower().replace("[.]", ".").strip(".") for t in re.split(r"[;,|\s]+", str(s))]
    toks = [t for t in toks if t and t != "nan"]
    ips = {t for t in toks if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", t)}
    return ips, set(toks) - ips


def match_dom(sni, doms):
    s = str(sni).lower().strip(".")
    return any(s == d or s.endswith("." + d) for d in doms)


def is_bg(sni):
    return match_dom(sni, OS_BACKGROUND_SUFFIXES)


ioc = {}
for _, r in hosts.iterrows():
    v = str(r[a.victim_col]).strip()
    if v and v.lower() != "nan":
        ioc[key(r[a.hosts_capture_col])] = (v, *parse_c2(r[a.c2_col]))

lab, basis = [], []
for cap, src, dst, sni in zip(flows[a.capture_col].map(key), flows[a.src_col], flows[a.dst_col],
                              flows[a.sni_col]):
    if cap not in ioc:
        lab.append(-1); basis.append("no_ioc_victim"); continue
    victim, ips, doms = ioc[cap]
    if str(src) != victim:
        lab.append(-1); basis.append("not_victim"); continue
    if str(dst) in ips or match_dom(sni, doms):
        lab.append(1); basis.append("ioc_c2")
    elif is_bg(sni):
        lab.append(0); basis.append("os_background")
    else:
        lab.append(-1); basis.append("unlabelled")
flows["label_flow"], flows["label_flow_basis"] = lab, basis
Path(a.out).parent.mkdir(parents=True, exist_ok=True)
flows.to_csv(a.out, index=False)

tab = pd.crosstab(flows[a.capture_col].map(key), flows["label_flow_basis"])
print(tab.to_string())
print("\nTOTAL", flows["label_flow_basis"].value_counts().to_dict())
both = ((tab.get("ioc_c2", 0) > 0) & (tab.get("os_background", 0) > 0)).sum()
print(f"captures with BOTH ioc_c2 and os_background flows (usable for within-capture contrast): {both}")
print(f"captures with an IOC victim: {len(ioc)}; wrote {a.out}")
