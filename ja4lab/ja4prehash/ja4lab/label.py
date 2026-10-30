"""
Label hygiene. THE most important step for a credible paper.

Problem: a "malware PCAP" is NOT 100% malware traffic. A sandbox/victim VM also produces
Windows Update, telemetry, browser, certificate (OCSP/CRL) traffic. Labelling every
connection in a malware pcap as malicious teaches the model "Windows = malware".

Rules applied here (all reported in the paper):
  1. Malicious pcaps: keep only connections from the infected host(s).
     - Preferred: provide data/meta/infected_hosts.csv  (pcap,ip)  from the dataset README /
       malware-traffic-analysis.net blog post (they always state the victim IP).
     - Fallback heuristic: the most frequent TLS client IP in that pcap (flagged in output).
  2. Malicious pcaps: connections whose SNI is a well-known benign domain (Tranco top-N and an
     OS background list) are moved to label "gray" (excluded from training AND testing), because
     they are most likely OS background noise - but malware also abuses popular services, so we
     neither call them benign nor malicious. Report how many were moved.
  3. Deduplication: one "client instance" = (pcap, src_ip, full pre-hash string incl. JA4S/JA4T).
     Repeated beacons of the same client are collapsed and counted in `n_conn`.
     Evaluating on instances stops thousands of identical beacons from inflating scores.

Usage:
    python -m ja4lab.label --in data/interim/connections.csv --out data/processed/instances.csv \
        [--infected data/meta/infected_hosts.csv] [--tranco data/meta/tranco.csv --tranco-top 10000]
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

OS_BACKGROUND_SUFFIXES = [
    "microsoft.com", "windowsupdate.com", "windows.com", "msftncsi.com", "msftconnecttest.com",
    "live.com", "msn.com", "bing.com", "office.com", "office.net", "office365.com", "skype.com",
    "microsoftonline.com", "azureedge.net", "msedge.net", "digicert.com", "verisign.com",
    "sectigo.com", "usertrust.com", "letsencrypt.org", "lencr.org", "globalsign.com",
    "gstatic.com", "googleapis.com", "google.com", "mozilla.com", "mozilla.org", "firefox.com",
    "apple.com", "icloud.com", "akamaihd.net", "akamaized.net", "adobe.com",
]


def reg_domain(host: str) -> str:
    """Cheap eTLD+1 (good enough for filtering; use `tldextract` for exact PSL handling)."""
    h = (host or "").lower().strip(".")
    parts = h.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "net", "org", "ac", "gov", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def load_allowlist(tranco: str | None, top: int) -> set[str]:
    allow = set(OS_BACKGROUND_SUFFIXES)
    if tranco and Path(tranco).exists():
        t = pd.read_csv(tranco, header=None, names=["rank", "domain"], nrows=top)
        allow |= set(t["domain"].str.lower())
    return allow


def is_allowlisted(sni: str, allow: set[str]) -> bool:
    if not isinstance(sni, str) or not sni:
        return False
    s = sni.lower()
    return reg_domain(s) in allow or any(s == a or s.endswith("." + a) for a in OS_BACKGROUND_SUFFIXES)


INSTANCE_KEY = ["pcap", "src_ip", "ja4_ro", "ja4s_r", "ja4t", "ja4h_r"]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--infected")
    ap.add_argument("--tranco")
    ap.add_argument("--tranco-top", type=int, default=10000)
    ap.add_argument("--keep-connections", action="store_true",
                    help="also write the cleaned connection-level file")
    a = ap.parse_args(argv)

    df = pd.read_csv(a.inp, dtype=str, keep_default_na=False, low_memory=False)
    n0 = len(df)
    report = {"connections_in": n0}

    # 1. infected-host filter
    mal = df["label"] == "malicious"
    df["host_rule"] = ""
    infected = {}
    if a.infected and Path(a.infected).exists():
        inf = pd.read_csv(a.infected, dtype=str)
        for p, g in inf.groupby("pcap"):
            infected[p] = set(g["ip"])
    for p, g in df[mal].groupby("pcap"):
        if p in infected:
            hosts, rule = infected[p], "given"
        else:
            vc = g[g["kind"] == "tls"]["src_ip"].value_counts()
            hosts, rule = ({vc.index[0]} if len(vc) else set()), "heuristic_top_client"
        idx = g.index
        df.loc[idx, "host_rule"] = rule
        df.loc[idx[~g["src_ip"].isin(hosts)], "label"] = "drop_non_victim"
    report["dropped_non_victim"] = int((df["label"] == "drop_non_victim").sum())
    df = df[df["label"] != "drop_non_victim"].copy()

    # 2. benign-background filter on malicious side
    allow = load_allowlist(a.tranco, a.tranco_top)
    gray = (df["label"] == "malicious") & df["sni"].map(lambda s: is_allowlisted(s, allow))
    df.loc[gray, "label"] = "gray"
    report["moved_to_gray"] = int(gray.sum())

    if a.keep_connections:
        df.to_csv(Path(a.out).with_name("connections_clean.csv"), index=False)

    # 3. dedup into client instances
    for c in INSTANCE_KEY:
        if c not in df.columns:
            df[c] = ""
    agg = df.groupby(INSTANCE_KEY, dropna=False, sort=False)
    inst = agg.head(1).copy()
    inst["n_conn"] = agg.size().values
    inst["n_distinct_sni"] = agg["sni"].nunique().values
    inst = inst[inst["label"].isin(["benign", "malicious"])]
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    inst.to_csv(a.out, index=False)

    report.update({
        "connections_after_cleaning": len(df),
        "instances_out": len(inst),
        "instances_malicious": int((inst["label"] == "malicious").sum()),
        "instances_benign": int((inst["label"] == "benign").sum()),
        "unique_ja4_malicious": inst.loc[inst["label"] == "malicious", "ja4"].nunique(),
        "unique_ja4_benign": inst.loc[inst["label"] == "benign", "ja4"].nunique(),
        "unique_ja4_total": inst["ja4"].nunique(),
    })
    rep = pd.Series(report)
    rep.to_csv(Path(a.out).with_suffix(".report.csv"), header=["value"])
    print(rep.to_string())


if __name__ == "__main__":
    main()
