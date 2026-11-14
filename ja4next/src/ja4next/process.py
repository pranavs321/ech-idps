"""Extract every downloaded pcap, attach analyst IOCs and labels, build features.

Steps (idempotent; re-running skips finished captures):
  1. extract each pcap listed in data/manifests/mta_files.csv -> data/interim/<capture>.parquet
  2. keep connections whose client is a private (internal) address
  3. per blog post, parse the analyst IOC text files -> per-capture IOC sets
  4. label + host-relative features -> data/processed/connections.parquet

Usage:
    python -I -m ja4next.process --workers 4
"""
from __future__ import annotations

import argparse
import glob
import ipaddress
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ja4next.extract import extract  # noqa: E402
from ja4next.labels import Feeds, label_frame, parse_ioc_text  # noqa: E402


def source_of(year: int) -> str:
    if year <= 2016:
        return "mta13_16"
    if year <= 2018:
        return "mta17_18"
    return "mta19_21" if year <= 2021 else "mta_holdout"


def _one(args):
    pcap, cap, src, year, date, post, out = args
    if os.path.exists(out):
        return out, -1
    try:
        df = extract(pcap, src, cap)
    except Exception as e:  # noqa: BLE001
        print("extract failed", pcap, e, file=sys.stderr)
        df = pd.DataFrame()
    if len(df):
        df["year"] = year
        df["date"] = date
        df["post_url"] = post
        df["pcap_name"] = os.path.basename(pcap)
    df.to_parquet(out, index=False)
    return out, len(df)


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", default="data/manifests/mta_files*.csv",
                    help="index csv(s); a glob is allowed; holdout indexes are skipped unless named exactly")
    ap.add_argument("--interim", default="data/interim")
    ap.add_argument("--labels", default="data/labels")
    ap.add_argument("--out", default="data/processed/connections.parquet")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--html-cache", default="data/manifests/mta_html_cache")
    ap.add_argument("--max-pcap-mb", type=float, default=300.0)
    a = ap.parse_args(argv)
    os.makedirs(a.interim, exist_ok=True)
    paths = sorted(glob.glob(a.files)) if any(ch in a.files for ch in "*?[") else [a.files]
    if a.files != "data/manifests/mta_files_holdout.csv":
        paths = [p for p in paths if "holdout" not in p]
    files = pd.concat([pd.read_csv(p) for p in paths], ignore_index=True).drop_duplicates("sha256")
    print("index files:", paths)
    pc = files[files["kind"] == "pcap"]
    pc = pc[pc["file"].str.lower().str.endswith((".pcap", ".pcapng"))]
    jobs = []
    for r in pc.itertuples():
        if r.bytes > a.max_pcap_mb * 1e6:
            continue
        cap = r.sha256[:16]
        jobs.append((r.file, cap, source_of(int(r.year)), int(r.year), r.date, r.post_url,
                     os.path.join(a.interim, cap + ".parquet")))
    print(f"{len(jobs)} pcaps to extract")
    done = 0
    with ProcessPoolExecutor(a.workers) as ex:
        for fut in as_completed([ex.submit(_one, j) for j in jobs]):
            out, n = fut.result()
            done += 1
            if done % 25 == 0:
                print(f"  {done}/{len(jobs)}")
    parts = [pd.read_parquet(p) for p in glob.glob(os.path.join(a.interim, "*.parquet"))]
    df = pd.concat([p for p in parts if len(p)], ignore_index=True)
    df = df[df["client_ip"].map(is_private) & ~df["server_ip"].map(is_private)].reset_index(drop=True)
    print(f"{len(df)} internal->external TLS connections from {df['capture_id'].nunique()} captures")

    # analyst IOCs per post -> per capture
    feeds = Feeds(a.labels)
    iocs = files[files["kind"] == "ioc"]
    post_iocs = {}
    for r in iocs.itertuples():
        try:
            txt = open(r.file, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        d, i = parse_ioc_text(txt, feeds.tlds)
        pd_, pi_ = post_iocs.get(r.post_url, (set(), set()))
        post_iocs[r.post_url] = (pd_ | d, pi_ | i)
    # IOCs named in the text of the blog post itself (cached by the crawler)
    import re as _re
    page_iocs = {}
    for post in df["post_url"].dropna().unique():
        fn = os.path.join(a.html_cache, _re.sub(r"[^A-Za-z0-9._-]", "_",
                                                post.replace("https://www.malware-traffic-analysis.net", "")))
        if os.path.exists(fn):
            txt = _re.sub(r"<[^>]+>", " ", open(fn, encoding="utf-8", errors="ignore").read())
            page_iocs[post] = parse_ioc_text(txt, feeds.tlds)
    pairs = df[["capture_id", "post_url"]].drop_duplicates().itertuples(index=False)
    pairs = list(pairs)
    cap_iocs = {cap: post_iocs.get(post, (set(), set())) for cap, post in pairs}
    cap_page = {cap: page_iocs.get(post, (set(), set())) for cap, post in pairs}
    df["has_analyst_ioc"] = df["post_url"].isin(post_iocs).astype(int)
    df = label_frame(df, feeds, cap_iocs, cap_page)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    df.to_parquet(a.out, index=False)
    print(df.groupby(["source", "label_tier"]).size().unstack(fill_value=0))


if __name__ == "__main__":
    main()
