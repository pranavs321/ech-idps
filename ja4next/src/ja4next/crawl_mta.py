"""Crawl malware-traffic-analysis.net (MTA) and write a manifest of pcap and IOC zips.

Never lists or downloads the "malware" zips (samples): only *.pcap.zip /
*.pcapng.zip traffic files and *IOC*.txt.zip analyst indicator files.

Years 2022-2026 are the pre-registered HOLDOUT: they are listed with
holdout=1 so the confirmatory set is frozen now, but download.py refuses to
fetch them unless --allow-holdout is passed (only for the confirmatory run).

Usage:
    python -I -m ja4next.crawl_mta --years 2013-2026 --out data/manifests/mta_manifest.csv
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import time
import urllib.request

BASE = "https://www.malware-traffic-analysis.net"
HOLDOUT_YEARS = set(range(2022, 2027))
UA = "Mozilla/5.0 (research crawler; academic JA4 study; 1 req/s)"


def fetch(url: str, cache_dir: str, delay: float = 1.0) -> str:
    os.makedirs(cache_dir, exist_ok=True)
    fn = os.path.join(cache_dir, re.sub(r"[^A-Za-z0-9._-]", "_", url.replace(BASE, "")) or "root")
    if os.path.exists(fn):
        return open(fn, encoding="utf-8", errors="replace").read()
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as r:
                html = r.read().decode("utf-8", errors="replace")
            open(fn, "w", encoding="utf-8").write(html)
            time.sleep(delay)
            return html
        except Exception as e:  # noqa: BLE001
            if attempt == 3:
                print("FAIL", url, e)
                return ""
            time.sleep(2 ** attempt)
    return ""


LI_RE = re.compile(r'<a href="(\d\d/\d\d/index\d*\.html)" class="list_header">(\d{4}-\d\d-\d\d)</a>\s*--\s*<a[^>]*>(.*?)</a>', re.I | re.S)
ZIP_RE = re.compile(r'href="([^"]+\.zip)"', re.I)


def classify(name: str) -> str | None:
    n = name.lower()
    if "malware" in n:
        return None  # samples: never touched
    if re.search(r"\.pcap(ng)?\.zip$", n) or "pcap" in n:
        return "pcap"
    if "ioc" in n and n.endswith(".zip"):
        return "ioc"
    return None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--years", default="2013-2021")
    ap.add_argument("--out", default="data/manifests/mta_manifest.csv")
    ap.add_argument("--cache", default="data/manifests/mta_html_cache")
    a = ap.parse_args(argv)
    y0, y1 = (int(x) for x in a.years.split("-")) if "-" in a.years else (int(a.years), int(a.years))
    rows = []
    for y in range(y0, y1 + 1):
        idx = fetch(f"{BASE}/{y}/index.html", a.cache)
        posts = LI_RE.findall(idx)
        print(f"{y}: {len(posts)} posts")
        for href, date, title in posts:
            post_url = f"{BASE}/{y}/{href}"
            html = fetch(post_url, a.cache)
            title = re.sub(r"<[^>]+>", "", title).strip()
            for z in sorted(set(x.strip() for x in ZIP_RE.findall(html))):
                if "/" in z and not z.startswith("http"):
                    zurl = f"{BASE}/{y}/{href.rsplit('/', 1)[0]}/{z}"
                elif z.startswith("http"):
                    zurl = z
                else:
                    zurl = f"{BASE}/{y}/{href.rsplit('/', 1)[0]}/{z}"
                kind = classify(z.rsplit("/", 1)[-1])
                if kind is None:
                    continue
                rows.append({"year": y, "date": date, "post_url": post_url, "title": title,
                             "kind": kind, "zip_url": zurl, "zip_name": z.rsplit("/", 1)[-1],
                             "holdout": int(y in HOLDOUT_YEARS)})
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    n_p = sum(r["kind"] == "pcap" for r in rows)
    n_h = sum(r["holdout"] for r in rows)
    print(f"wrote {len(rows)} rows ({n_p} pcap zips, {n_h} holdout rows) -> {a.out}")


if __name__ == "__main__":
    main()
