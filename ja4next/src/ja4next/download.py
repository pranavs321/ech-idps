"""Download MTA pcap and IOC zips from a manifest, unpack them, record SHA-256.

Safety:
  * only rows the crawler classified as kind=pcap or kind=ioc (never "malware" zips)
  * refuses holdout rows (2022-2026) unless --allow-holdout is given
  * unpacks only .pcap / .pcapng / .txt members; anything else in a zip is skipped
  * writes into data/raw/mta/<date>/ ; nothing is executed

Usage:
    python -I -m ja4next.download --manifest data/manifests/mta_2019_2021.csv --years 2019-2021
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import time
import urllib.request

import pyzipper

UA = "Mozilla/5.0 (research crawler; academic JA4 study)"
KEEP_EXT = (".pcap", ".pcapng", ".txt")


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def get(url: str, dest: str) -> bool:
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return True
    tmp = dest + ".part"
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=300) as r, open(tmp, "wb") as f:
                while True:
                    b = r.read(1 << 20)
                    if not b:
                        break
                    f.write(b)
            os.replace(tmp, dest)
            return True
        except Exception as e:  # noqa: BLE001
            print("retry", attempt, url, e)
            time.sleep(2 ** attempt * 2)
    return False


def unpack(zpath: str, outdir: str, date: str) -> list[str]:
    """Info-ZIP `unzip` first (fast, ZipCrypto); pyzipper as the fallback for AES archives."""
    pw_list = [f"infected_{date.replace('-', '')}".encode()]
    import re as _re
    m = _re.match(r"(\d{4})-(\d\d)-(\d\d)", os.path.basename(zpath))
    if m and "".join(m.groups()) != date.replace("-", ""):
        pw_list.append(f"infected_{''.join(m.groups())}".encode())  # filename date differs from post date
    pw_list.append(b"infected")
    import shutil
    import subprocess
    import tempfile
    if shutil.which("unzip"):
        for pw in pw_list:
            tmp = tempfile.mkdtemp(dir=outdir, prefix=".unz_")
            r = subprocess.run(["unzip", "-o", "-q", "-j", "-P", pw.decode(), zpath,
                                "*.pcap", "*.pcapng", "*.txt", "-d", tmp],
                               capture_output=True, text=True, stdin=subprocess.DEVNULL)
            got = [f for f in os.listdir(tmp) if f.lower().endswith(KEEP_EXT)]
            if r.returncode in (0, 1) and got:
                res = []
                for f in got:
                    dest = os.path.join(outdir, f)
                    os.replace(os.path.join(tmp, f), dest)
                    res.append(dest)
                shutil.rmtree(tmp, ignore_errors=True)
                return res
            shutil.rmtree(tmp, ignore_errors=True)
    out = []
    for pw in pw_list:
        try:
            with pyzipper.AESZipFile(zpath) as z:
                z.setpassword(pw)
                for m in z.infolist():
                    name = os.path.basename(m.filename)
                    if not name or not name.lower().endswith(KEEP_EXT):
                        continue
                    dest = os.path.join(outdir, name)
                    if not os.path.exists(dest):
                        with z.open(m) as src, open(dest, "wb") as dst:
                            while True:
                                b = src.read(1 << 20)
                                if not b:
                                    break
                                dst.write(b)
                    out.append(dest)
            return out
        except RuntimeError:
            continue  # wrong password
        except Exception as e:  # noqa: BLE001
            print("unzip error", zpath, e)
            return out
    print("no password worked", zpath)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--years", default="2019-2021")
    ap.add_argument("--kinds", default="pcap,ioc")
    ap.add_argument("--root", default="data/raw/mta")
    ap.add_argument("--index", default="data/manifests/mta_files.csv")
    ap.add_argument("--allow-holdout", action="store_true")
    ap.add_argument("--max-mb", type=float, default=400.0, help="skip zips larger than this")
    a = ap.parse_args(argv)
    y0, y1 = (int(x) for x in a.years.split("-")) if "-" in a.years else (int(a.years), int(a.years))
    kinds = set(a.kinds.split(","))
    rows = list(csv.DictReader(open(a.manifest)))
    todo = [r for r in rows if y0 <= int(r["year"]) <= y1 and r["kind"] in kinds]
    if not a.allow_holdout:
        held = [r for r in todo if r["holdout"] == "1"]
        if held:
            print(f"refusing {len(held)} holdout rows (pass --allow-holdout only for the confirmatory run)")
        todo = [r for r in todo if r["holdout"] != "1"]
    os.makedirs(os.path.dirname(a.index), exist_ok=True)
    new_index = not os.path.exists(a.index)
    idx = open(a.index, "a", newline="")
    w = csv.writer(idx)
    if new_index:
        w.writerow(["year", "date", "post_url", "kind", "zip_name", "file", "sha256", "bytes"])
    for i, r in enumerate(todo):
        outdir = os.path.join(a.root, r["date"])
        os.makedirs(outdir, exist_ok=True)
        zdest = os.path.join(outdir, r["zip_name"])
        if os.path.exists(zdest + ".done"):
            continue
        if not get(r["zip_url"], zdest):
            print("FAILED", r["zip_url"])
            continue
        if os.path.getsize(zdest) > a.max_mb * 1e6:
            print("skip large", zdest)
            continue
        for f in unpack(zdest, outdir, r["date"]):
            w.writerow([r["year"], r["date"], r["post_url"], r["kind"], r["zip_name"], f, sha256(f), os.path.getsize(f)])
        idx.flush()
        os.remove(zdest)  # keep only the unpacked pcap / txt
        open(zdest + ".done", "w").close()
        if i % 20 == 0:
            print(f"{i + 1}/{len(todo)} {r['zip_name']}")
        time.sleep(0.5)
    idx.close()


if __name__ == "__main__":
    main()
