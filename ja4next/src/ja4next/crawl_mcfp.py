"""Build the Stratosphere MCFP pcap manifests (listing pages only; downloads READMEs, never samples/zips).
  botnet     : CTU-Malware-Capture-Botnet-*  pcaps 1-120 MB            -> mcfp_pcaps.csv
  mixed      : CTU-Mixed-Capture-* and CTU-Normal-* pcaps (any size)    -> mcfp_mixed_normal_pcaps.csv
  targeted   : larger (120-1200 MB) banking-trojan botnet pcaps         -> mcfp_targeted_pcaps.csv
Usage: python -I -m ja4next.crawl_mcfp [--out data/manifests] [--meta data/mcfp_meta]"""
from __future__ import annotations
import argparse, csv, os, re, subprocess, time
from concurrent.futures import ThreadPoolExecutor

B = "https://mcfp.felk.cvut.cz/publicDatasets/"
FAM = r"trick|dridex|emotet|qakbot|qbot|zeus|zbot|gootkit|ursnif|gozi|cobalt|banker|icedid|hancitor|ramnit|kovter|tinba|dyre|vawtrak|shifu"


def curl(url: str) -> str:
    for attempt in range(4):  # the server drops some parallel requests; retry empty replies
        out = subprocess.run(["curl", "-s", "-m", "90", url], capture_output=True, text=True).stdout
        if out.strip():
            return out
        time.sleep(2 * (attempt + 1))
    return ""


def to_mb(s: str) -> float:
    m = re.match(r"([\d.]+)([KMGT]?)", s.strip())
    return float(m.group(1)) * {"": 1 / 1048576, "K": 1 / 1024, "M": 1, "G": 1024, "T": 1048576}[m.group(2)] if m else 0.0


def list_pcaps(d: str):
    h = curl(f"{B}{d}/")
    return [(d, m.group(1), m.group(3), m.group(2), to_mb(m.group(3))) for m in
            re.finditer(r'href="([^"]+\.pcap(?:ng)?)">[^<]*</a></td><td[^>]*>([\d-]+ [\d:]+)\s*</td><td[^>]*>\s*([\d.]+[KMGT]?)', h)]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/manifests"); ap.add_argument("--meta", default="data/mcfp_meta")
    a = ap.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    root = re.findall(r'href="(CTU-[^"/]*)/"', curl(B))
    botnet = sorted(d for d in root if "Malware-Capture-Botnet" in d)
    mixnorm = sorted(d for d in root if re.search(r"Mixed|Normal", d))
    def readme(d):
        os.makedirs(f"{a.meta}/{d}", exist_ok=True)
        subprocess.run(["curl", "-s", "-m", "60", "-o", f"{a.meta}/{d}/README.md", f"{B}{d}/README.md"])
    with ThreadPoolExecutor(4) as ex:
        list(ex.map(readme, botnet + mixnorm))
        bn = [r for rows in ex.map(list_pcaps, botnet) for r in rows]
        mn = [r for rows in ex.map(list_pcaps, mixnorm) for r in rows]
    hdr = ["dir", "file", "size", "date", "mb"]
    def write(name, rows):
        with open(os.path.join(a.out, name), "w", newline="") as f:
            w = csv.writer(f); w.writerow(hdr); w.writerows(rows)
        print(name, len(rows), "files", round(sum(r[4] for r in rows) / 1024, 1), "GB")
    write("mcfp_pcaps.csv", [r for r in bn if 1 <= r[4] <= 120])
    write("mcfp_mixed_normal_pcaps.csv", mn)
    def fam(d):
        t = open(f"{a.meta}/{d}/README.md", errors="ignore").read() if os.path.exists(f"{a.meta}/{d}/README.md") else ""
        m = re.search(r"Probable Name:\s*(.*)", t)
        return bool(m and re.search(FAM, m.group(1), re.I))
    write("mcfp_targeted_pcaps.csv", [r for r in bn if 120 < r[4] <= 1200 and fam(r[0])])


if __name__ == "__main__":
    main()
