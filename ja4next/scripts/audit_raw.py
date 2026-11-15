"""Classify every raw pcap in data/raw by SHA-256: used by the processed table, duplicate, or unused.
Read-only by default. With --apply, deletes only (a) byte-identical duplicates (keeps the copy that the
manifest names) and (b) files whose hash is not in any manifest and not in the processed table.
Also removes captures that gave no TLS rows (nothing in the models depends on them). Never touches data/raw_holdout, data/confirmatory_reserved or the MCFP trees."""
import glob, hashlib, json, os, sys
from collections import defaultdict
import pandas as pd

APPLY = "--apply" in sys.argv
ROOT = "data/raw"
files = [p for p in glob.glob(f"{ROOT}/mta/**/*", recursive=True) + glob.glob(f"{ROOT}/ctu/*")
         if p.endswith((".pcap", ".pcapng")) and os.path.isfile(p)]
sha = {}
for p in files:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 22), b""): h.update(b)
    sha[p] = h.hexdigest()

man = pd.concat([pd.read_csv(f) for f in glob.glob("data/manifests/mta_files*.csv") if os.path.getsize(f) > 0], ignore_index=True)
man_pcap = man[man["kind"] == "pcap"].dropna(subset=["sha256"])
manifest_sha = set(man_pcap["sha256"])
manifest_path = {}
for r in man_pcap.itertuples(): manifest_path.setdefault(r.sha256, r.file)
conn = pd.read_parquet("data/processed/connections.parquet", columns=["capture_id"])
used16 = set(conn["capture_id"].astype(str))

groups = defaultdict(list)
for p, h in sha.items(): groups[h].append(p)
keep, dup, orphan, used, zero = [], [], [], [], []
for h, paths in groups.items():
    pref = manifest_path.get(h)
    primary = next((p for p in paths if pref and p.endswith(os.path.basename(pref))), paths[0])
    keep.append(primary)
    for p in paths:
        if p != primary: dup.append(p)
    if h[:16] in used16: used.append(primary)
    elif h in manifest_sha: zero.append(primary)       # extracted, no TLS connections kept
    else: orphan.append(primary)

sizes = {p: os.path.getsize(p) for p in sha}
def gb(paths): return round(sum(sizes[p] for p in paths) / 1e9, 2)
summary = {
    "raw_pcaps": len(sha), "unique_sha256": len(groups),
    "duplicate_copies": len(dup), "duplicate_gb": gb(dup),
    "used_by_processed_table": len(used), "used_gb": gb(used),
    "in_manifest_no_tls_rows": len(zero), "no_tls_gb": gb(zero),
    "not_in_manifest_or_table": len(orphan), "orphan_gb": gb(orphan),
    "action": "applied" if APPLY else "dry run",
}
print(json.dumps(summary, indent=2))
os.makedirs("results", exist_ok=True)
pd.DataFrame([{"path": p, "sha256": sha[p], "bytes": sizes[p],
               "status": "duplicate" if p in dup else ("used" if p in used else ("no_tls" if p in zero else "orphan"))}
              for p in sha]).to_csv("results/raw_pcap_audit.csv", index=False)
json.dump(summary, open("results/raw_pcap_audit.json", "w"), indent=2)
if APPLY:
    for p in dup + orphan + zero:
        if p.startswith(f"{ROOT}/") and "holdout" not in p and "reserved" not in p:
            os.remove(p)
    print("removed", len(dup) + len(orphan) + len(zero), "files")
