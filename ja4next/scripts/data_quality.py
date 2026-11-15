"""Data-quality audit: duplicates, missing values, inconsistencies, per-source counts.
Writes results/data_quality.json and results/data_quality_sources.csv. Read-only on data/."""
import glob, json, os, re, warnings
warnings.filterwarnings("ignore")
import numpy as np, pandas as pd
out = {}
JA4_RE = re.compile(r"^[tqd][0-9a-z]{9}[0-9a-z]*_[0-9a-f]{12}_[0-9a-f]{12}$")

# 1. pcap-level duplicates across all manifests (by SHA-256)
sha = []
for f in glob.glob("data/manifests/mta_files*.csv"):
    d = pd.read_csv(f)
    d = d[d["kind"].astype(str).str.contains("pcap")] if "kind" in d else d
    if "sha256" in d: sha += [("mta", h) for h in d["sha256"].dropna()]
for f in glob.glob("data/manifests/mcfp*_files.csv"):
    try: d = pd.read_csv(f)
    except pd.errors.EmptyDataError: continue
    sha += [(os.path.basename(f), h) for h in d["sha256"].dropna()]
s = pd.DataFrame(sha, columns=["manifest", "sha256"])
dup = s[s.duplicated("sha256", keep=False)]
out["pcap_hashes"] = int(len(s)); out["pcap_unique_hashes"] = int(s.sha256.nunique())
out["pcap_duplicate_hashes_across_or_within"] = int(dup.sha256.nunique())

# 2. connection tables
def audit(df, name):
    r = {"rows": int(len(df)), "captures": int(df.capture_id.nunique()) if "capture_id" in df else None}
    r["dup_conn_rows(capture,stream)"] = int(df.duplicated(["capture_id", "stream"]).sum()) if "stream" in df else None
    r["dup_conn_rows(5tuple,time)"] = int(df.duplicated(["capture_id", "client_ip", "client_port", "server_ip", "server_port", "t_clienthello"]).sum())
    r["ja4_missing"] = int(df.ja4.isna().sum() + (df.ja4 == "").sum())
    ok = df.ja4.dropna().astype(str)
    r["ja4_malformed"] = int((~ok.map(lambda v: bool(JA4_RE.match(v)))).sum())
    r["sni_empty_share"] = round(float((df.sni.fillna("") == "").mean()), 4)
    r["negative_duration"] = int((pd.to_numeric(df.get("duration"), errors="coerce") < 0).sum()) if "duration" in df else None
    r["syn_missing_share"] = round(float(df.env_c_mss.isna().mean()), 4) if "env_c_mss" in df else None
    r["server_hello_missing_share"] = round(float(df.ja4s.isna().mean()), 4) if "ja4s" in df else None
    r["beh_nan_share"] = round(float(df[[c for c in df if c.startswith("b_")]].isna().mean().mean()), 4)
    return r
tab = {}
main = pd.read_parquet("data/processed/connections.parquet")
tab["MTA 2013-2021 (processed)"] = audit(main, "mta")
for tag in ("mcfp", "mcfp2", "mcfp3"):
    fs = glob.glob(f"data/interim/{tag}/*.parquet")
    if not fs: continue
    fr = [pd.read_parquet(f) for f in fs]; fr = [f for f in fr if len(f)]
    if not fr: continue
    d = pd.concat(fr, ignore_index=True)
    d["capture_id"] = d["mcfp_dir"] + "/" + d["pcap_name"]
    tab[f"Stratosphere {tag}"] = audit(d, tag)
out["tables"] = tab
if "label_tier" in main: out["mta_label_tiers"] = main.label_tier.value_counts().to_dict()
# label conflicts: same (capture, server, sni) labelled both classes
l = main.dropna(subset=["y"]); g = l.groupby(["capture_id", "server_ip"]).y.nunique()
out["mta_server_with_both_labels_within_capture"] = int((g > 1).sum())
os.makedirs("results", exist_ok=True)
json.dump(out, open("results/data_quality.json", "w"), indent=2, default=str)
pd.DataFrame(tab).T.to_csv("results/data_quality_sources.csv")
print(json.dumps(out, indent=2, default=str)[:3500])
