"""Write labels.csv for ech-idps scripts/05_real_pcap_eval.py from the ja4next benchmark.
Columns: pcap, capture_id, source, year, cli_ip, cli_port, srv_ip, srv_port, label, tier, has_sni, ja4_ref
Usage: python -I scripts/export_echidps_labels.py <out.csv>"""
import glob
import os
import sys

import pandas as pd

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
d = pd.read_parquet(os.path.join(ROOT, "data/processed/connections.parquet"))
files = pd.concat([pd.read_csv(f) for f in glob.glob(os.path.join(ROOT, "data/manifests/mta_files*.csv"))
                   if "holdout" not in f]).drop_duplicates("sha256")
files["capture_id"] = files["sha256"].str[:16]
path = files.set_index("capture_id")["file"].map(lambda p: os.path.join(ROOT, p))
d = d[d["y"].notna()].copy()
out = pd.DataFrame({
    "pcap": d["capture_id"].map(path), "capture_id": d["capture_id"], "source": d["source"], "year": d["year"],
    "cli_ip": d["client_ip"], "cli_port": d["client_port"], "srv_ip": d["server_ip"], "srv_port": d["server_port"],
    "label": d["y"].astype(int), "tier": d["label_tier"], "has_sni": (d["sni"].fillna("") != "").astype(int),
    "ja4_ref": d["ja4"]})
out.to_csv(sys.argv[1], index=False)
print(len(out), "labelled connections,", out["capture_id"].nunique(), "captures,", out["pcap"].isna().sum(), "without a file")
