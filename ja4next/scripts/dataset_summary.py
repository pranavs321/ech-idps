"""results/dataset_summary.json: counts, natural mimicry, TLS-version split by class."""
import json
import os
import sys

import pandas as pd

ROOT = os.path.join(os.path.dirname(__file__), "..")
d = pd.read_parquet(os.path.join(ROOT, "data/processed/connections.parquet"))
d["host"] = d["capture_id"] + "|" + d["client_ip"]
lab = d[d["y"].notna()]
named = lab[lab["sni"].fillna("") != ""]
out = {
    "captures": int(d["capture_id"].nunique()),
    "hosts": int(d["host"].nunique()),
    "tls_connections_internal_to_external": int(len(d)),
    "by_source_tier": {s: g["label_tier"].value_counts().to_dict() for s, g in d.groupby("source")},
    "by_year_labelled": {int(y): {"malicious": int((g.y == 1).sum()), "benign": int((g.y == 0).sum()),
                                  "captures": int(g.capture_id.nunique())} for y, g in lab.groupby("year")},
    "gold_evidence": d.loc[d.label_tier == "gold_mal", "label_evidence"].str.split(";").explode()
                      .str.split(":").str[0].value_counts().to_dict(),
    "ja4_tshark_agreement": float((d["ja4"] == d["ja4_tshark"]).mean()),
}
ben = set(zip(named.loc[named.y == 0, "host"], named.loc[named.y == 0, "ja4"]))
mal = named[named.y == 1]
out["natural_mimicry_hostname_only"] = {
    "malicious_rows": int(len(mal)),
    "share_sharing_exact_ja4_with_benign_on_same_host": float(sum((h, j) in ben for h, j in zip(mal.host, mal.ja4)) / max(1, len(mal))),
    "hosts_with_both_classes": int(named.groupby("host")["y"].nunique().eq(2).sum()),
}
mal = mal.assign(shared=[(h, j) in ben for h, j in zip(mal.host, mal.ja4)])
both = named.groupby("host")["y"].nunique().eq(2)
mb = mal[mal.host.isin(both[both].index)]
out["natural_mimicry_hostname_only"]["capture_weighted_share_hosts_with_both_classes"] = float(
    mb.groupby("capture_id")["shared"].mean().mean()) if len(mb) else None
out["natural_mimicry_hostname_only"]["row_share_hosts_with_both_classes"] = float(mb["shared"].mean()) if len(mb) else None
ver = lab["ja4"].str[1:3]
out["tls_version_by_class"] = pd.crosstab(ver, lab["y"]).rename(columns={0.0: "benign", 1.0: "malicious"}).to_dict()
out["bare_ip_share_by_class"] = lab.assign(bare=lab.sni.fillna("") == "").groupby("y")["bare"].mean().rename(
    {0.0: "benign", 1.0: "malicious"}).to_dict()
os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
json.dump(out, open(os.path.join(ROOT, "results/dataset_summary.json"), "w"), indent=2, default=str)
print(json.dumps(out, indent=2, default=str))
