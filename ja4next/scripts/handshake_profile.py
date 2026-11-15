"""TLS handshake profile of the MTA 2013-2021 connections, by label tier and year. Reads only processed data.
Writes results/handshake/*.csv + summary.json. Used to check what the handshake alone reveals before modelling."""
import json, os
import numpy as np, pandas as pd

OUT = "results/handshake"; os.makedirs(OUT, exist_ok=True)
d = pd.read_parquet("data/processed/connections.parquet")
d["tls_ver"] = d["ja4"].str[1:3].map({"13": "TLS1.3", "12": "TLS1.2", "11": "TLS1.1", "10": "TLS1.0"}).fillna("other")
d["has_sni"] = d["sni"].fillna("") != ""
d["alpn"] = d["ja4"].str[8:10]
d["tier"] = d["label_tier"].fillna("none")

# 1. version and SNI by tier
t1 = d.groupby(["tier", "tls_ver"]).size().unstack(fill_value=0)
t1 = t1.div(t1.sum(axis=1), axis=0).round(4); t1.to_csv(f"{OUT}/version_by_tier.csv")
t2 = d.groupby("tier").agg(n=("ja4", "size"), sni_share=("has_sni", "mean"), distinct_ja4=("ja4", "nunique"),
                           distinct_ja4s=("ja4s", "nunique")).round(4)
t2.to_csv(f"{OUT}/tier_summary.csv")

# 2. per-year version mix and fingerprint diversity
t3 = d.groupby(["year", "tls_ver"]).size().unstack(fill_value=0)
t3 = t3.div(t3.sum(axis=1), axis=0).round(4); t3.to_csv(f"{OUT}/version_by_year.csv")

# 3. how often a malicious JA4 is also used by benign traffic (in the same capture): natural mimicry on MTA
lab = d[d.y.notna()]
ben_ja4 = set(lab.loc[lab.y == 0, "ja4"])
mal = lab[lab.y == 1]
share_any = float(mal.ja4.isin(ben_ja4).mean()) if len(mal) else float("nan")
hosts = mal.assign(h=mal.capture_id + "|" + mal.client_ip).groupby("h")
per_capture_shared = float(mal.assign(s=mal.ja4.isin(ben_ja4)).groupby("capture_id").s.max().mean())

# 4. top JA4 values by label (concentration)
top = (lab.groupby(["ja4", "y"]).size().unstack(fill_value=0).rename(columns={0.0: "benign", 1.0: "malicious"}))
top["total"] = top.sum(axis=1)
top.sort_values("total", ascending=False).head(25).to_csv(f"{OUT}/top_ja4.csv")

summary = {
    "connections": int(len(d)), "labelled": int(lab.shape[0]),
    "tls13_share_all": round(float((d.tls_ver == "TLS1.3").mean()), 4),
    "sni_missing_share_malicious": round(float((~mal.has_sni).mean()), 4) if len(mal) else None,
    "sni_missing_share_benign": round(float((~lab[lab.y == 0].has_sni).mean()), 4),
    "malicious_ja4_also_seen_in_benign_connection_share": round(share_any, 4),
    "captures_with_malicious_sharing_a_benign_ja4_share": round(per_capture_shared, 4),
    "distinct_ja4_all": int(d.ja4.nunique()),
}
json.dump(summary, open(f"{OUT}/summary.json", "w"), indent=2)
print(json.dumps(summary, indent=2)); print(t2.to_string()); print(t1.to_string())

# 5. shortcut checks on the handshake: can the TLS version alone, or the missing-SNI flag alone, separate the classes?
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import roc_auc_score
rows = []
L = lab[lab.y.notna()].copy()
L = L[L.capture_id.notna()]
for name, cols in (("tls_version_only", ["tls_ver"]), ("sni_missing_only", ["has_sni"])):
    X = pd.get_dummies(L[cols].astype(str), dtype=float).values
    y = L.y.values.astype(int); g = L.capture_id.values
    p = np.zeros(len(L))
    for tr, te in GroupKFold(5).split(X, y, g):
        m = DecisionTreeClassifier(max_depth=2, class_weight="balanced").fit(X[tr], y[tr])
        p[te] = m.predict_proba(X[te])[:, 1]
    rows.append({"features": name, "auc_capture_disjoint": round(float(roc_auc_score(y, p)), 4)})
pd.DataFrame(rows).to_csv(f"{OUT}/shortcut_checks.csv", index=False)
print(pd.DataFrame(rows).to_string(index=False))
