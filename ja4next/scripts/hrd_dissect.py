"""Which host-relative destination-context (HRd) features carry the cross-source signal,
and is any of them a proxy for how the labels were made?

For the source and time splits, trains TLS+BEH plus (a) one HRd group at a time and
(b) all HRd minus one group. Writes results/<run>/hrd_dissect.csv.
Usage: python -I scripts/hrd_dissect.py [--hostname-only] [--tiers gold_mal,weak_mal,benign] --out results/hostname_only
"""
import argparse
import os
import sys
import warnings

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupKFold

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ja4next import features as F  # noqa: E402
from ja4next.evaluate import capture_weights, cap_per_capture, fit_predict, metrics  # noqa: E402

GROUPS = {
    "beacon": ["hr_beacon_log_med_gap", "hr_beacon_cv_gap", "hr_beacon_periodicity"],
    "dest_volume": ["hr_dest_share", "hr_dest_n_conns"],
    "dest_n_stacks": ["hr_dest_n_stacks"],
    "server_ip_shared_by_n_names": ["hr_srv_n_dests"],
    "stack_context": ["hr_stack_share", "hr_stack_n_dests", "hr_host_n_stacks", "hr_host_n_conns"],
    "server_side_rarity": ["hr_ja4s_share", "hr_z_host_cert_validity"],
}

ap = argparse.ArgumentParser()
ap.add_argument("--data", default="data/processed/connections.parquet")
ap.add_argument("--out", default="results/hostname_only")
ap.add_argument("--hostname-only", action="store_true")
ap.add_argument("--tiers", default="gold_mal,weak_mal,benign")
a = ap.parse_args()
df = pd.read_parquet(a.data)
if a.hostname_only:
    df = df[df["sni"].fillna("") != ""].reset_index(drop=True)
df["host"] = df["capture_id"] + "|" + df["client_ip"]
fams = F.build(df)
df.loc[~df["label_tier"].isin(a.tiers.split(",")), "y"] = np.nan
df.loc[~cap_per_capture(df, 100), "y"] = np.nan
lab = df["y"].notna().values
D = df[lab].reset_index(drop=True)
y = D["y"].astype(int).values
caps = D["capture_id"].values
w = capture_weights(D)
base = pd.concat([fams["TLS"], fams["BEH"]], axis=1)[lab].reset_index(drop=True)
hrd = fams["HRd"][lab].reset_index(drop=True)
srcs = sorted(D["source"].unique())
splits = {"source": [(np.where(D.source != s)[0], np.where(D.source == s)[0]) for s in srcs],
          "time": [(np.where(D.year <= 2018)[0], np.where(D.year >= 2019)[0])]}
variants = {"TLS+BEH": []}
variants.update({f"+{g}": cols for g, cols in GROUPS.items()})
variants["+HRd(all)"] = [c for cols in GROUPS.values() for c in cols]
variants.update({f"+HRd-minus-{g}": [c for gg, cols in GROUPS.items() if gg != g for c in cols] for g in GROUPS})
variants["HRd-only:server_ip_shared_by_n_names"] = "ONLY"
rows = []
for sname, folds in splits.items():
    for vname, cols in variants.items():
        if cols == "ONLY":
            X = hrd[["hr_srv_n_dests"]]
        else:
            X = pd.concat([base, hrd[[c for c in cols if c in hrd]]], axis=1)
        X.columns = [f"{i}_{c}" for i, c in enumerate(X.columns)]
        p = np.full(len(D), np.nan)
        for tr, te in folds:
            p[te], _ = fit_predict(X.iloc[tr], y[tr], w[tr], X.iloc[te])
        ok = ~np.isnan(p)
        m = metrics(y[ok], p[ok], caps[ok])
        m.update({"split": sname, "variant": vname})
        rows.append(m)
        print(f"{sname:7s} {vname:42s} auc={m['roc_auc']:.3f} tpr1%={m['tpr_at_1pct']:.3f} bal={m['bal_acc_cw']:.3f}", flush=True)
# no-model rules: a single host-relative feature used directly as the score
for sname, folds in splits.items():
    te_all = np.unique(np.concatenate([te for _, te in folds]))
    for feat in ("hr_dest_share", "hr_dest_n_conns", "hr_beacon_periodicity"):
        sc = hrd[feat].values.astype(float)
        m = metrics(y[te_all], sc[te_all], caps[te_all])
        m.update({"split": sname, "variant": f"RULE:{feat} (no training)"})
        rows.append(m)
        print(f"{sname:7s} RULE {feat:37s} auc={m['roc_auc']:.3f} tpr1%={m['tpr_at_1pct']:.3f}", flush=True)
# distributions of the CDN-proxy feature by class
dist = D.assign(v=hrd["hr_srv_n_dests"].values).groupby("y")["v"].describe()
print(dist)
res = pd.DataFrame(rows)
os.makedirs(a.out, exist_ok=True)
res.to_csv(os.path.join(a.out, "hrd_dissect.csv"), index=False)
dist.to_csv(os.path.join(a.out, "hrd_srv_n_dests_by_class.csv"))
