"""Remaining analyses on the hostname-only benchmark (exploratory).

  1. TLS-version stratified results (leave-one-source-out predictions, split by TLS version)
  2. Version-only baseline (depth-1 tree on the TLS version alone)
  3. Variance decomposition: share of each behaviour feature's variance that is
     between captures and between eras, raw vs host-relative
  4. Group-robust training (GroupDRO-style exponentiated reweighting over
     era x label groups, boosted trees) vs plain ERM, leave-one-source-out
Usage: python -I scripts/extras.py
"""
import os, sys, warnings
import numpy as np, pandas as pd
warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from sklearn.metrics import roc_auc_score
from sklearn.tree import DecisionTreeClassifier
from ja4next import features as F
from ja4next.evaluate import SETS, cap_per_capture, capture_weights, fit_predict, metrics, tpr_at, _setX, XGB
from xgboost import XGBClassifier

OUT = "results/extras"; os.makedirs(OUT, exist_ok=True)
df = pd.read_parquet("data/processed/connections.parquet")
df = df[df["sni"].fillna("") != ""].reset_index(drop=True)
df["host"] = df["capture_id"] + "|" + df["client_ip"]
fams = F.build(df)
lab = df["label_tier"].isin(["gold_mal", "weak_mal", "benign"]).values
df.loc[~lab, "y"] = np.nan
df.loc[~cap_per_capture(df, 100), "y"] = np.nan
L = df["y"].notna().values
D = df[L].reset_index(drop=True); y = D["y"].astype(int).values; caps = D["capture_id"].values
w = capture_weights(D)
srcs = sorted(D["source"].unique())
folds = [(np.where(D.source != s)[0], np.where(D.source == s)[0]) for s in srcs]
ver = D["ja4"].str[1:3].map({"13": "TLS 1.3", "12": "TLS 1.2", "10": "TLS 1.0", "11": "TLS 1.1", "s3": "SSL 3"}).fillna("other")
rows = []

# 1+2: leave-one-source-out predictions, then stratify by TLS version
def loso(setname, weights_fn=None):
    X = _setX({k: v[L].reset_index(drop=True) for k, v in fams.items()}, setname)
    p = np.full(len(D), np.nan)
    for tr, te in folds:
        if weights_fn is None:
            p[te], _ = fit_predict(X.iloc[tr], y[tr], w[tr], X.iloc[te])
        else:
            p[te] = weights_fn(X.iloc[tr], y[tr], w[tr], X.iloc[te], D.source.values[tr])
    return p

preds = {s: loso(s) for s in ["TLS+BEH", "HR+TLS+BEH", "TLS+BEHsrc"]}
for name, p in preds.items():
    for v in ["TLS 1.3", "TLS 1.2", "TLS 1.0", "all"]:
        m = np.ones(len(D), bool) if v == "all" else (ver.values == v)
        if (y[m] == 1).sum() < 5 or (y[m] == 0).sum() < 5: continue
        r = metrics(y[m], p[m], caps[m]); rows.append({"analysis": "tls_version_stratified", "set": name, "stratum": v, **r})

# version-only baseline (depth-1 tree on TLS version, trained leave-one-source-out)
Vnum = pd.Series(ver).map({"TLS 1.3": 3, "TLS 1.2": 2, "TLS 1.1": 1, "TLS 1.0": 0, "SSL 3": -1, "other": -2}).values.reshape(-1, 1)
pv = np.full(len(D), np.nan)
for tr, te in folds:
    t = DecisionTreeClassifier(max_depth=1).fit(Vnum[tr], y[tr])
    pv[te] = t.predict_proba(Vnum[te])[:, 1]
rows.append({"analysis": "version_only_baseline", "set": "TLS version (depth-1 tree)", "stratum": "all", **metrics(y, pv, caps)})

# 4: group-robust training (GroupDRO-style, approximate)
def groupdro(Xtr, ytr, wtr, Xte, src_tr, rounds=6, eta=0.5):
    groups = pd.factorize(pd.Series(src_tr).astype(str) + "|" + ytr.astype(str))[0]
    G = groups.max() + 1
    q = np.ones(G) / G
    base_w = wtr.copy()
    for _ in range(rounds):
        sw = base_w * q[groups] * G
        m = XGBClassifier(**{**XGB, "n_jobs": 4}, random_state=0).fit(Xtr, ytr, sample_weight=sw)
        p = np.clip(m.predict_proba(Xtr)[:, 1], 1e-6, 1 - 1e-6)
        loss = -(ytr * np.log(p) + (1 - ytr) * np.log(1 - p))
        g_loss = np.array([loss[groups == g].mean() for g in range(G)])
        q = q * np.exp(eta * g_loss); q /= q.sum()
    return m.predict_proba(Xte)[:, 1]

for setname in ["HR+TLS+BEH"]:
    X = _setX({k: v[L].reset_index(drop=True) for k, v in fams.items()}, setname)
    pg = np.full(len(D), np.nan)
    for tr, te in folds:
        pg[te] = groupdro(X.iloc[tr], y[tr], w[tr], X.iloc[te], D.source.values[tr])
    rows.append({"analysis": "erm_vs_groupdro", "set": f"ERM {setname}", "stratum": "all", **metrics(y, preds[setname], caps)})
    rows.append({"analysis": "erm_vs_groupdro", "set": f"GroupDRO-approx {setname}", "stratum": "all", **metrics(y, pg, caps)})
    # worst-era balanced accuracy, the quantity DRO methods are meant to improve
    for lab_, pp in [("ERM", preds[setname]), ("GroupDRO-approx", pg)]:
        worst = min(roc_auc_score(y[te], pp[te]) for _, te in folds if len(np.unique(y[te])) == 2)
        rows.append({"analysis": "erm_vs_groupdro_worst_era", "set": f"{lab_} {setname}", "stratum": "worst era AUC", "auc": worst})

# 3: variance decomposition (one-way random effects, share of variance between groups)
def icc(x, g):
    x = pd.Series(x).astype(float); g = pd.Series(g).values
    ok = np.isfinite(x.values)
    x = x[ok]; g = g[ok]
    grand = x.mean(); total = ((x - grand) ** 2).sum()
    means = x.groupby(g).transform("mean")
    within = ((x - means) ** 2).sum()
    return max(0.0, 1 - within / total) if total > 0 else np.nan
behs = ["mean_pkt_size", "std_pkt_size", "size_lattice_entropy", "log_mean_iat", "iat_cv", "directionality_ratio", "up_down_pkt_ratio", "log_flow_duration"]
beh_df = fams["BEH"][L].reset_index(drop=True)
for c in ["b_bytes_up", "b_mean_up", "b_mean_down", "b_med_gap_rtt", "duration", "b_byte_ratio", "b_dir_changes"]:
    rows.append({"analysis": "variance_decomposition", "set": f"raw {c}", "stratum": "share between captures",
                 "auc": icc(D.index.map(lambda i: 0) * 0 + beh_df[c].values if c in beh_df else np.nan, caps)})
    rows.append({"analysis": "variance_decomposition", "set": f"raw {c}", "stratum": "share between eras",
                 "auc": icc(beh_df[c].values if c in beh_df else np.nan, D.source.values)})
hr = fams["HRb"][L].reset_index(drop=True)
for c in [c for c in hr.columns if c.startswith("hr_z_stack_")][:6]:
    rows.append({"analysis": "variance_decomposition", "set": f"host-relative {c}", "stratum": "share between captures",
                 "auc": icc(hr[c].values, caps)})
    rows.append({"analysis": "variance_decomposition", "set": f"host-relative {c}", "stratum": "share between eras",
                 "auc": icc(hr[c].values, D.source.values)})

out = pd.DataFrame(rows)
out.to_csv(os.path.join(OUT, "extras_results.csv"), index=False)
pd.set_option("display.width", 200)
print(out.round(3).to_string())
