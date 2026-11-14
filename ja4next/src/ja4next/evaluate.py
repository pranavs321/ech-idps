"""Split ladder, ELI, low-FPR operating points, per-host triage, bootstrap CIs.

Feature sets compared (all with the same XGBoost settings):
  ENV, TLS, BEH, SRV, HR, TLS+BEH (old best), HR+BEH, HR+TLS+BEH (new),
  HR+TLS+BEH+SRV, and path-robust variants.
Splits:
  capture  GroupKFold by capture (5 folds)
  ja4      GroupKFold by JA4 value (unseen fingerprints)
  source   leave-one-source-out
  time     train on years <= 2018, test on 2019-2021
Metrics: capture-weighted balanced accuracy at 0.5, ROC-AUC, TPR at 1% / 0.1% FPR,
         per-host triage hit@1 and precision@5 (rank each host's connections, labelled or
         not, by score; count how often the top alerts are labelled malicious).

Usage:
    python -I -m ja4next.evaluate --data data/processed/connections.parquet --out results/
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.model_selection import GroupKFold
from xgboost import XGBClassifier

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ja4next import features as F  # noqa: E402

XGB = dict(n_estimators=200, max_depth=4, learning_rate=0.1, subsample=0.9, colsample_bytree=0.8,
           tree_method="hist", n_jobs=int(os.environ.get("XGB_THREADS", "4")), eval_metric="logloss")

SETS = {
    # single families
    "ENV": ["ENV"], "TLS": ["TLS"], "BEH": ["BEH"], "SRV": ["SRV"],
    "HRb": ["HRb"], "HRd": ["HRd"], "POS": ["POS"],
    # previous best and a domain-generalisation strawman
    "TLS+BEH": ["TLS", "BEH"],
    "TLS+BEHsrc": ["TLS", "BEHsrc"],
    # new: relative behaviour, then + destination context, then + server side
    "HRb+TLS+BEH": ["HRb", "TLS", "BEH"],
    "HR+TLS+BEH": ["HRb", "HRd", "TLS", "BEH"],
    "HR+TLS+BEH+SRV": ["HRb", "HRd", "TLS", "BEH", "SRV"],
}


def capture_weights(df: pd.DataFrame) -> np.ndarray:
    """Every capture weighs the same within its class."""
    w = np.ones(len(df))
    for yv in (0, 1):
        m = df["y"].values == yv
        caps = df.loc[m, "capture_id"]
        cnt = caps.map(caps.value_counts())
        w[m] = 1.0 / cnt.values
        w[m] *= m.sum() / w[m].sum()
    return w


def bal_acc_cw(y, p, caps, thr=0.5):
    df = pd.DataFrame({"y": y, "hit": (p >= thr) == (y == 1), "c": caps})
    accs = []
    for yv in (0, 1):
        s = df[df.y == yv]
        if len(s):
            accs.append(s.groupby("c")["hit"].mean().mean())
    return float(np.mean(accs)) if accs else np.nan


def tpr_at(y, p, fpr_t):
    if len(np.unique(y)) < 2:
        return np.nan
    fpr, tpr, _ = roc_curve(y, p)
    ok = fpr <= fpr_t
    return float(tpr[ok].max()) if ok.any() else 0.0


def triage(df_all: pd.DataFrame, score: np.ndarray, k: int = 5):
    """Rank every connection of each host (labelled or not) and score the top alerts."""
    d = df_all[["host", "y"]].copy()
    d["s"] = score
    hit1, prec = [], []
    for h, g in d.groupby("host"):
        if not (g["y"] == 1).any():
            continue
        g = g.sort_values("s", ascending=False)
        lab = g["y"]
        hit1.append(float(lab.iloc[0] == 1))
        top = lab.iloc[:k]
        prec.append(float((top == 1).sum() / max(1, len(top))))
    return (float(np.mean(hit1)) if hit1 else np.nan, float(np.mean(prec)) if prec else np.nan, len(hit1))


def fit_predict(Xtr, ytr, wtr, Xte, seed=0):
    m = XGBClassifier(**XGB, random_state=seed)
    m.fit(Xtr, ytr, sample_weight=wtr)
    return m.predict_proba(Xte)[:, 1], m


def metrics(y, p, caps):
    return {
        "bal_acc_cw": bal_acc_cw(y, p, caps),
        "roc_auc": float(roc_auc_score(y, p)) if len(np.unique(y)) == 2 else np.nan,
        "tpr_at_1pct": tpr_at(y, p, 0.01),
        "tpr_at_0.1pct": tpr_at(y, p, 0.001),
        "n": int(len(y)), "n_pos": int((y == 1).sum()),
    }


KEY_SETS = ("TLS+BEH", "HRb+TLS+BEH", "HR+TLS+BEH")
# splits with many folds run a reduced list of sets to keep a laptop run under an hour
REDUCED = {"ja4", "year"}
REDUCED_SETS = ("ENV", "TLS", "BEH", "HRd", "TLS+BEH", "HRb+TLS+BEH", "HR+TLS+BEH")


def cap_per_capture(df: pd.DataFrame, k: int, seed: int = 0) -> np.ndarray:
    """Boolean mask keeping at most k labelled connections per (capture, class), uniformly at random.
    Features are computed on ALL connections first, so host context is untouched."""
    keep = np.zeros(len(df), dtype=bool)
    lab = df["y"].notna().values
    rng = np.random.default_rng(seed)
    for _, idx in df[lab].groupby(["capture_id", "y"]).indices.items():
        rows = np.where(lab)[0][idx]
        keep[rows if len(rows) <= k else rng.choice(rows, k, replace=False)] = True
    return keep


def run(df: pd.DataFrame, fams: dict, out: str, seeds=(0, 1, 2)):
    lab = df["y"].notna().values
    D = df[lab].reset_index(drop=True)
    X = {k: v[lab].reset_index(drop=True) for k, v in fams.items()}
    y = D["y"].astype(int).values
    caps = D["capture_id"].values
    w = capture_weights(D)
    rows, preds = [], {}
    splits = {}
    splits["capture"] = list(GroupKFold(5).split(D, y, D["capture_id"]))
    splits["ja4"] = list(GroupKFold(5).split(D, y, D["ja4"]))
    srcs = sorted(D["source"].unique())
    if len(srcs) >= 2:
        splits["source"] = [(np.where(D["source"] != s)[0], np.where(D["source"] == s)[0]) for s in srcs]
    if (D["year"] <= 2018).any() and (D["year"] >= 2019).any():
        splits["time"] = [(np.where(D["year"] <= 2018)[0], np.where(D["year"] >= 2019)[0])]
    yrs = sorted(D["year"].unique())
    if len(yrs) >= 3:  # leave-one-year-out within the data (temporal source shift)
        splits["year"] = [(np.where(D["year"] != yv)[0], np.where(D["year"] == yv)[0]) for yv in yrs
                          if (D.loc[D["year"] == yv, "y"].nunique() == 2)]
    for sname, folds in splits.items():
        for setname, fl in SETS.items():
            if sname in REDUCED and setname not in REDUCED_SETS:
                continue
            Xs = pd.concat([X[f] for f in fl], axis=1)
            Xs.columns = [f"{i}_{c}" for i, c in enumerate(Xs.columns)]
            seed_list = seeds if (sname == "capture" and setname in KEY_SETS) else (0,)
            for seed in seed_list:
                p = np.full(len(D), np.nan)
                for tr, te in folds:
                    if len(np.unique(y[tr])) < 2:
                        continue
                    p[te], _ = fit_predict(Xs.iloc[tr], y[tr], w[tr], Xs.iloc[te], seed)
                ok = ~np.isnan(p)
                m = metrics(y[ok], p[ok], caps[ok])
                m.update({"split": sname, "set": setname, "seed": seed})
                if sname == "source":
                    for (tr, te), s in zip(folds, srcs):
                        mm = metrics(y[te], p[te], caps[te])
                        m[f"auc_{s}"] = mm["roc_auc"]
                        m[f"balacc_{s}"] = mm["bal_acc_cw"]
                rows.append(m)
                if seed == 0:
                    preds[(sname, setname)] = p
                print(f"{sname:8s} {setname:16s} seed{seed} bal={m['bal_acc_cw']:.3f} auc={m['roc_auc']:.3f} tpr1%={m['tpr_at_1pct']:.3f}", flush=True)
    res = pd.DataFrame(rows)
    os.makedirs(out, exist_ok=True)
    res.to_csv(os.path.join(out, "split_ladder.csv"), index=False)
    return res, preds, D, X, y, caps, w


def eli(res: pd.DataFrame) -> dict:
    """ELI = (env_only - 0.5) / (max(env_only, other) - 0.5), capture-disjoint balanced accuracy."""
    r = res[(res.split == "capture") & (res.seed == 0)].set_index("set")["bal_acc_cw"]
    out = {}
    for other in ("TLS", "BEH", "HRb", "TLS+BEH", "HR+TLS+BEH"):
        env, oth = r.get("ENV", np.nan), r.get(other, np.nan)
        den = max(env, oth) - 0.5
        out[f"ELI_env_vs_{other}"] = float((env - 0.5) / den) if den > 0 else np.nan
    return out


def unsupervised_auc(df: pd.DataFrame, fams: dict) -> dict:
    """Label-free host x JA4 outlier score: no training at all."""
    sc = F.unsupervised_stack_outlier(fams["HRb"]).values
    lab = df["y"].notna().values
    y = df.loc[lab, "y"].astype(int).values
    out = {"all": float(roc_auc_score(y, sc[lab])) if len(np.unique(y)) == 2 else np.nan}
    for src in sorted(df["source"].unique()):
        m = lab & (df["source"] == src).values
        yy = df.loc[m, "y"].astype(int).values
        if len(np.unique(yy)) == 2:
            out[src] = float(roc_auc_score(yy, sc[m]))
    # restricted to natural mimicry: malicious rows whose exact JA4 also has benign rows on the same host
    d = df[lab].assign(s=sc[lab])
    ben = set(zip(d.loc[d.y == 0, "host"], d.loc[d.y == 0, "ja4"]))
    shared = np.array([(h, j) in ben for h, j in zip(d["host"], d["ja4"])], dtype=bool)
    mim = d[(d.y == 0).values | shared]
    if mim["y"].nunique() == 2:
        out["natural_mimicry_subset"] = float(roc_auc_score(mim["y"].astype(int), mim["s"]))
        out["natural_mimicry_share"] = float(((d.y == 1).values & shared).sum() / max(1, (d.y == 1).sum()))
    return out


SIZE_COLS = ["b_bytes_up", "b_bytes_down", "b_mean_up", "b_std_up", "b_max_up", "b_mean_down", "b_std_down",
             "b_max_down"] + [f"b_splt_{i}" for i in range(8)]


def perturb_hosts(df: pd.DataFrame, seed=0) -> pd.DataFrame:
    """Host-constant nuisance: every host gets its own size factor (padding / segmentation) and
    timing factor (latency), the kind of difference a new network adds. Labels untouched."""
    rng = np.random.default_rng(seed)
    d = df.copy()
    hosts = d["host"].unique()
    sf = dict(zip(hosts, rng.uniform(0.75, 1.35, len(hosts))))
    tf = dict(zip(hosts, rng.uniform(0.5, 2.5, len(hosts))))
    s = d["host"].map(sf).values
    t = d["host"].map(tf).values
    for c in SIZE_COLS:
        d[c] = d[c].astype(float) * s
    d["duration"] = d["duration"].astype(float) * t
    d["t_clienthello"] = d.groupby("host")["t_clienthello"].transform(lambda x: x.min()) + \
        (d["t_clienthello"] - d.groupby("host")["t_clienthello"].transform("min")) * t
    return d


def _setX(fams, setname):
    Xs = pd.concat([fams[f] for f in SETS[setname]], axis=1)
    Xs.columns = [f"{i}_{c}" for i, c in enumerate(Xs.columns)]
    return Xs


def stress_and_bags(df: pd.DataFrame, fams: dict, sets=("TLS+BEH", "HRb+TLS+BEH", "HR+TLS+BEH")) -> dict:
    """(1) nuisance stress test: train clean, test on host-perturbed copies of the test hosts.
    (2) environment-matched negative bags: each infected host vs the SAME host with its labelled
        malicious connections removed (features rebuilt), scored by the max connection score.
    Capture-disjoint folds over hosts; predictions on every connection (labelled or not)."""
    out = {}
    fams_p = F.build(perturb_hosts(df))
    neg = df[df["y"].fillna(0) != 1]
    fams_n = F.build(neg)
    caps = df["capture_id"].values
    lab = df["y"].notna().values
    folds = list(GroupKFold(5).split(df, groups=caps))
    w_all = np.zeros(len(df))
    for setname in sets:
        X, Xp, Xn = _setX(fams, setname), _setX(fams_p, setname), _setX(fams_n, setname)
        Xp, Xn = Xp.reindex(columns=X.columns, fill_value=0), Xn.reindex(columns=X.columns, fill_value=0)
        p_clean, p_pert = np.full(len(df), np.nan), np.full(len(df), np.nan)
        p_neg = pd.Series(np.nan, index=neg.index)
        for tr, te in folds:
            trl = tr[lab[tr]]
            Dtr = df.iloc[trl].reset_index(drop=True)
            w = capture_weights(Dtr)
            m = XGBClassifier(**XGB, random_state=0)
            m.fit(X.iloc[trl], Dtr["y"].astype(int).values, sample_weight=w)
            p_clean[te] = m.predict_proba(X.iloc[te])[:, 1]
            p_pert[te] = m.predict_proba(Xp.iloc[te])[:, 1]
            te_caps = set(caps[te])
            nm = neg["capture_id"].isin(te_caps).values
            if nm.any():
                p_neg.iloc[np.where(nm)[0]] = m.predict_proba(Xn.iloc[np.where(nm)[0]])[:, 1]
        y = df.loc[lab, "y"].astype(int).values
        cw = df.loc[lab, "capture_id"].values
        mc, mp = metrics(y, p_clean[lab], cw), metrics(y, p_pert[lab], cw)
        out[f"stress_{setname}"] = {"auc_clean": mc["roc_auc"], "auc_perturbed": mp["roc_auc"],
                                   "tpr1_clean": mc["tpr_at_1pct"], "tpr1_perturbed": mp["tpr_at_1pct"],
                                   "auc_drop": mc["roc_auc"] - mp["roc_auc"]}
        # bags
        pos, negs, hit1, top_unknown = [], [], [], []
        dd = df.assign(s=p_clean)
        for h, g in dd.groupby("host"):
            if not (g["y"] == 1).any():
                continue
            pos.append(g["s"].max())
            g_sorted = g.sort_values("s", ascending=False)
            hit1.append(float(g_sorted["y"].iloc[0] == 1))
            top_unknown.append(float(pd.isna(g_sorted["y"].iloc[0])))
            gn = p_neg[neg["host"] == h]
            if len(gn):
                negs.append(gn.max())
        if pos and negs:
            yb = np.r_[np.ones(len(pos)), np.zeros(len(negs))]
            out[f"bags_{setname}"] = {"bag_auc_env_matched": float(roc_auc_score(yb, np.r_[pos, negs])),
                                     "hosts": len(pos), "hit@1_all_connections": float(np.mean(hit1)),
                                     "top_is_unlabelled": float(np.mean(top_unknown))}
        print(setname, out.get(f"stress_{setname}"), out.get(f"bags_{setname}"), flush=True)
    return out


def source_identifiability(D: pd.DataFrame, X: dict, seed=0) -> dict:
    """How well each family predicts WHICH dataset a connection came from
    (capture-grouped CV, balanced accuracy; chance = 1/#sources). Lower means the
    family carries less of the environment."""
    from sklearn.metrics import balanced_accuracy_score
    srcs = D["source"].astype("category")
    ys = srcs.cat.codes.values
    if len(np.unique(ys)) < 2:
        return {}
    out = {"chance": 1.0 / len(np.unique(ys))}
    for fam, M in X.items():
        p = np.zeros(len(D), dtype=int)
        for tr, te in GroupKFold(5).split(M, ys, D["capture_id"]):
            m = XGBClassifier(n_estimators=150, max_depth=4, learning_rate=0.1, tree_method="hist",
                              n_jobs=4, random_state=seed)
            m.fit(M.iloc[tr], ys[tr])
            p[te] = m.predict(M.iloc[te])
        out[fam] = float(balanced_accuracy_score(ys, p))
    return out


def bootstrap_diff(y, pa, pb, caps, fpr_t=0.01, n=1000, seed=0):
    """Capture-cluster bootstrap of TPR@fpr_t(a) - TPR@fpr_t(b) and AUC(a) - AUC(b)."""
    rng = np.random.default_rng(seed)
    uc = np.unique(caps)
    idx_by = {c: np.where(caps == c)[0] for c in uc}
    dt, da = [], []
    for _ in range(n):
        samp = rng.choice(uc, len(uc), replace=True)
        ii = np.concatenate([idx_by[c] for c in samp])
        yy = y[ii]
        if len(np.unique(yy)) < 2:
            continue
        dt.append(tpr_at(yy, pa[ii], fpr_t) - tpr_at(yy, pb[ii], fpr_t))
        da.append(roc_auc_score(yy, pa[ii]) - roc_auc_score(yy, pb[ii]))
    q = lambda v: (float(np.mean(v)), float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5)))
    return {"d_tpr": q(dt), "d_auc": q(da)}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed/connections.parquet")
    ap.add_argument("--out", default="results")
    ap.add_argument("--tiers", default="gold_mal,weak_mal,benign", help="label tiers to train/test on")
    ap.add_argument("--hostname-only", action="store_true", help="drop bare-IP connections (bare-IP shortcut)")
    ap.add_argument("--skip-stress", action="store_true")
    ap.add_argument("--max-per-capture", type=int, default=100,
                    help="cap labelled connections per (capture, class) after feature building; 0 = no cap")
    a = ap.parse_args(argv)
    df = pd.read_parquet(a.data)
    df["host"] = df["capture_id"].astype(str) + "|" + df["client_ip"].astype(str)
    if a.hostname_only:
        df = df[df["sni"].fillna("") != ""].reset_index(drop=True)
    fams = F.build(df)  # HR uses every connection of the host, labelled or not
    keep = df["label_tier"].isin(a.tiers.split(","))
    df.loc[~keep, "y"] = np.nan
    if a.max_per_capture:
        m = cap_per_capture(df, a.max_per_capture)
        n0 = int(df["y"].notna().sum())
        df.loc[~m, "y"] = np.nan  # dropped rows stay as unlabelled host context
        print(f"capped labelled rows {n0} -> {int(df['y'].notna().sum())} (max {a.max_per_capture} per capture and class)")
    res, preds, D, X, y, caps, w = run(df, fams, a.out)
    summ = res.groupby(["split", "set"])[["bal_acc_cw", "roc_auc", "tpr_at_1pct", "tpr_at_0.1pct"]].mean().round(3)
    summ.to_csv(os.path.join(a.out, "summary.csv"))
    print(summ.to_string())
    e = eli(res)
    print("ELI:", e)
    extra = {"ELI": e}
    # per-host triage on the source split (ranks ALL connections of a host incl. unknown)
    lab_idx = np.where(df["y"].notna().values)[0]
    for sname in ("capture", "source"):
        for setname in ("TLS+BEH", "HRb+TLS+BEH", "HR+TLS+BEH"):
            p = preds.get((sname, setname))
            if p is None:
                continue
            full = np.full(len(df), np.nan)
            full[lab_idx] = p
            lab_only = df.iloc[lab_idx].assign(s=p)
            h1, p5, nh = triage(lab_only, p)
            extra[f"triage_{sname}_{setname}"] = {"hit@1": h1, "prec@5": p5, "hosts": nh}
    for sname in ("capture", "ja4", "source", "time"):
        for new in ("HRb+TLS+BEH", "HR+TLS+BEH"):
            pa, pb = preds.get((sname, new)), preds.get((sname, "TLS+BEH"))
            if pa is None or pb is None:
                continue
            ok = ~np.isnan(pa) & ~np.isnan(pb)
            extra[f"boot_{sname}_{new}_minus_TLS+BEH"] = bootstrap_diff(y[ok], pa[ok], pb[ok], caps[ok])
    extra["source_identifiability"] = source_identifiability(D, X)
    extra["unsupervised_stack_outlier_auc"] = unsupervised_auc(df, fams)
    if not a.skip_stress:
        extra.update(stress_and_bags(df, fams))
    json.dump(extra, open(os.path.join(a.out, "extra.json"), "w"), indent=2, default=float)
    print(json.dumps(extra, indent=2, default=float))


if __name__ == "__main__":
    main()
