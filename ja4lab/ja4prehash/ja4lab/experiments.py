"""
All experiments of the study, one command:

    python -m ja4lab.experiments --instances data/processed/instances.csv --out results/

Research questions answered (each writes its own CSV in results/):
  RQ1  Collision ceiling      : how much malicious traffic has EXACTLY the same pre-hash
                                parameters as benign traffic? (no model can separate those)
                                -> rq1_collisions.csv
  RQ2  Unseen fingerprints    : detection when the test JA4 was never seen in training
                                (leave-fingerprint-out) vs exact lookup vs fuzzy kNN matching,
                                and vs the optimistic random split.  -> rq2_detection.csv
  RQ3  What information helps : ablation CH_STRICT -> +CH_EXT -> +JA4S -> +JA4T.  -> rq3_ablation.csv
  RQ4  Generalisation limits  : leave-FAMILY-out and leave-DATASET-out (shortcut test).
                                -> rq2_detection.csv (split column)
  RQ5  Family attribution     : predict malware family / application for unseen fingerprints,
                                with an abstain option (open-set).  -> rq5_attribution.csv
  Explain                     : grouped permutation importance.  -> importance_groups.csv
"""
from __future__ import annotations

import argparse
import json
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, balanced_accuracy_score, f1_score,
                             roc_auc_score, roc_curve, precision_score, recall_score)
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold, StratifiedKFold
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .features import Featurizer, GROUPS

warnings.filterwarnings("ignore")
SEED = 42

ABLATIONS = {
    "A1_CH_STRICT": ["CH_STRICT"],
    "A2_+CH_EXT": ["CH_STRICT", "CH_EXT"],
    "A3_+JA4S": ["CH_STRICT", "CH_EXT", "JA4S"],
    "A4_+JA4T": ["CH_STRICT", "CH_EXT", "JA4S", "JA4T"],
}


def models():
    return {
        "HGB": lambda: HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08,
                                                      class_weight="balanced", random_state=SEED),
        "RF": lambda: RandomForestClassifier(n_estimators=400, min_samples_leaf=2, n_jobs=-1,
                                             class_weight="balanced_subsample", random_state=SEED),
        "LR": lambda: make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, C=0.5,
                                                                         class_weight="balanced")),
    }


# ----------------------------------------------------------------------------- splits

def make_splits(df: pd.DataFrame, y: np.ndarray, kind: str, k: int = 5):
    if kind == "random":
        return list(StratifiedKFold(k, shuffle=True, random_state=SEED).split(df, y)), None
    col = {"leave_fingerprint_out": "ja4", "leave_family_out": "family",
           "leave_dataset_out": "source"}[kind]
    groups = df[col].astype(str) + ("|" + df["label"] if col != "ja4" else "")
    n_groups_per_class = df.assign(g=groups).groupby("label")["g"].nunique()
    kk = int(min(k, n_groups_per_class.min()))
    if kk < 2:
        return [], f"needs >=2 distinct {col} per class (have {n_groups_per_class.to_dict()})"
    return list(StratifiedGroupKFold(kk, shuffle=True, random_state=SEED).split(df, y, groups)), None


# ----------------------------------------------------------------------------- metrics

def metrics(y, p, thr):
    out = {"n_test": len(y), "n_test_mal": int(y.sum())}
    if len(np.unique(y)) == 2:
        out["pr_auc"] = average_precision_score(y, p)
        out["roc_auc"] = roc_auc_score(y, p)
        fpr, tpr, _ = roc_curve(y, p)
        out["tpr@1%fpr"] = float(np.interp(0.01, fpr, tpr))
    yh = (p >= thr).astype(int)
    out.update({"precision": precision_score(y, yh, zero_division=0),
                "recall": recall_score(y, yh, zero_division=0),
                "f1": f1_score(y, yh, zero_division=0),
                "bal_acc": balanced_accuracy_score(y, yh) if len(np.unique(y)) == 2 else np.nan,
                "fpr": float(((yh == 1) & (y == 0)).sum() / max(1, (y == 0).sum()))})
    return out


def choose_threshold(make_model, Xtr, ytr, gtr, target_fpr=0.01):
    """Pick the decision threshold on an inner, group-disjoint validation split (never on test)."""
    try:
        gss = GroupShuffleSplit(1, test_size=0.25, random_state=SEED)
        a, b = next(gss.split(Xtr, ytr, gtr))
        if len(np.unique(ytr[a])) < 2 or len(np.unique(ytr[b])) < 2:
            return 0.5
        m = make_model().fit(Xtr[a], ytr[a])
        pv = m.predict_proba(Xtr[b])[:, 1]
        neg = np.sort(pv[ytr[b] == 0])
        if len(neg) == 0:
            return 0.5
        thr = neg[min(len(neg) - 1, int(np.ceil((1 - target_fpr) * len(neg))))]
        # also consider the F1-optimal threshold; take the stricter of both
        cand = np.unique(pv)
        f1s = [f1_score(ytr[b], pv >= c, zero_division=0) for c in cand[:: max(1, len(cand) // 200)]]
        f1thr = cand[:: max(1, len(cand) // 200)][int(np.argmax(f1s))]
        return float(max(thr, f1thr) if thr < 0.999 else f1thr)
    except ValueError:
        return 0.5


# ----------------------------------------------------------------------------- baselines

def exact_lookup(train: pd.DataFrame, test: pd.DataFrame):
    """Signature lookup trained on the SAME training data: JA4 -> majority label."""
    table = train.groupby("ja4")["y"].mean()
    known = test["ja4"].isin(table.index).values
    p = test["ja4"].map(table).fillna(0.0).values     # unknown JA4 -> "no alert"
    return p, float(known.mean())


def knn_fuzzy(Xtr_bool, ytr, Xte_bool, k=5):
    """Fuzzy matching baseline (Jaccard nearest neighbours on token sets)."""
    m = KNeighborsClassifier(n_neighbors=min(k, len(ytr)), metric="jaccard", weights="distance")
    m.fit(Xtr_bool, ytr)
    return m.predict_proba(Xte_bool)[:, 1]


# ----------------------------------------------------------------------------- RQ1

def rq1_collisions(df: pd.DataFrame) -> pd.DataFrame:
    keys = {
        "JA4 hash": ["ja4"],
        "JA4_r (sorted raw)": ["ja4_r"],
        "JA4_ro (wire order raw)": ["ja4_ro"],
        "JA4_ro + groups/keyshare": ["ja4_ro", "ch_groups", "ch_key_share_groups", "ch_ec_point_formats"],
        "... + JA4S": ["ja4_ro", "ch_groups", "ch_key_share_groups", "ch_ec_point_formats", "ja4s"],
        "... + JA4S + JA4T": ["ja4_ro", "ch_groups", "ch_key_share_groups", "ch_ec_point_formats", "ja4s", "ja4t"],
    }
    rows = []
    for name, cols in keys.items():
        k = df[cols].astype(str).agg("|".join, axis=1)
        lab = df.assign(k=k).groupby("k")["label"].agg(lambda s: set(s))
        shared = {kk for kk, s in lab.items() if len(s) > 1}
        mal = df["label"] == "malicious"
        rows.append({
            "key": name,
            "distinct_keys": int(k.nunique()),
            "mal_instances": int(mal.sum()),
            "mal_instances_sharing_key_with_benign": int(k[mal].isin(shared).sum()),
            "pct_mal_inseparable": round(100 * k[mal].isin(shared).mean(), 2),
            "pct_benign_sharing_with_mal": round(100 * k[~mal].isin(shared).mean(), 2),
        })
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------- RQ2/3/4

def run_detection(df: pd.DataFrame, out: Path, splits_to_run, quick=False):
    y = (df["label"] == "malicious").astype(int).values
    df = df.assign(y=y)
    rows = []
    for split in splits_to_run:
        folds, why = make_splits(df, y, split)
        if not folds:
            print(f"  [skip] {split}: {why}")
            rows.append({"split": split, "method": "SKIPPED", "note": why})
            continue
        print(f"  split={split} folds={len(folds)}")
        ablations = ABLATIONS if not quick else {"A4_+JA4T": ABLATIONS["A4_+JA4T"]}
        for fi, (tr, te) in enumerate(folds):
            dtr, dte = df.iloc[tr], df.iloc[te]
            unseen = ~dte["ja4"].isin(set(dtr["ja4"])).values
            # --- baseline: exact lookup
            p, cov = exact_lookup(dtr, dte)
            for subset, mask in (("all", np.ones(len(dte), bool)), ("unseen_ja4_only", unseen)):
                if mask.sum() == 0 or dte["y"].values[mask].sum() == 0:
                    continue
                r = metrics(dte["y"].values[mask], p[mask], 0.5)
                rows.append({"split": split, "fold": fi, "method": "ExactLookup(JA4)", "features": "hash",
                             "subset": subset, "lookup_coverage": cov, **r})
            # --- baseline: fuzzy kNN on strict tokens
            fz = Featurizer(groups=["CH_STRICT"]).fit(dtr)
            Xb_tr = fz.transform(dtr).values > 0
            Xb_te = fz.transform(dte).values > 0
            pk = knn_fuzzy(Xb_tr, dtr["y"].values, Xb_te)
            for subset, mask in (("all", np.ones(len(dte), bool)), ("unseen_ja4_only", unseen)):
                if mask.sum() == 0 or dte["y"].values[mask].sum() == 0:
                    continue
                rows.append({"split": split, "fold": fi, "method": "kNN-Jaccard", "features": "CH_STRICT",
                             "subset": subset, **metrics(dte["y"].values[mask], pk[mask], 0.5)})
            # --- ML models x feature ablations
            for ab_name, groups in ablations.items():
                fz = Featurizer(groups=groups).fit(dtr)
                Xtr, Xte = fz.transform(dtr).values, fz.transform(dte).values
                model_set = models() if ab_name == "A4_+JA4T" else {"HGB": models()["HGB"]}
                for mname, mk in model_set.items():
                    thr = choose_threshold(mk, Xtr, dtr["y"].values, dtr["ja4"].values)
                    m = mk().fit(Xtr, dtr["y"].values)
                    pp = m.predict_proba(Xte)[:, 1]
                    for subset, mask in (("all", np.ones(len(dte), bool)), ("unseen_ja4_only", unseen)):
                        if mask.sum() == 0 or dte["y"].values[mask].sum() == 0:
                            continue
                        rows.append({"split": split, "fold": fi, "method": mname, "features": ab_name,
                                     "subset": subset, "threshold": thr,
                                     **metrics(dte["y"].values[mask], pp[mask], thr)})
    res = pd.DataFrame(rows)
    res.to_csv(out / "rq2_detection_folds.csv", index=False)
    num = [c for c in ["pr_auc", "roc_auc", "tpr@1%fpr", "precision", "recall", "f1", "bal_acc", "fpr",
                       "lookup_coverage", "n_test"] if c in res.columns]
    ok = res[res["method"] != "SKIPPED"]
    if ok.empty:
        return res, pd.DataFrame()
    summ = ok.groupby(["split", "subset", "method", "features"])[num].agg(["mean", "std"]).round(4)
    summ.columns = [f"{a}_{b}" for a, b in summ.columns]
    summ = summ.reset_index()
    summ.to_csv(out / "rq2_detection.csv", index=False)
    abl = summ[summ["method"] == "HGB"]
    abl.to_csv(out / "rq3_ablation.csv", index=False)
    return res, summ


# ----------------------------------------------------------------------------- RQ5

def rq5_attribution(df: pd.DataFrame, out: Path, label_col="family", min_fps=2, taus=(0.0, 0.5, 0.7, 0.9)):
    """Family / application attribution on UNSEEN fingerprints (grouped by ja4), with abstention."""
    fam_fps = df.groupby(label_col)["ja4"].nunique()
    keep = fam_fps[fam_fps >= min_fps].index
    d = df[df[label_col].isin(keep)].reset_index(drop=True)
    if d[label_col].nunique() < 3:
        pd.DataFrame([{"note": f"need >=3 {label_col}s with >={min_fps} distinct JA4 each"}]).to_csv(
            out / "rq5_attribution.csv", index=False)
        return None
    y = d[label_col].values
    kk = int(min(5, d.groupby(label_col)["ja4"].nunique().min()))
    folds = StratifiedGroupKFold(max(2, kk), shuffle=True, random_state=SEED).split(d, y, d["ja4"])
    rows, allp, ally = [], [], []
    for fi, (tr, te) in enumerate(folds):
        fz = Featurizer(groups=["CH_STRICT", "CH_EXT", "JA4S", "JA4T"]).fit(d.iloc[tr])
        m = HistGradientBoostingClassifier(max_iter=300, class_weight="balanced", random_state=SEED)
        m.fit(fz.transform(d.iloc[tr]).values, y[tr])
        pr = m.predict_proba(fz.transform(d.iloc[te]).values)
        pred = m.classes_[pr.argmax(1)]
        conf = pr.max(1)
        seen_classes = set(y[tr])
        for tau in taus:
            acc_mask = conf >= tau
            yt = y[te]
            rows.append({"fold": fi, "tau": tau,
                         "coverage": float(acc_mask.mean()),
                         "accuracy_on_answered": float((pred[acc_mask] == yt[acc_mask]).mean()) if acc_mask.any() else np.nan,
                         "macro_f1_on_answered": f1_score(yt[acc_mask], pred[acc_mask], average="macro") if acc_mask.any() else np.nan,
                         "n_test": len(te), "classes_in_test_not_train": len(set(yt) - seen_classes)})
    r = pd.DataFrame(rows).groupby("tau").mean(numeric_only=True).round(4).reset_index()
    r.to_csv(out / "rq5_attribution.csv", index=False)
    return r


# ----------------------------------------------------------------------------- importance

def group_importance(df: pd.DataFrame, out: Path, n_repeats=5):
    y = (df["label"] == "malicious").astype(int).values
    folds, _ = make_splits(df, y, "leave_fingerprint_out")
    if not folds:
        return None
    tr, te = folds[0]
    fz = Featurizer(groups=GROUPS[:4]).fit(df.iloc[tr])
    Xtr, Xte = fz.transform(df.iloc[tr]), fz.transform(df.iloc[te])
    m = HistGradientBoostingClassifier(max_iter=300, class_weight="balanced", random_state=SEED)
    m.fit(Xtr.values, y[tr])
    base = average_precision_score(y[te], m.predict_proba(Xte.values)[:, 1])
    rng = np.random.default_rng(SEED)
    groups = pd.Series(fz.groups_of(Xte.columns), index=Xte.columns)
    rows = []
    for g in groups.unique():
        cols = groups[groups == g].index
        drops = []
        for _ in range(n_repeats):
            Xp = Xte.copy()
            perm = rng.permutation(len(Xp))
            Xp[cols] = Xp[cols].values[perm]
            drops.append(base - average_precision_score(y[te], m.predict_proba(Xp.values)[:, 1]))
        rows.append({"group": g, "n_features": len(cols), "pr_auc_drop_mean": np.mean(drops),
                     "pr_auc_drop_std": np.std(drops)})
    # top single features
    single = []
    for c in Xte.columns:
        if Xte[c].nunique() < 2:
            continue
        Xp = Xte.copy()
        Xp[c] = rng.permutation(Xp[c].values)
        single.append({"feature": c, "group": groups[c],
                       "pr_auc_drop": base - average_precision_score(y[te], m.predict_proba(Xp.values)[:, 1])})
    pd.DataFrame(rows).sort_values("pr_auc_drop_mean", ascending=False).to_csv(out / "importance_groups.csv", index=False)
    pd.DataFrame(single).sort_values("pr_auc_drop", ascending=False).head(40).to_csv(out / "importance_top_features.csv", index=False)


# ----------------------------------------------------------------------------- figures

def figures(summ: pd.DataFrame, coll: pd.DataFrame, out: Path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    if summ is not None and not summ.empty and "pr_auc_mean" in summ:
        s = summ[(summ["subset"] == "all") & summ["method"].isin(["ExactLookup(JA4)", "kNN-Jaccard", "HGB"])]
        s = s[(s["method"] != "HGB") | (s["features"] == "A4_+JA4T")]
        piv = s.pivot_table(index="split", columns="method", values="pr_auc_mean")
        ax = piv.plot.bar(figsize=(8, 4), rot=0)
        ax.set_ylabel("PR-AUC"); ax.set_ylim(0, 1); ax.set_title("Detection by evaluation protocol")
        plt.tight_layout(); plt.savefig(out / "fig_protocols.png", dpi=200); plt.close()
        a = summ[(summ["method"] == "HGB") & (summ["subset"] == "all") & (summ["split"] == "leave_fingerprint_out")]
        if not a.empty:
            ax = a.set_index("features")["pr_auc_mean"].plot.bar(figsize=(7, 4), rot=15,
                                                                   yerr=a.set_index("features")["pr_auc_std"])
            ax.set_ylabel("PR-AUC (unseen JA4)"); ax.set_ylim(0, 1); ax.set_title("Ablation: which JA4+ inputs help")
            plt.tight_layout(); plt.savefig(out / "fig_ablation.png", dpi=200); plt.close()
    if coll is not None and not coll.empty:
        ax = coll.set_index("key")["pct_mal_inseparable"].plot.barh(figsize=(8, 3.5))
        ax.set_xlabel("% malicious instances with a benign twin"); ax.set_title("Collision ceiling (RQ1)")
        plt.tight_layout(); plt.savefig(out / "fig_collisions.png", dpi=200); plt.close()


# ----------------------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--instances", required=True)
    ap.add_argument("--out", default="results")
    ap.add_argument("--quick", action="store_true", help="fewer ablations (debugging)")
    ap.add_argument("--splits", default="random,leave_fingerprint_out,leave_family_out,leave_dataset_out")
    a = ap.parse_args(argv)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(a.instances, dtype=str, keep_default_na=False, low_memory=False)
    df = df[(df.get("kind", "tls") == "tls") & df["label"].isin(["benign", "malicious"])].reset_index(drop=True)
    info = {"instances": len(df), "malicious": int((df["label"] == "malicious").sum()),
            "benign": int((df["label"] == "benign").sum()), "unique_ja4": int(df["ja4"].nunique()),
            "families": int(df["family"].nunique()), "sources": int(df["source"].nunique())}
    print("Dataset:", info)
    (out / "dataset_summary.json").write_text(json.dumps(info, indent=2))

    print("RQ1 collisions ..."); coll = rq1_collisions(df); coll.to_csv(out / "rq1_collisions.csv", index=False)
    print(coll.to_string(index=False))
    print("RQ2-4 detection ...")
    _, summ = run_detection(df, out, a.splits.split(","), quick=a.quick)
    print("RQ5 attribution ...")
    mal = df[df["label"] == "malicious"]
    rq5_attribution(mal, out)
    print("Importance ..."); group_importance(df, out)
    figures(summ, coll, out)
    if summ is not None and not summ.empty:
        cols = ["split", "subset", "method", "features", "pr_auc_mean", "tpr@1%fpr_mean", "recall_mean",
                "fpr_mean", "lookup_coverage_mean"]
        cols = [c for c in cols if c in summ.columns]
        view = summ[(summ["method"] != "HGB") | (summ["features"] == "A4_+JA4T")][cols]
        md = view.to_markdown(index=False) if hasattr(view, "to_markdown") else view.to_string(index=False)
        (out / "SUMMARY.md").write_text("# Main results\n\n" + md + "\n")
        print(view.to_string(index=False))
    print(f"\nAll results in {out}/")


if __name__ == "__main__":
    main()
