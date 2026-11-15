"""Pre-registered confirmatory test on the 2022-2026 holdout. Run ONCE.

Train on every labelled 2013-2021 connection (exploratory data) with the frozen
settings, score the holdout once, and test the hypotheses in
docs/PREREG_ADDENDUM.md. Refuses to run if any frozen file changed.

Usage (via scripts/run_stage.sh confirm only):
    python -I -m ja4next.confirm --frozen docs/PREREG_FROZEN.sha256
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ja4next import features as F  # noqa: E402
from ja4next.evaluate import SETS, bootstrap_diff, cap_per_capture, capture_weights, fit_predict, metrics  # noqa: E402
from ja4next.process import main as process_main  # noqa: E402

ALPHA = 0.05


def verify(frozen: str):
    bad = []
    for line in open(frozen):
        h, path = line.strip().split(None, 1)
        path = path.lstrip("*")
        if hashlib.sha256(open(path, "rb").read()).hexdigest() != h:
            bad.append(path)
    if bad:
        raise SystemExit(f"REFUSED: files changed since freezing: {bad}")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--frozen", required=True)
    ap.add_argument("--out", default="results/confirmatory")
    a = ap.parse_args(argv)
    verify(a.frozen)
    process_main(["--files", "data/manifests/mta_files_holdout.csv", "--interim", "data/interim_holdout",
                  "--out", "data/processed/holdout.parquet"])
    tr = pd.read_parquet("data/processed/connections.parquet")
    te = pd.read_parquet("data/processed/holdout.parquet")
    run_confirm(tr[tr["year"] <= 2021], te[te["year"] >= 2022], a.out)


def run_confirm(tr: pd.DataFrame, te: pd.DataFrame, out: str) -> dict:
    """The registered analysis: train on tr, score te once, test H1-H6. Returns the hypothesis dict."""
    both = pd.concat([tr.assign(_part="train"), te.assign(_part="test")], ignore_index=True)
    both = both[both["sni"].fillna("") != ""].reset_index(drop=True)  # primary analysis: hostname-only
    fams = F.build(both)  # host-relative features are per host, so no train/test mixing
    both.loc[~cap_per_capture(both, 100), "y"] = np.nan  # registered cap: 100 per (capture, class)
    lab = both["y"].notna()
    is_tr = (both["_part"] == "train") & lab
    is_te = (both["_part"] == "test") & lab
    y = both["y"].values
    w = capture_weights(both[is_tr].reset_index(drop=True))
    preds, rows = {}, []
    for setname in ("TLS+BEH", "HR+TLS+BEH", "HRb+TLS+BEH", "ENV"):  # ENV last (H3)
        X = pd.concat([fams[f] for f in SETS[setname]], axis=1)
        X.columns = [f"{i}_{c}" for i, c in enumerate(X.columns)]
        p, _ = fit_predict(X[is_tr.values], y[is_tr.values].astype(int), w, X[is_te.values], seed=0)
        preds[setname] = p
        m = metrics(y[is_te.values].astype(int), p, both.loc[is_te, "capture_id"].values)
        m["set"] = setname
        rows.append(m)
    os.makedirs(out, exist_ok=True)
    pd.DataFrame(rows).to_csv(os.path.join(out, "holdout_metrics.csv"), index=False)
    yt = y[is_te.values].astype(int)
    caps = both.loc[is_te, "capture_id"].values
    b = bootstrap_diff(yt, preds["HR+TLS+BEH"], preds["TLS+BEH"], caps)
    res = {
        "H1_HR_improves_tpr_at_1pct": {"diff_mean_ci": b["d_tpr"], "supported": b["d_tpr"][1] > 0},
        "H2_HR_improves_auc": {"diff_mean_ci": b["d_auc"], "supported": b["d_auc"][1] > 0},
        "H3_env_alone_below_0.6_auc": {"auc": rows[-1]["roc_auc"], "supported": rows[-1]["roc_auc"] < 0.6},
    }
    # H4: natural mimicry on the holdout (hostname-only; capture-weighted over hosts with both classes)
    T = both[is_te.values].copy()
    T["host"] = T["capture_id"].astype(str) + "|" + T["client_ip"].astype(str)
    ben = set(zip(T.loc[T.y == 0, "host"], T.loc[T.y == 0, "ja4"]))
    hb = T.groupby("host")["y"].nunique()
    mal = T[(T.y == 1) & T["host"].isin(hb[hb == 2].index)]
    mal = mal.assign(shared=[(h, j) in ben for h, j in zip(mal["host"], mal["ja4"])])
    share = float(mal.groupby("capture_id")["shared"].mean().mean()) if len(mal) else float("nan")
    res["H4_mimicry_share_ge_0.50"] = {"share": share, "supported": share >= 0.50}
    # H5: host triage hit@1, paired bootstrap over infected hosts
    T["pa"], T["pb"] = preds["HR+TLS+BEH"], preds["TLS+BEH"]
    hits = []
    for h, g in T.groupby("host"):
        if (g.y == 1).any():
            hits.append((float(g.sort_values("pa").y.iloc[-1] == 1), float(g.sort_values("pb").y.iloc[-1] == 1)))
    hits = np.array(hits)
    rng = np.random.default_rng(0)
    diffs = [hits[rng.integers(0, len(hits), len(hits))].mean(0) @ np.array([1, -1]) for _ in range(1000)] if len(hits) else [np.nan]
    res["H5_triage_hit1"] = {"hr": float(hits[:, 0].mean()) if len(hits) else None,
                             "base": float(hits[:, 1].mean()) if len(hits) else None,
                             "diff_ci": (float(np.percentile(diffs, 2.5)), float(np.percentile(diffs, 97.5))),
                             "supported": float(np.percentile(diffs, 2.5)) > 0}
    # H6: no-training rule, hr_dest_share as the score
    from sklearn.metrics import roc_auc_score
    rule = fams["HRd"]["hr_dest_share"].values[is_te.values]
    auc6 = float(roc_auc_score(yt, rule)) if len(np.unique(yt)) == 2 else float("nan")
    res["H6_dest_share_rule_auc_ge_0.85"] = {"auc": auc6, "supported": auc6 >= 0.85}
    json.dump(res, open(os.path.join(out, "hypotheses.json"), "w"), indent=2, default=str)
    print(json.dumps(res, indent=2, default=str))
    return res


if __name__ == "__main__":
    main()
