"""
The detector on real captures, with connection-level labels.

This is the `--real-pcap` path AGENTS.md asks for. It runs the project's own
sensor (Module 2) over real pcaps, joins each flow to an external label by
5-tuple (the join is the only place addresses are used; rule 2), and then
asks four questions, each under two splits:

  capture   5 folds, no capture in two folds (rule 3)
  source    leave one source out: a different set of machines and years

  Q1  How does Tier 2 on the 14-D vector do on real traffic?
  Q2  Does D(x) help, with the four hand-written browser profiles and with
      classes learned from the data (the client TLS stack)?
  Q3  Does host context (module2_sensor/host_context.py) help, in batch and
      in causal (deployable) form, and which block of it?
  Q4  How good is a no-training rule on one host-context number?

Labels file (CSV): pcap, capture_id, source, cli_ip, cli_port, srv_ip,
srv_port, label (1 malicious / 0 benign), has_sni; optional ja4_ref (a JA4
from an independent extractor, used only to check the sensor).

Usage:
    python3 scripts/05_real_pcap_eval.py --labels labels.csv --out results/real_pcap
Thresholds are never tuned on test data: every operating point is read off the
test ROC curve at a stated false-positive rate, or calibrated on training
benign flows (rule 4).
"""
from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
import warnings
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from idps.features import FEATURE_NAMES  # noqa: E402
from idps.module2_sensor.host_context import (CONTEXT_NAMES, DEST_IDX,  # noqa: E402
                                               RELATIVE_IDX, host_context)
from idps.module2_sensor.sources import read_pcap  # noqa: E402
from idps.module3_ml.dissonance import DissonanceConfig, DissonanceModel  # noqa: E402
from idps.module3_ml.tier2_supervised import SupervisedConfig  # noqa: E402

MAX_PER_CAPTURE = 100      # labelled flows per capture and class (beacon-heavy captures)


# --------------------------------------------------------------------------
# Stage 1: sensor
# --------------------------------------------------------------------------
def _sense(pcap: str):
    try:
        recs = list(read_pcap(pcap, idle_timeout=120.0))
    except Exception as e:  # noqa: BLE001
        return pcap, None, repr(e)
    if not recs:
        return pcap, None, "no flows"
    rows = pd.DataFrame({
        "pcap": pcap,
        "cli_ip": [r.src_ip for r in recs], "cli_port": [r.src_port for r in recs],
        "srv_ip": [r.dst_ip for r in recs], "srv_port": [r.dst_port for r in recs],
        "declared": [r.declared for r in recs], "stack": [r.stack or "none" for r in recs],
        "ja4": [r.ja4 or "" for r in recs], "sensor_sni": [int(r.has_sni) for r in recs],
    })
    X = np.vstack([r.features for r in recs])
    return pcap, (rows, X, host_context(recs), host_context(recs, causal=True)), ""


def run_sensor(labels: pd.DataFrame, cache: str, workers: int):
    if os.path.exists(cache):
        return pickle.load(open(cache, "rb"))
    pcaps = sorted(labels["pcap"].unique())
    parts, fails = [], []
    with ProcessPoolExecutor(workers) as ex:
        for i, (pcap, res, err) in enumerate(ex.map(_sense, pcaps, chunksize=4)):
            if res is None:
                fails.append((pcap, err))
            else:
                parts.append(res)
            if (i + 1) % 100 == 0:
                print(f"  sensor {i + 1}/{len(pcaps)}", flush=True)
    rows = pd.concat([p[0] for p in parts], ignore_index=True)
    out = (rows, np.vstack([p[1] for p in parts]), np.vstack([p[2] for p in parts]),
           np.vstack([p[3] for p in parts]), fails)
    pickle.dump(out, open(cache, "wb"))
    return out


# --------------------------------------------------------------------------
# Stage 2: evaluation helpers
# --------------------------------------------------------------------------
def tpr_at(y, s, fpr_t):
    from sklearn.metrics import roc_curve
    fpr, tpr, _ = roc_curve(y, s)
    ok = fpr <= fpr_t
    return float(tpr[ok].max()) if ok.any() else 0.0


def metrics(y, s):
    from sklearn.metrics import roc_auc_score
    return {"auc": float(roc_auc_score(y, s)), "tpr_at_1pct_fpr": tpr_at(y, s, 0.01),
            "tpr_at_0.1pct_fpr": tpr_at(y, s, 0.001)}


def capture_weights(y, caps):
    w = np.ones(len(y))
    for cls in (0, 1):
        m = y == cls
        cnt = pd.Series(caps[m]).map(pd.Series(caps[m]).value_counts()).values
        w[m] = 1.0 / cnt
        w[m] *= m.sum() / w[m].sum()
    return w


def xgb(seed=7):
    from xgboost import XGBClassifier
    c = SupervisedConfig()
    return XGBClassifier(n_estimators=c.n_estimators, max_depth=c.max_depth,
                         learning_rate=c.learning_rate, subsample=c.subsample,
                         colsample_bytree=c.colsample_bytree, min_child_weight=c.min_child_weight,
                         reg_lambda=c.reg_lambda, eval_metric="aucpr", tree_method="hist",
                         random_state=seed, n_jobs=int(os.environ.get("XGB_THREADS", "4")))


def dissonance(X, classes, benign_fit, min_samples):
    """D(x) for every row, densities fitted on `benign_fit` rows only (rule 3)."""
    try:
        m = DissonanceModel(DissonanceConfig(min_samples_per_class=min_samples))
        m.fit(X, classes, benign_fit)
        return m.score(X, classes), len(m.classes)
    except ValueError:
        return np.zeros(len(X)), 0


def boot_diff(y, a, b, caps, n=1000, seed=0):
    from sklearn.metrics import roc_auc_score
    rng = np.random.default_rng(seed)
    uc = np.unique(caps)
    where = {c: np.where(caps == c)[0] for c in uc}
    dt, da = [], []
    for _ in range(n):
        ii = np.concatenate([where[c] for c in rng.choice(uc, len(uc))])
        if len(np.unique(y[ii])) < 2:
            continue
        dt.append(tpr_at(y[ii], a[ii], 0.01) - tpr_at(y[ii], b[ii], 0.01))
        da.append(roc_auc_score(y[ii], a[ii]) - roc_auc_score(y[ii], b[ii]))
    q = lambda v: [float(np.mean(v)), float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]
    return {"tpr_at_1pct_fpr": q(dt), "auc": q(da)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", required=True)
    ap.add_argument("--out", default="results/real_pcap")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--all-connections", action="store_true",
                    help="keep connections without a server name (default: hostname-only, because "
                         "allowlist-based benign labels need a hostname and bare-IP rows are "
                         "then almost all malicious)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    labels = pd.read_csv(a.labels)
    rows, X14, CTXb, CTXc, fails = run_sensor(labels, os.path.join(a.out, "sensor_cache.pkl"), a.workers)
    report = {"pcaps": int(labels["pcap"].nunique()), "pcaps_failed": len(fails),
              "sensor_flows": int(len(rows))}

    # ---- join flows to labels by 5-tuple (addresses are used here and nowhere else)
    key = ["pcap", "cli_ip", "cli_port", "srv_ip", "srv_port"]
    rows["_i"] = np.arange(len(rows))
    J = labels.merge(rows.drop_duplicates(key), on=key, how="left")
    report["labelled_connections"] = int(len(J))
    report["matched_by_sensor"] = int(J["_i"].notna().sum())
    M = J[J["_i"].notna()].copy()
    M["_i"] = M["_i"].astype(int)
    report["matched_with_ja4"] = int((M["ja4"] != "").sum())
    if "ja4_ref" in M:
        both = M[(M["ja4"] != "") & M["ja4_ref"].notna()]
        report["ja4_agrees_with_reference_extractor"] = float((both["ja4"] == both["ja4_ref"]).mean())
    # a flow the sensor could not orient would show up reversed in the join
    rev = labels.merge(rows.rename(columns={"cli_ip": "srv_ip", "cli_port": "srv_port",
                                            "srv_ip": "cli_ip", "srv_port": "cli_port"}), on=key)
    report["flows_with_reversed_direction"] = int(len(rev))
    if not a.all_connections:
        M = M[M["has_sni"] == 1]
    M = M.reset_index(drop=True)
    y_all = M["label"].values.astype(int)
    caps_all = M["capture_id"].values
    report["evaluated"] = {"connections": int(len(M)), "malicious": int(y_all.sum()),
                           "benign": int((y_all == 0).sum()), "captures": int(M["capture_id"].nunique()),
                           "declared_class_counts": M["declared"].value_counts().to_dict()}

    # cap per capture and class
    rng = np.random.default_rng(0)
    keep = np.zeros(len(M), dtype=bool)
    for _, idx in M.groupby(["capture_id", "label"]).indices.items():
        keep[idx if len(idx) <= MAX_PER_CAPTURE else rng.choice(idx, MAX_PER_CAPTURE, replace=False)] = True
    E = np.where(keep)[0]
    y, caps, src = y_all[E], caps_all[E], M["source"].values[E]
    Xe, Cb, Cc = X14[M["_i"].values[E]], CTXb[M["_i"].values[E]], CTXc[M["_i"].values[E]]
    report["evaluated"]["after_cap"] = {"connections": int(len(E)), "malicious": int(y.sum())}

    from sklearn.model_selection import GroupKFold
    splits = {"capture": list(GroupKFold(5).split(Xe, y, caps))}
    sources = sorted(set(src))
    if len(sources) > 1:
        splits["source"] = [(np.where(src != s)[0], np.where(src == s)[0]) for s in sources]

    X_all = X14[M["_i"].values]
    results, preds = [], {}
    for sname, folds in splits.items():
        P = {k: np.full(len(E), np.nan) for k in
             ("tier2_14d", "tier2_14d+D_profiles", "tier2_14d+D_stacks", "tier2_14d+host_context",
              "tier2_14d+host_context_causal", "tier2_14d+dest_block", "tier2_14d+relative_block",
              "host_context_only", "D_profiles_alone", "D_stacks_alone", "rule_dest_share")}
        n_classes = {"profiles": [], "stacks": []}
        for tr, te in folds:
            if len(np.unique(y[tr])) < 2 or len(te) == 0:
                continue
            w = capture_weights(y[tr], caps[tr])
            # D(x): densities from benign flows of TRAINING captures only (uncapped)
            train_caps = set(caps[tr])
            fit_mask = np.array([c in train_caps for c in caps_all]) & (y_all == 0)
            Dp, kp = dissonance(X_all, M["declared"].values, fit_mask, 120)
            Ds, ks = dissonance(X_all, M["stack"].values, fit_mask, 60)
            n_classes["profiles"].append(kp)
            n_classes["stacks"].append(ks)
            Dp, Ds = Dp[E], Ds[E]
            feats = {
                "tier2_14d": Xe,
                "tier2_14d+D_profiles": np.column_stack([Xe, Dp]),
                "tier2_14d+D_stacks": np.column_stack([Xe, Ds]),
                "tier2_14d+host_context": np.column_stack([Xe, Cb]),
                "tier2_14d+host_context_causal": np.column_stack([Xe, Cc]),
                "tier2_14d+dest_block": np.column_stack([Xe, Cb[:, DEST_IDX]]),
                "tier2_14d+relative_block": np.column_stack([Xe, Cb[:, RELATIVE_IDX]]),
                "host_context_only": Cb,
            }
            for name, F in feats.items():
                m = xgb().fit(F[tr], y[tr], sample_weight=w)
                P[name][te] = m.predict_proba(F[te])[:, 1]
            P["D_profiles_alone"][te], P["D_stacks_alone"][te] = Dp[te], Ds[te]
            P["rule_dest_share"][te] = Cb[te, CONTEXT_NAMES.index("dest_share")]
        ok = ~np.isnan(P["tier2_14d"])
        for name, p in P.items():
            r = {"split": sname, "model": name, **metrics(y[ok], p[ok])}
            results.append(r)
            print(f"{sname:8s} {name:32s} auc={r['auc']:.3f} tpr@1%={r['tpr_at_1pct_fpr']:.3f}", flush=True)
        report[f"{sname}_dissonance_classes_fitted"] = {k: float(np.mean(v)) for k, v in n_classes.items() if v}
        for new in ("tier2_14d+host_context", "tier2_14d+host_context_causal"):
            report[f"{sname}: {new} minus tier2_14d (mean, 95% CI over captures)"] = boot_diff(
                y[ok], P[new][ok], P["tier2_14d"][ok], caps[ok])
        preds[sname] = {k: v.tolist() for k, v in P.items()}
    pd.DataFrame(results).to_csv(os.path.join(a.out, "real_pcap_results.csv"), index=False)
    json.dump(report, open(os.path.join(a.out, "real_pcap_report.json"), "w"), indent=2)
    print(json.dumps(report, indent=2))
    print("14-D names:", FEATURE_NAMES)


if __name__ == "__main__":
    main()
