"""Metrics at flow level and capture (entity) level, with capture-level bootstrap CIs.

Flow level      ROC-AUC, PR-AUC, F1 / precision / recall / FPR / balanced accuracy / MCC at 0.5
Capture level   capture score = mean flow score; capture ROC-AUC;
                host alert rate = share of captures with >=1 flow scored >= 0.5
                (on benign captures this is the host-level false-alarm rate, the number a SOC feels)
Bootstrap       resample CAPTURES with replacement (never flows), recompute, take 2.5/97.5 percentiles
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, balanced_accuracy_score, f1_score,
                             matthews_corrcoef, precision_score, recall_score, roc_auc_score)


def _safe(fn, *a, **k):
    try:
        return float(fn(*a, **k))
    except ValueError:
        return float("nan")


def flow_metrics(y: np.ndarray, p: np.ndarray, thr: float = 0.5) -> dict:
    yhat = (p >= thr).astype(int)
    neg = y == 0
    return {
        "roc_auc": _safe(roc_auc_score, y, p),
        "pr_auc": _safe(average_precision_score, y, p),
        "f1": _safe(f1_score, y, yhat, zero_division=0),
        "precision": _safe(precision_score, y, yhat, zero_division=0),
        "recall": _safe(recall_score, y, yhat, zero_division=0),
        "fpr": float(yhat[neg].mean()) if neg.any() else float("nan"),
        "bal_acc": _safe(balanced_accuracy_score, y, yhat),
        "mcc": _safe(matthews_corrcoef, y, yhat),
        "prevalence": float(y.mean()),
        "n": int(len(y)),
    }


def capture_table(df: pd.DataFrame, thr: float = 0.5) -> pd.DataFrame:
    """df needs columns capture_id, label, score. One row per capture."""
    g = df.groupby("capture_id")
    out = pd.DataFrame({
        "n_flows": g.size(),
        "label": g["label"].max(),                 # 1 if any malicious flow in the capture
        "mixed": g["label"].nunique() > 1,
        "mean_score": g["score"].mean(),
        "frac_flagged": g["score"].apply(lambda s: float((s >= thr).mean())),
        "any_flagged": g["score"].apply(lambda s: bool((s >= thr).any())),
    })
    return out.reset_index()


def capture_metrics(ct: pd.DataFrame) -> dict:
    ben, mal = ct[ct.label == 0], ct[ct.label == 1]
    return {
        "cap_roc_auc": _safe(roc_auc_score, ct["label"], ct["mean_score"]),
        "cap_alert_rate_benign": float(ben["any_flagged"].mean()) if len(ben) else float("nan"),
        "cap_alert_rate_malicious": float(mal["any_flagged"].mean()) if len(mal) else float("nan"),
        "n_captures": int(len(ct)),
        "n_mixed_captures": int(ct["mixed"].sum()),
    }


def bootstrap_ci(y: np.ndarray, p: np.ndarray, groups: np.ndarray, n_boot: int = 1000,
                 seed: int = 42, thr: float = 0.5) -> dict:
    """Percentile CIs for roc_auc, pr_auc and f1, resampling whole captures."""
    if n_boot <= 0:
        return {}
    rng = np.random.default_rng(seed)
    codes, uniq = pd.factorize(groups)
    rows_by_g = [np.flatnonzero(codes == i) for i in range(len(uniq))]
    stats = {"roc_auc": [], "pr_auc": [], "f1": []}
    for _ in range(n_boot):
        pick = rng.integers(0, len(uniq), len(uniq))
        ix = np.concatenate([rows_by_g[i] for i in pick])
        yy, pp = y[ix], p[ix]
        if len(set(yy)) < 2:
            continue
        stats["roc_auc"].append(roc_auc_score(yy, pp))
        stats["pr_auc"].append(average_precision_score(yy, pp))
        stats["f1"].append(f1_score(yy, (pp >= thr).astype(int), zero_division=0))
    out = {"boot_ok": len(stats["f1"])}
    for k, v in stats.items():
        if v:
            out[f"{k}_lo"], out[f"{k}_hi"] = (float(np.percentile(v, 2.5)),
                                              float(np.percentile(v, 97.5)))
    return out
