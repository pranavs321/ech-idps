"""Summarise out-of-fold predictions: pooled metrics, capture tables, capture-bootstrap CIs, SUMMARY.md.

Separated from training so results can be re-summarised from oof.csv.gz without retraining
(scripts/35_summarize.py). The bootstrap uses exact numpy re-implementations of ROC-AUC and
average precision (identical to scikit-learn's; checked in tests) because they are ~10x faster.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import rankdata

from .metrics import capture_metrics, capture_table, flow_metrics


def fast_roc_auc(y: np.ndarray, p: np.ndarray) -> float:
    n1 = int(y.sum()); n0 = len(y) - n1
    if n1 == 0 or n0 == 0:
        return float("nan")
    r = rankdata(p)
    return float((r[y == 1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


def fast_ap(y: np.ndarray, p: np.ndarray) -> float:
    if y.sum() == 0:
        return float("nan")
    o = np.argsort(-p, kind="mergesort")
    ys, ps = y[o], p[o]
    tp = np.cumsum(ys); fp = np.cumsum(1 - ys)
    idx = np.r_[np.flatnonzero(np.diff(ps)), len(ys) - 1]
    tps, fps = tp[idx], fp[idx]
    prec = tps / (tps + fps); rec = tps / tps[-1]
    return float(np.sum(np.diff(np.r_[0.0, rec]) * prec))


def fast_f1(y: np.ndarray, p: np.ndarray, thr: float = 0.5) -> float:
    yh = p >= thr
    tp = np.sum(yh & (y == 1)); fp = np.sum(yh & (y == 0)); fn = np.sum(~yh & (y == 1))
    d = 2 * tp + fp + fn
    return float(2 * tp / d) if d else 0.0


def bootstrap(y, p, groups, n_boot=1000, seed=42, thr=0.5) -> dict:
    if n_boot <= 0:
        return {}
    rng = np.random.default_rng(seed)
    codes, uniq = pd.factorize(groups)
    order = np.argsort(codes, kind="mergesort")
    starts = np.r_[0, np.cumsum(np.bincount(codes, minlength=len(uniq)))]
    rows = [order[starts[i]:starts[i + 1]] for i in range(len(uniq))]
    s = {"roc_auc": [], "pr_auc": [], "f1": []}
    for _ in range(n_boot):
        ix = np.concatenate([rows[i] for i in rng.integers(0, len(uniq), len(uniq))])
        yy, pp = y[ix], p[ix]
        if yy.min() == yy.max():
            continue
        s["roc_auc"].append(fast_roc_auc(yy, pp)); s["pr_auc"].append(fast_ap(yy, pp))
        s["f1"].append(fast_f1(yy, pp, thr))
    out = {"boot_ok": len(s["f1"])}
    for k, v in s.items():
        if v:
            out[f"{k}_lo"], out[f"{k}_hi"] = float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))
    return out


def _fold_auc(g: pd.DataFrame) -> dict:
    """Per-fold ROC-AUC. Pooled AUC mixes folds whose score scales differ (e.g. a lookup table that
    outputs each fold's training prior for every unseen JA4), so the fold mean/min are reported too."""
    v = [fast_roc_auc(h["label"].to_numpy().astype(int), h["score"].to_numpy().astype(float))
         for _, h in g.groupby("fold")]
    v = [x for x in v if x == x]
    return {"roc_auc_fold_mean": float(np.mean(v)) if v else float("nan"),
            "roc_auc_fold_min": float(np.min(v)) if v else float("nan")}


def _fmt(r, k):
    v = r.get(k, np.nan); lo, hi = r.get(f"{k}_lo", np.nan), r.get(f"{k}_hi", np.nan)
    if pd.isna(v):
        return "n/a"
    return f"{v:.3f}" + (f" [{lo:.3f}, {hi:.3f}]" if not pd.isna(lo) else "")


def summarize(oof: pd.DataFrame, skips: pd.DataFrame, meta: dict, out: Path,
              n_boot: int = 1000, seed: int = 42) -> pd.DataFrame:
    out = Path(out)
    summ, caps = [], []
    for (proto, combo), g in oof.groupby(["protocol", "combo"], sort=False):
        y = g["label"].to_numpy().astype(int); p = g["score"].to_numpy().astype(float)
        ct = capture_table(g)
        ct.insert(0, "combo", combo); ct.insert(0, "protocol", proto)
        caps.append(ct)
        summ.append({"protocol": proto, "combo": combo, "n_folds": g["fold"].nunique(),
                     **flow_metrics(y, p), **capture_metrics(ct),
                     "seen_ja4_rate": float(g["ja4_seen"].mean()),
                     **_fold_auc(g),
                     **bootstrap(y, p, g["capture_id"].to_numpy(), n_boot, seed)})
        print(f"summarised {proto} {combo}", flush=True)
    summary = pd.DataFrame(summ)
    summary.to_csv(out / "summary.csv", index=False)
    pd.concat(caps, ignore_index=True).to_csv(out / "captures.csv", index=False)
    (out / "run_meta.json").write_text(json.dumps(meta, indent=2, default=str))
    md = ["# Protocol results (generated; do not edit by hand)", "",
          "```json", json.dumps(meta, indent=2, default=str), "```", "",
          "Flow-level metrics pooled over out-of-fold predictions; [95% CI] = bootstrap over captures.",
          "cap_alert_benign = share of BENIGN captures with >=1 flow scored >= 0.5 (host-level false alarms).",
          "seen_ja4 = share of test rows whose exact JA4 occurred in training.",
          "fold ROC-AUC = mean (min) of per-fold ROC-AUC. When it differs from the pooled value, trust the",
          "per-fold value: pooling mixes folds with different score scales. For P5/P6/P7 read folds.csv.", "",
          "| protocol | combo | ROC-AUC pooled | fold ROC-AUC | PR-AUC | F1 | recall | FPR | cap ROC-AUC | cap_alert_benign | seen_ja4 | n_test | captures |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for _, r in summary.iterrows():
        md.append(f"| {r.protocol} | {r.combo} | {_fmt(r,'roc_auc')} | {r.roc_auc_fold_mean:.3f} ({r.roc_auc_fold_min:.3f}) | {_fmt(r,'pr_auc')} | {_fmt(r,'f1')} | "
                  f"{r.recall:.3f} | {r.fpr:.3f} | {r.cap_roc_auc:.3f} | {r.cap_alert_rate_benign:.3f} | "
                  f"{r.seen_ja4_rate:.2f} | {r.n} | {r.n_captures} |")
    md += ["", "## Skipped folds", ""]
    if len(skips):
        md += ["| protocol | fold | reason |", "|---|---|---|"]
        md += [f"| {s.protocol} | {s.fold} | {s.reason} |" for s in skips.itertuples()]
    else:
        md.append("none")
    (out / "SUMMARY.md").write_text("\n".join(md) + "\n")
    return summary
