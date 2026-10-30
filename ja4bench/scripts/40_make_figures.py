#!/usr/bin/env python3
"""Figures for the report. Reads ONLY summary.csv / folds.csv of a run, so every bar is traceable.

  python scripts/40_make_figures.py --run results_reference/protocols_main --out results_reference/figures

fig1_protocols.png   pooled ROC-AUC with capture-bootstrap 95% CI for partition protocols
                     (P1, P2, P4, P8); P3 shown as per-fold mean (pooled is invalid for the lookup there)
fig2_alerts.png      host-level false alarms: share of benign captures with >= 1 alert, per protocol
fig3_domain.png      P6 per fold: train on one platform, test on the other
"""
import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--run", required=True)
ap.add_argument("--out", required=True)
a = ap.parse_args()
run, out = Path(a.run), Path(a.out)
out.mkdir(parents=True, exist_ok=True)
s = pd.read_csv(run / "summary.csv")
f = pd.read_csv(run / "folds.csv")
COMBOS = [c for c in ["lookup:ja4", "xgb:ja4_components", "xgb:ja4_plus_sni", "xgb:env_only"]
          if c in set(s.combo)]
LABEL = {"lookup:ja4": "JA4 lookup table", "xgb:ja4_components": "XGBoost, JA4 components",
         "xgb:ja4_plus_sni": "XGBoost, JA4 + SNI", "xgb:env_only": "environment only (no TLS)"}
PROT = [p for p in ["P1_random", "P2_capture", "P3_ja4", "P4_family", "P8_env_matched"] if p in set(s.protocol)]

# fig1
fig, ax = plt.subplots(figsize=(10, 4.2))
w = 0.8 / len(COMBOS)
for i, c in enumerate(COMBOS):
    xs, ys, lo, hi = [], [], [], []
    for j, p in enumerate(PROT):
        r = s[(s.protocol == p) & (s.combo == c)]
        if r.empty:
            continue
        r = r.iloc[0]
        if p == "P3_ja4" and "roc_auc_fold_mean" in r:
            v, l, h = r.roc_auc_fold_mean, r.roc_auc_fold_mean, r.roc_auc_fold_mean
        else:
            v, l, h = r.roc_auc, r.get("roc_auc_lo", r.roc_auc), r.get("roc_auc_hi", r.roc_auc)
        xs.append(j + (i - (len(COMBOS) - 1) / 2) * w); ys.append(v); lo.append(v - l); hi.append(h - v)
    ax.bar(xs, ys, w, yerr=[lo, hi], capsize=2, label=LABEL[c])
ax.axhline(0.5, color="grey", lw=0.8, ls="--")
ax.set_xticks(range(len(PROT)))
ax.set_xticklabels([p.replace("_", "\n") + ("\n(fold mean)" if p == "P3_ja4" else "") for p in PROT])
ax.set_ylabel("ROC-AUC"); ax.set_ylim(0, 1.02)
ax.set_title("Same detector, different evaluation protocol (public Matoušek corpus, TCP only)")
ax.legend(fontsize=8, ncol=2, loc="lower left")
fig.tight_layout(); fig.savefig(out / "fig1_protocols.png", dpi=200); plt.close(fig)

# fig2
fig, ax = plt.subplots(figsize=(8, 3.6))
for i, c in enumerate(COMBOS):
    vals = [s[(s.protocol == p) & (s.combo == c)].cap_alert_rate_benign.iloc[0]
            if not s[(s.protocol == p) & (s.combo == c)].empty else np.nan for p in PROT]
    ax.bar(np.arange(len(PROT)) + (i - (len(COMBOS) - 1) / 2) * w, vals, w, label=LABEL[c])
ax.set_xticks(range(len(PROT))); ax.set_xticklabels([p.replace("_", "\n") for p in PROT])
ax.set_ylabel("benign captures with ≥1 alert"); ax.set_ylim(0, 1.02)
ax.set_title("Host-level false alarms at threshold 0.5")
ax.legend(fontsize=8, ncol=2)
fig.tight_layout(); fig.savefig(out / "fig2_alerts.png", dpi=200); plt.close(fig)

# fig3
d = f[f.protocol == "P6_domain"]
if len(d):
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.4), sharey=True)
    for ax, metric, title in [(axes[0], "roc_auc", "ROC-AUC"), (axes[1], "fpr", "false-positive rate at 0.5")]:
        folds = sorted(d.fold.unique())
        for i, c in enumerate(COMBOS):
            vals = [d[(d.fold == fo) & (d.combo == c)][metric].mean() for fo in folds]
            ax.bar(np.arange(len(folds)) + (i - (len(COMBOS) - 1) / 2) * w, vals, w, label=LABEL[c])
        ax.set_xticks(range(len(folds)))
        ax.set_xticklabels([fo.replace("test=", "train other, test ") for fo in folds], fontsize=8)
        ax.set_title(title); ax.set_ylim(0, 1.02)
        if metric == "roc_auc":
            ax.axhline(0.5, color="grey", lw=0.8, ls="--")
    axes[0].legend(fontsize=7)
    fig.suptitle("P6: train on one platform, test on the other")
    fig.tight_layout(); fig.savefig(out / "fig3_domain.png", dpi=200); plt.close(fig)
print("wrote", sorted(p.name for p in out.glob("*.png")))
