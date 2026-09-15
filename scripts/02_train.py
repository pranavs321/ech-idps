#!/usr/bin/env python3
"""
Step 2 -- train the detection stack.

Fits, in order:
    1. the class-conditional dissonance model  (benign traffic only)
    2. the Tier 2 supervised detector          (labelled, with D(x) available)
    3. the Tier 3 novelty detector             (benign traffic only)
    4. the Tier 1 JA4 blocklist                (harvested from naive malware)

On the split
------------
Train/validation/test is a three-way split, and the threshold is calibrated on
validation rather than on train. Calibrating a threshold on the same data the
model was fitted to gives an optimistically low false-positive rate, because
the model has already memorised part of the benign distribution. That mistake
turns a reported 0.5% FPR into several percent in deployment, and it is the
single most common reason IDS papers do not reproduce.

Usage:
    python3 scripts/02_train.py
    python3 scripts/02_train.py --no-dissonance-feature   # 14-D ablation
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from idps.module3_ml.dissonance import DissonanceConfig, DissonanceModel
from idps.module3_ml.tier1_blocklist import JA4Blocklist
from idps.module3_ml.tier2_supervised import SupervisedConfig, SupervisedTier
from idps.module3_ml.tier3_anomaly import AnomalyConfig, AnomalyTier


def split(n: int, seed: int = 11, fracs=(0.6, 0.2, 0.2)):
    rng = np.random.default_rng(seed)
    idx = rng.permutation(n)
    a = int(fracs[0] * n)
    b = a + int(fracs[1] * n)
    return idx[:a], idx[a:b], idx[b:]


def recall_at_fpr(y, score, target_fpr=0.005):
    """Recall achievable while holding the false-positive rate at target."""
    benign = score[y == 0]
    if len(benign) == 0:
        return 0.0, 0.0
    thr = float(np.quantile(benign, 1.0 - target_fpr))
    rec = float((score[y == 1] >= thr).mean())
    fpr = float((benign >= thr).mean())
    return rec, fpr


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "artifacts" / "dataset.npz"))
    ap.add_argument("--out", default=str(ROOT / "artifacts"))
    ap.add_argument("--target-fpr", type=float, default=0.005)
    ap.add_argument("--no-dissonance-feature", action="store_true",
                    help="train Tier 2 on the bare 14-D vector (ablation)")
    ap.add_argument("--seed", type=int, default=11)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    data = np.load(args.data, allow_pickle=True)
    X, y = data["X"], data["y"].astype(int)
    declared, ja4, pops = data["declared"], data["ja4"], data["population"]
    print(f"loaded {len(X)} records from {args.data}")

    tr, va, te = split(len(X), seed=args.seed)
    print(f"split  train={len(tr)}  val={len(va)}  test={len(te)}")

    # -- 1. dissonance ----------------------------------------------------
    t0 = time.time()
    print("\n[1/4] fitting class-conditional densities for D(x)")
    dm = DissonanceModel(DissonanceConfig(target_fpr=args.target_fpr))
    dm.fit(X[tr], declared[tr], benign_mask=(y[tr] == 0))
    print(f"      classes modelled : {dm.classes}")
    print(f"      tau @ FPR {args.target_fpr:.3%} : {dm.tau:.3f} nats")
    d_tr = dm.score(X[tr], declared[tr])
    d_va = dm.score(X[va], declared[va])
    d_te = dm.score(X[te], declared[te])
    r, f = recall_at_fpr(y[te], d_te, args.target_fpr)
    print(f"      D(x) alone on test: recall={r:.3f} at FPR={f:.4f}, "
          f"AUC={roc_auc_score(y[te], d_te):.4f}")
    dm.save(str(out / "dissonance.joblib"))

    # -- 2. supervised ----------------------------------------------------
    print("\n[2/4] training Tier 2 (XGBoost)")
    cfg = SupervisedConfig(
        target_fpr=args.target_fpr,
        use_dissonance_feature=not args.no_dissonance_feature)
    st = SupervisedTier(cfg)
    st.fit(X[tr], y[tr], d_tr, X_val=X[va], y_val=y[va], dissonance_val=d_va)
    s_te = st.score(X[te], d_te)
    r2, f2 = recall_at_fpr(y[te], s_te, args.target_fpr)
    print(f"      inputs           : {len(st.feature_names)} "
          f"({'with' if cfg.use_dissonance_feature else 'without'} D(x))")
    print(f"      threshold        : {st.threshold:.4f}")
    print(f"      test AUC         : {roc_auc_score(y[te], s_te):.4f}")
    print(f"      test AP          : {average_precision_score(y[te], s_te):.4f}")
    print(f"      recall @ FPR {args.target_fpr:.3%}: {r2:.4f} "
          f"(measured FPR {f2:.4f})")
    st.save(str(out / "supervised.joblib"))

    # -- 3. novelty -------------------------------------------------------
    print("\n[3/4] fitting Tier 3 (Isolation Forest) on clean traffic")
    clean = X[tr][y[tr] == 0]
    at = AnomalyTier(AnomalyConfig())
    at.fit(clean)
    a_te = at.score(X[te])
    print(f"      trained on {len(clean)} benign flows")
    print(f"      test AUC (standalone): {roc_auc_score(y[te], a_te):.4f}")
    at.save(str(out / "anomaly.joblib"))

    # -- 4. blocklist -----------------------------------------------------
    print("\n[4/4] harvesting Tier 1 JA4 blocklist")
    bl = JA4Blocklist()
    naive = (pops[tr] == "malware_naive")
    seen = {}
    for j in ja4[tr][naive]:
        if j:
            seen[j] = seen.get(j, 0) + 1
    # Only list a fingerprint if it never appears in benign traffic. A JA4 that
    # both malware and real users emit is a false-positive generator, and the
    # whole point of Tier 1 is that it should never need a second opinion.
    benign_ja4 = set(ja4[tr][y[tr] == 0])
    added = 0
    for j, n in sorted(seen.items(), key=lambda kv: -kv[1]):
        if j in benign_ja4:
            print(f"      skipping {j}: also seen in benign traffic")
            continue
        bl.add(j, label="c2_naive_implant", source="corpus_harvest")
        added += 1
    print(f"      {added} fingerprints listed (from {len(seen)} candidates)")
    bl.save(str(out / "ja4_blocklist.json"))

    summary = {
        "n_records": int(len(X)),
        "split": {"train": len(tr), "val": len(va), "test": len(te)},
        "target_fpr": args.target_fpr,
        "dissonance": {"tau": dm.tau, "classes": dm.classes,
                       "test_auc": float(roc_auc_score(y[te], d_te)),
                       "test_recall_at_fpr": r},
        "supervised": {"threshold": st.threshold,
                       "uses_dissonance_feature": cfg.use_dissonance_feature,
                       "test_auc": float(roc_auc_score(y[te], s_te)),
                       "test_recall_at_fpr": r2, "measured_fpr": f2},
        "anomaly": {"test_auc": float(roc_auc_score(y[te], a_te))},
        "blocklist_size": len(bl),
        "train_seconds": round(time.time() - t0, 1),
    }
    (out / "training_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nartifacts written to {out}")
    print(f"total {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
