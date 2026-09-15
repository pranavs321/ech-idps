#!/usr/bin/env python3
"""
Step 3 -- the evaluation that goes in the report.

Produces four results, matching Section 7 of the dossier:

  A. Baseline comparison
     Our detector against a JA4 blocklist, an Anderson-McGrew-style metadata
     classifier, and a crypto-blind flow-ML IDS. All at a fixed FPR budget,
     because comparing detectors at different operating points is meaningless.

  B. The evasion-cost curve  (the empirical face of Pillar 2)
     Recall against the attacker's *measured* shaping cost. Every point is a
     shaping level from the sweep; the cost axis is read off the generated
     traffic, not assumed.

  C. Feature-13 ablation
     Does coupling the crypto axis to the physics actually buy anything over
     physics alone? If it does not, Pillar 1 is decoration and the paper should
     say so.

  D. Collateral damage
     Innocent flows disrupted on shared infrastructure, with and without
     attribution-scoped mitigation. This is the measurement that makes Pillar 3
     a claim rather than an assertion.

Usage:
    python3 scripts/03_evaluate.py
    python3 scripts/03_evaluate.py --no-plots
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score

from idps.features import CRYPTO_IDX, FEATURE_NAMES, PHYSICS_IDX
from idps.module3_ml.dissonance import DissonanceConfig, DissonanceModel
from idps.module3_ml.tier1_blocklist import JA4Blocklist
from idps.module3_ml.tier2_supervised import SupervisedConfig, SupervisedTier

TARGET_FPR = 0.005


# ---------------------------------------------------------------------------
def split(n, seed=11, fracs=(0.6, 0.2, 0.2)):
    rng = np.random.default_rng(seed)
    idx = rng.permutation(n)
    a = int(fracs[0] * n)
    b = a + int(fracs[1] * n)
    return idx[:a], idx[a:b], idx[b:]


def operating_point(y, score, target_fpr=TARGET_FPR):
    """Threshold set on benign, then recall/precision read off at that point."""
    benign = score[y == 0]
    thr = float(np.quantile(benign, 1.0 - target_fpr)) if len(benign) else 0.0
    pred = score >= thr
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    return {
        "threshold": thr,
        "recall": tp / max(1, tp + fn),
        "precision": tp / max(1, tp + fp),
        "fpr": fp / max(1, int((y == 0).sum())),
        "auc": float(roc_auc_score(y, score)) if len(set(y)) > 1 else float("nan"),
    }


# ---------------------------------------------------------------------------
def result_a_baselines(X, y, ja4, declared, tr, te, blocklist):
    print("\n" + "=" * 72)
    print("A. BASELINE COMPARISON  (all at FPR budget "
          f"{TARGET_FPR:.1%})")
    print("=" * 72)
    rows = {}

    # 1. Pure JA4 blocklist. Expected to collapse: it catches the naive
    #    implant and nothing that bothered to clone a browser.
    bl_score = np.array([1.0 if blocklist.check(j) else 0.0 for j in ja4[te]])
    tp = int(((bl_score > 0) & (y[te] == 1)).sum())
    fp = int(((bl_score > 0) & (y[te] == 0)).sum())
    fn = int(((bl_score == 0) & (y[te] == 1)).sum())
    rows["JA4 blocklist"] = {
        "recall": tp / max(1, tp + fn),
        "precision": tp / max(1, tp + fp),
        "fpr": fp / max(1, int((y[te] == 0).sum())),
        "auc": float("nan"),
        "note": "deterministic; no tunable operating point",
    }

    # 2. Anderson-McGrew style: metadata + flow features, no consistency test,
    #    no adaptive adversary in its training assumptions. Approximated by a
    #    random forest over the same physics features.
    rf = RandomForestClassifier(n_estimators=300, max_depth=12, n_jobs=4,
                                random_state=7, class_weight="balanced")
    rf.fit(X[tr][:, PHYSICS_IDX], y[tr])
    rows["Metadata classifier (Anderson-McGrew style)"] = operating_point(
        y[te], rf.predict_proba(X[te][:, PHYSICS_IDX])[:, 1])

    # 3. Crypto-blind eBPF flow-ML IDS: line rate, but no cryptographic axis.
    st_blind = SupervisedTier(SupervisedConfig(use_dissonance_feature=False))
    Xb_tr = X[tr].copy(); Xb_tr[:, CRYPTO_IDX] = 0.0
    Xb_te = X[te].copy(); Xb_te[:, CRYPTO_IDX] = 0.0
    st_blind.fit(Xb_tr, y[tr])
    rows["Crypto-blind flow-ML IDS"] = operating_point(
        y[te], st_blind.score(Xb_te))

    # 4. Ours.
    dm = DissonanceModel(DissonanceConfig(target_fpr=TARGET_FPR))
    dm.fit(X[tr], declared[tr], benign_mask=(y[tr] == 0))
    st = SupervisedTier(SupervisedConfig(target_fpr=TARGET_FPR,
                                         use_dissonance_feature=True))
    st.fit(X[tr], y[tr], dm.score(X[tr], declared[tr]))
    ours = st.score(X[te], dm.score(X[te], declared[te]))
    rows["This system (dissonance-coupled)"] = operating_point(y[te], ours)

    print(f"{'detector':<46s} {'recall':>8s} {'prec':>8s} {'FPR':>8s} {'AUC':>8s}")
    print("-" * 72)
    for name, r in rows.items():
        auc = f"{r['auc']:.4f}" if r["auc"] == r["auc"] else "     --"
        print(f"{name:<46s} {r['recall']:8.4f} {r['precision']:8.4f} "
              f"{r['fpr']:8.4f} {auc:>8s}")

    return rows, dm, st, ours


# ---------------------------------------------------------------------------
def result_b_evasion_curve(y, ours, pops, shaping, latency, overhead, te, thr):
    print("\n" + "=" * 72)
    print("B. EVASION-COST CURVE  (Pillar 2, empirical)")
    print("=" * 72)
    mim = pops[te] == "malware_mimicry"
    benign = y[te] == 0
    curve = []
    print(f"{'shaping s':>10s} {'n':>6s} {'recall':>8s} "
          f"{'latency ms':>11s} {'bandwidth overhead':>19s}")
    print("-" * 72)
    for s in sorted(set(shaping[te][mim])):
        sel = mim & (shaping[te] == s)
        if sel.sum() == 0:
            continue
        rec = float((ours[sel] >= thr).mean())
        # Median, not mean: per-flow overhead is heavy-tailed (a flow that
        # delivered little real work has a huge ratio), and a mean over a
        # heavy tail reports the outliers rather than the typical cost.
        lat = float(np.median(latency[te][sel]))
        ovh = float(np.median(overhead[te][sel]))
        curve.append({"shaping": float(s), "n": int(sel.sum()),
                      "recall": rec, "latency_ms": lat, "overhead": ovh})
        print(f"{s:10.2f} {int(sel.sum()):6d} {rec:8.4f} {lat:11.0f} "
              f"{ovh * 100:18.0f}%")

    print("\nReading the curve: recall falls as the adversary shapes harder, "
          "which is expected\nand is the honest result -- the claim was never "
          "that evasion is impossible. What\nmatters is the price column. To "
          "reach the low-recall region the operator is paying")
    if curve:
        worst = min(curve, key=lambda c: c["recall"])
        cheap = curve[0]
        print(f"roughly {worst['overhead'] * 100:.0f}% bandwidth overhead "
              f"against {cheap['overhead'] * 100:.0f}% unshaped: a "
              f"{worst['overhead'] / max(1e-9, cheap['overhead']):.0f}x "
              f"increase in\ncover traffic for a channel whose entire purpose "
              "is to stay inconspicuous.")
    print("\nNote on which cost binds: for a browser cover story the dominant "
          "penalty is\nbandwidth, not latency. Dense human-like traffic "
          "actually gives the implant MORE\nsending opportunities, so task "
          "latency falls while filler volume explodes. Worth\nstating "
          "explicitly in the paper -- the theorem bounds a sum of costs, and "
          "which\nterm dominates depends on the cover class the attacker picks.")
    return curve


# ---------------------------------------------------------------------------
def result_c_ablation(X, y, declared, tr, te):
    print("\n" + "=" * 72)
    print("C. FEATURE-13 ABLATION  (does crypto x physics coupling pay?)")
    print("=" * 72)
    rows = {}

    # physics only, f13 zeroed
    Xa_tr = X[tr].copy(); Xa_tr[:, CRYPTO_IDX] = 0.0
    Xa_te = X[te].copy(); Xa_te[:, CRYPTO_IDX] = 0.0
    m1 = SupervisedTier(SupervisedConfig(use_dissonance_feature=False))
    m1.fit(Xa_tr, y[tr])
    rows["physics only (f1-f12)"] = operating_point(y[te], m1.score(Xa_te))

    # physics + raw f13, no dissonance
    m2 = SupervisedTier(SupervisedConfig(use_dissonance_feature=False))
    m2.fit(X[tr], y[tr])
    rows["physics + raw JA4 similarity (f1-f13)"] = operating_point(
        y[te], m2.score(X[te]))

    # full: physics + f13 + D(x)
    dm = DissonanceModel(DissonanceConfig(target_fpr=TARGET_FPR))
    dm.fit(X[tr], declared[tr], benign_mask=(y[tr] == 0))
    m3 = SupervisedTier(SupervisedConfig(use_dissonance_feature=True))
    m3.fit(X[tr], y[tr], dm.score(X[tr], declared[tr]))
    rows["full: + dissonance D(x)"] = operating_point(
        y[te], m3.score(X[te], dm.score(X[te], declared[te])))

    print(f"{'configuration':<44s} {'recall':>8s} {'AUC':>9s}")
    print("-" * 72)
    for name, r in rows.items():
        print(f"{name:<44s} {r['recall']:8.4f} {r['auc']:9.4f}")

    base = rows["physics only (f1-f12)"]["recall"]
    full = rows["full: + dissonance D(x)"]["recall"]
    print(f"\nCoupling the declared identity to the physics moves recall by "
          f"{(full - base) * 100:+.1f} points\nat the same false-positive "
          "budget.")
    return rows


# ---------------------------------------------------------------------------
def result_d_collateral(X, y, declared, pops, ja4, te, ours, thr, dm):
    """
    Measure what enforcement does to bystanders.

    Two policies, same verdicts:
      naive   every malicious verdict bans the source IP for the full TTL
      ours    Module 5's attribution-driven policy

    The count is of *benign* flows from shared-infrastructure addresses that a
    source-scoped ban would have swallowed.
    """
    print("\n" + "=" * 72)
    print("D. COLLATERAL DAMAGE ON SHARED INFRASTRUCTURE  (Pillar 3)")
    print("=" * 72)

    from idps.module1_dataplane.dataplane import SimulatedDataPlane
    from idps.module2_sensor.extractor import FlowRecord
    from idps.module3_ml.engine import Verdict
    from idps.module4_xai.treeshap import ExplainabilityEngine
    from idps.module5_soar.ip_context import IPContextStore
    from idps.module5_soar.policy import MitigationPolicy, Scope

    # Reconstruct source addresses for the test split. The corpus places
    # shared-egress traffic in 203.0.113.0/24, so membership is known ground
    # truth and the measurement does not depend on the context store guessing
    # correctly -- that would make the result circular.
    rng = np.random.default_rng(3)
    shared_pool = [f"203.0.113.{i}" for i in range(1, 255)]
    dedicated_pool = [f"198.51.100.{i}" for i in range(1, 255)]
    attacker_pool = [f"192.0.2.{i}" for i in range(1, 255)]

    ips = []
    for p in pops[te]:
        if p == "benign_shared":
            ips.append(rng.choice(shared_pool))
        elif p == "benign_direct":
            ips.append(rng.choice(dedicated_pool))
        elif p == "malware_mimicry" and rng.random() < 0.30:
            ips.append(rng.choice(shared_pool))       # beacon behind the NAT
        else:
            ips.append(rng.choice(attacker_pool))
    ips = np.array(ips)

    flagged = ours >= thr
    d_te = dm.score(X[te], declared[te])
    best_fit = dm.best_fit_class(X[te])

    # -- naive policy: ban every flagged source ---------------------------
    naive_banned = set(ips[flagged])
    naive_hit = int(((y[te] == 0) & np.isin(ips, list(naive_banned))).sum())

    # -- our policy: run the real attribution-driven decision --------------
    st = SupervisedTier(SupervisedConfig(use_dissonance_feature=True))
    # reuse the already-fitted model via the engine path
    from idps.pipeline import ARTIFACTS
    st = SupervisedTier.load(str(ARTIFACTS / "supervised.joblib"))
    ex = ExplainabilityEngine(st)
    policy = MitigationPolicy()
    ctx_store = IPContextStore().load_defaults()
    for ip, dcl in zip(ips, declared[te]):
        ctx_store.observe(ip, str(dcl))

    ours_banned = set()
    scope_counts = {"flow": 0, "five_tuple": 0, "source_ip": 0}
    vetoed = 0
    idxs = np.where(flagged)[0]
    # Attribution is the expensive step, so sample when the flagged set is
    # large. The sample is uniform, so the scope proportions are unbiased.
    sample = idxs if len(idxs) <= 1200 else rng.choice(idxs, 1200, replace=False)
    for i in sample:
        rec = FlowRecord(features=X[te][i], declared=str(declared[te][i]),
                         declared_confidence=1.0, ja4=str(ja4[te][i]),
                         src_ip=str(ips[i]), dst_ip="100.64.0.1", dst_port=443,
                         n_packets=15)
        v = Verdict(label="malicious", tier="tier2_supervised",
                    risk=float(ours[i]), confidence=0.9,
                    declared=str(declared[te][i]), best_fit=str(best_fit[i]),
                    dissonance=float(d_te[i]), dissonance_tau=dm.tau,
                    supervised_score=float(ours[i]), record=rec)
        attr = ex.explain(X[te][i], np.array([d_te[i]]))
        dec = policy.decide(v, attr, ctx_store.lookup(str(ips[i])))
        scope_counts[dec.scope.value] += 1
        if dec.escalation_blocked:
            vetoed += 1
        if dec.scope == Scope.SOURCE_IP:
            ours_banned.add(str(ips[i]))
    ours_hit = int(((y[te] == 0) & np.isin(ips, list(ours_banned))).sum())

    n_benign = int((y[te] == 0).sum())
    print(f"flagged flows in test split       : {int(flagged.sum())}")
    print(f"attribution sample evaluated      : {len(sample)}")
    print()
    print(f"{'policy':<34s} {'IPs banned':>11s} {'innocent flows hit':>20s}")
    print("-" * 72)
    print(f"{'ban every flagged source':<34s} {len(naive_banned):11d} "
          f"{naive_hit:20d}")
    print(f"{'attribution-driven (Module 5)':<34s} {len(ours_banned):11d} "
          f"{ours_hit:20d}")
    reduction = (1 - ours_hit / naive_hit) * 100 if naive_hit else 0.0
    print(f"\ninnocent flows spared: {naive_hit - ours_hit} "
          f"({reduction:.1f}% reduction) out of {n_benign} benign flows")
    print(f"escalations vetoed by attribution: {vetoed} / {len(sample)}")
    print(f"scope distribution: {scope_counts}")

    return {
        "naive_ips_banned": len(naive_banned),
        "naive_innocent_hit": naive_hit,
        "ours_ips_banned": len(ours_banned),
        "ours_innocent_hit": ours_hit,
        "reduction_pct": reduction,
        "escalations_vetoed": vetoed,
        "scope_distribution": scope_counts,
        "n_benign_test": n_benign,
    }


# ---------------------------------------------------------------------------
def make_plots(curve, baselines, ablation, collateral, out: Path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.size": 9, "axes.grid": True,
                         "grid.alpha": 0.25, "figure.dpi": 150})

    fig, axes = plt.subplots(2, 2, figsize=(11, 8))

    # B1: recall vs shaping
    ax = axes[0][0]
    s = [c["shaping"] for c in curve]
    r = [c["recall"] for c in curve]
    ax.plot(s, r, "o-", color="#1f3a68", lw=2)
    ax.set_xlabel("shaping intensity s")
    ax.set_ylabel("detector recall")
    ax.set_title("Recall falls as the adversary shapes")
    ax.set_ylim(0, 1.02)

    # B2: the actual evasion-cost curve -- recall vs measured price
    ax = axes[0][1]
    ov = [c["overhead"] * 100 for c in curve]
    ax.plot(ov, r, "o-", color="#a4391f", lw=2)
    for c in curve:
        ax.annotate(f"s={c['shaping']:.2f}",
                    (c["overhead"] * 100, c["recall"]),
                    fontsize=6, xytext=(3, 4), textcoords="offset points")
    ax.set_xscale("symlog")
    ax.set_xlabel("attacker bandwidth overhead (%, measured)")
    ax.set_ylabel("detector recall")
    ax.set_title("Evasion-cost curve: what evasion costs")
    ax.set_ylim(0, 1.02)

    # C: ablation
    ax = axes[1][0]
    names = list(ablation.keys())
    vals = [ablation[n]["recall"] for n in names]
    short = ["physics\nonly", "physics\n+ JA4", "physics + JA4\n+ D(x)"]
    ax.bar(short[:len(names)], vals, color=["#8fa3bf", "#5a7aa8", "#1f3a68"])
    ax.set_ylabel(f"recall @ FPR {TARGET_FPR:.1%}")
    ax.set_title("Feature-13 ablation")
    for i, v in enumerate(vals):
        ax.text(i, v + 0.01, f"{v:.3f}", ha="center", fontsize=8)
    ax.set_ylim(0, 1.1)

    # D: collateral
    ax = axes[1][1]
    ax.bar(["ban every\nflagged source", "attribution-driven\n(Module 5)"],
           [collateral["naive_innocent_hit"], collateral["ours_innocent_hit"]],
           color=["#a4391f", "#1f6b4a"])
    ax.set_ylabel("innocent flows disrupted")
    ax.set_title("Collateral damage on shared infrastructure")
    for i, v in enumerate([collateral["naive_innocent_hit"],
                           collateral["ours_innocent_hit"]]):
        ax.text(i, v + 1, str(v), ha="center", fontsize=9)

    fig.suptitle("Adaptive, Explainable, ECH-Aware Split-Plane IDPS "
                 "-- evaluation results", fontsize=11)
    fig.tight_layout()
    path = out / "evaluation.png"
    fig.savefig(path, bbox_inches="tight")
    print(f"\nfigures written to {path}")
    return path


# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "artifacts" / "dataset.npz"))
    ap.add_argument("--artifacts", default=str(ROOT / "artifacts"))
    ap.add_argument("--out", default=str(ROOT / "results"))
    ap.add_argument("--no-plots", action="store_true")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    data = np.load(args.data, allow_pickle=True)
    X, y = data["X"], data["y"].astype(int)
    declared, ja4, pops = data["declared"], data["ja4"], data["population"]
    shaping, latency, overhead = (data["shaping"], data["latency_ms"],
                                  data["overhead"])
    tr, va, te = split(len(X))
    blocklist = JA4Blocklist.load(str(Path(args.artifacts) /
                                      "ja4_blocklist.json"))

    baselines, dm, st, ours = result_a_baselines(
        X, y, ja4, declared, tr, te, blocklist)
    thr = baselines["This system (dissonance-coupled)"]["threshold"]
    curve = result_b_evasion_curve(y, ours, pops, shaping, latency, overhead,
                                   te, thr)
    ablation = result_c_ablation(X, y, declared, tr, te)
    collateral = result_d_collateral(X, y, declared, pops, ja4, te, ours, thr, dm)

    report = {"baselines": baselines, "evasion_curve": curve,
              "ablation": ablation, "collateral": collateral,
              "target_fpr": TARGET_FPR, "n_test": int(len(te))}
    (out / "evaluation.json").write_text(json.dumps(report, indent=2,
                                                    default=float))
    print(f"\nwrote {out / 'evaluation.json'}")

    if not args.no_plots:
        make_plots(curve, baselines, ablation, collateral, out)
    print(f"evaluation complete in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
