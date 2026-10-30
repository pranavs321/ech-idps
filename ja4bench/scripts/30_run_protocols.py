#!/usr/bin/env python3
"""Run evaluation protocols x (model, feature set) combos on canonical table(s).

  python scripts/30_run_protocols.py --in data/canonical/matousek2024.csv.gz --tcp-only \
      --out results/protocols_matousek --boot 1000

Default combos:
  lookup:ja4            JA4 lookup table (the memorisation baseline every result is compared with)
  xgb:ja4_components    the "JA4 model" of the literature / team baseline
  xgb:ja4_plus_sni      + SNI domain (what ECH removes)
  xgb:env_only          DIAGNOSTIC: environment fields only (Environment Leakage Index under P2)

Outputs in --out:
  summary.csv           pooled out-of-fold metrics per protocol x combo, with capture-bootstrap CIs
  folds.csv             per-fold metrics, seen-JA4 rate, train/test sizes
  skipped_folds.csv     every fold that was skipped and why
  captures.csv          per-capture scores (pooled OOF) per protocol x combo
  oof.csv.gz            all out-of-fold predictions
  SUMMARY.md            the table to paste into the paper/report, with run metadata and input hashes
"""
import argparse
import hashlib
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ja4bench  # noqa: E402
from ja4bench.features import FeatureBuilder  # noqa: E402
from ja4bench.metrics import flow_metrics  # noqa: E402
from ja4bench.report import summarize  # noqa: E402
from ja4bench.models import LookupBaseline, make_model  # noqa: E402
from ja4bench.protocols import PROTOCOLS, Fold, generate  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--in", dest="inp", nargs="+", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--protocols", default=",".join(PROTOCOLS))
ap.add_argument("--combos", default="lookup:ja4,xgb:ja4_components,xgb:ja4_plus_sni,xgb:env_only")
ap.add_argument("--domain-col", default="platform")
ap.add_argument("--k", type=int, default=5)
ap.add_argument("--seed", type=int, default=42)
ap.add_argument("--boot", type=int, default=1000)
ap.add_argument("--tcp-only", action="store_true")
ap.add_argument("--exclude-flag", action="append", default=[],
                help="drop rows where this 0/1 column is 1 (e.g. flag_os_background). Repeatable.")
ap.add_argument("--only-env", action="append", default=[], help="keep only these env_groups")
a = ap.parse_args()

t0 = time.time()
hashes = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in a.inp}
df = pd.concat([pd.read_csv(p, low_memory=False) for p in a.inp], ignore_index=True)
n0 = len(df)
filters = []
df = df[df["label"].isin([0, 1])]
filters.append(f"label in {{0,1}}: {n0} -> {len(df)}")
if a.tcp_only:
    m = len(df); df = df[df["proto"] == "tcp"]; filters.append(f"tcp-only: {m} -> {len(df)}")
for f in a.exclude_flag:
    m = len(df); df = df[df[f].fillna(0).astype(int) == 0]; filters.append(f"exclude {f}: {m} -> {len(df)}")
if a.only_env:
    m = len(df); df = df[df["env_group"].isin(a.only_env)]; filters.append(f"only env {a.only_env}: {m} -> {len(df)}")
df = df.reset_index(drop=True)
y_all = df["label"].to_numpy().astype(int)
combos = [tuple(c.split(":")) for c in a.combos.split(",")]
out = Path(a.out)
out.mkdir(parents=True, exist_ok=True)

fold_rows, skip_rows, oof_parts = [], [], []
for proto in a.protocols.split(","):
    for f in generate(df, proto, k=a.k, seed=a.seed, domain_col=a.domain_col):
        if not isinstance(f, Fold):
            skip_rows.append({"protocol": f.protocol, "fold": f.name, "reason": f.reason})
            print(f"[skip] {proto} {f.name}: {f.reason}", flush=True)
            continue
        tr, te = df.iloc[f.train], df.iloc[f.test]
        ytr, yte = y_all[f.train], y_all[f.test]
        seen_rate = float(te["ja4"].isin(set(tr["ja4"])).mean())
        for model, fs in combos:
            t1 = time.time()
            if model == "lookup":
                lk = LookupBaseline().fit(tr["ja4"], ytr)
                p, seen = lk.predict_proba(te["ja4"])
                notes = ""
            else:
                fb = FeatureBuilder(fs).fit(tr)
                Xtr, Xte = fb.transform(tr), fb.transform(te)
                base = model
                if model.endswith("LEAK"):
                    # DELIBERATE LEAK (pre-registered test, PREREG section 6): JA4 target mean computed
                    # on ALL rows, test rows included. A sound protocol must show this inflation.
                    base = model[:-4]
                    te_all = df.groupby("ja4")["label"].mean()
                    Xtr = Xtr.assign(LEAK_ja4_target_mean=tr["ja4"].map(te_all).to_numpy())
                    Xte = Xte.assign(LEAK_ja4_target_mean=te["ja4"].map(te_all).to_numpy())
                clf = make_model(base, ytr, a.seed).fit(Xtr, ytr)
                p = clf.predict_proba(Xte)[:, 1]
                seen = te["ja4"].isin(set(tr["ja4"])).to_numpy()
                notes = "; ".join(fb.notes)
            combo = f"{model}:{fs}"
            met = flow_metrics(yte, p)
            fold_rows.append({"protocol": proto, "fold": f.name, "combo": combo,
                              "n_train": len(tr), "n_test": len(te),
                              "train_prev": float(ytr.mean()), "seen_ja4_rate": seen_rate,
                              "secs": round(time.time() - t1, 1), "notes": notes, **met})
            oof_parts.append(pd.DataFrame({"protocol": proto, "fold": f.name, "combo": combo,
                                           "row_id": te["row_id"].values,
                                           "capture_id": te["capture_id"].values,
                                           "env_group": te["env_group"].values,
                                           "label": yte, "score": p, "ja4_seen": seen}))
            print(f"{proto:15s} {f.name:28s} {combo:22s} roc={met['roc_auc']:.3f} "
                  f"f1={met['f1']:.3f} fpr={met['fpr']:.3f} seen={seen_rate:.2f} "
                  f"({time.time()-t1:.0f}s)", flush=True)

folds = pd.DataFrame(fold_rows)
skips = pd.DataFrame(skip_rows, columns=["protocol", "fold", "reason"])
oof = pd.concat(oof_parts, ignore_index=True) if oof_parts else pd.DataFrame()
folds.to_csv(out / "folds.csv", index=False)
skips.to_csv(out / "skipped_folds.csv", index=False)
oof.to_csv(out / "oof.csv.gz", index=False)

meta = {"utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ja4bench": ja4bench.__version__, "python": platform.python_version(),
        "pandas": pd.__version__, "numpy": np.__version__, "args": vars(a),
        "input_sha256": hashes, "filters": filters, "rows_used": int(len(df)),
        "captures_used": int(df["capture_id"].nunique()), "train_runtime_s": round(time.time() - t0)}
try:
    import sklearn, xgboost  # noqa: E401
    meta["sklearn"], meta["xgboost"] = sklearn.__version__, xgboost.__version__
except Exception:  # noqa: BLE001
    pass
(out / "train_meta.json").write_text(json.dumps(meta, indent=2, default=str))
summarize(oof, skips, meta, out, n_boot=a.boot, seed=a.seed)
print((out / "SUMMARY.md").read_text())
