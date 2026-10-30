#!/usr/bin/env python3
"""Re-summarise a finished run from its saved out-of-fold predictions (no retraining).

  python scripts/35_summarize.py --run results_reference/protocols_main --boot 1000
"""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ja4bench.report import summarize  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--run", required=True)
ap.add_argument("--boot", type=int, default=1000)
ap.add_argument("--seed", type=int, default=42)
a = ap.parse_args()
run = Path(a.run)
oof = pd.read_csv(run / "oof.csv.gz", low_memory=False)
skips = pd.read_csv(run / "skipped_folds.csv")
mp = run / "train_meta.json"
meta = json.loads(mp.read_text()) if mp.exists() else {"note": "train_meta.json absent; summarised from oof.csv.gz"}
meta["summarised_from"] = "oof.csv.gz"
summarize(oof, skips, meta, run, n_boot=a.boot, seed=a.seed)
print((run / "SUMMARY.md").read_text())
