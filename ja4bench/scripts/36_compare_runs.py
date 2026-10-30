#!/usr/bin/env python3
"""Compare a rerun with the reference: PASS if every metric matches within --tol.

  python scripts/36_compare_runs.py results/protocols_main results_reference/protocols_main
Different CPUs (Mac ARM vs Linux x86) can change the last decimals of tree models; differences
above the tolerance are real and must be reported, not fixed.
"""
import sys

import pandas as pd

a, b = sys.argv[1], sys.argv[2]
tol = float(sys.argv[3]) if len(sys.argv) > 3 else 0.005
A = pd.read_csv(f"{a}/summary.csv").set_index(["protocol", "combo"])
B = pd.read_csv(f"{b}/summary.csv").set_index(["protocol", "combo"])
cols = ["roc_auc", "pr_auc", "f1", "recall", "fpr", "n", "n_captures"]
if set(A.index) != set(B.index):
    print("DIFFERENT protocol/combo sets:", set(A.index) ^ set(B.index)); sys.exit(1)
d = (A[cols] - B.loc[A.index, cols]).abs()
bad = d[(d > tol).any(axis=1)]
print(d.max().round(4).to_string())
if len(bad):
    print("\nFAIL: rows above tolerance\n", bad.round(4).to_string()); sys.exit(1)
print(f"\nPASS: all {len(d)} rows within {tol}")
