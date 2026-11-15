"""Dry run of the confirmatory analysis WITHOUT the holdout: train 2013-2020, 'holdout' = 2021.
Proves the code path works end to end. Its numbers are NOT confirmatory results."""
import os
import sys
import warnings

import pandas as pd

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ja4next.confirm import run_confirm  # noqa: E402

d = pd.read_parquet("data/processed/connections.parquet")
tr, te = d[d.year <= 2020].copy(), d[d.year == 2021].copy()
te["year"] = 2022  # pretend
res = run_confirm(tr, te, "results/dryrun_confirm_NOT_CONFIRMATORY")
print({k: v.get("supported") for k, v in res.items()})
