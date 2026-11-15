"""Single-feature ROC-AUC per lab (strict MCFP labels) to see whether features point the same way in both labs.
Writes results/second_lab/feature_direction.csv. Usage: PYTHONPATH=src python -m ja4next.feature_direction"""
from __future__ import annotations
import os, sys
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ja4next import features as F, second_lab as S
from ja4next.evaluate import cap_per_capture


def main():
    both = S.load(); fams = F.build(both)
    both.loc[~cap_per_capture(both, 100), "y"] = np.nan
    ok = both.y.notna().values
    rows = []
    for lab in ("MTA", "MCFP"):
        m = ok & (both.lab == lab).values; y = both.y.values[m].astype(int)
        for fam in ("HRd", "HRb", "POS", "BEH", "TLS"):
            X = fams[fam][m]
            for c in X.columns:
                if X[c].std() == 0: continue
                rows.append(dict(lab=lab, family=fam, feature=c, auc=float(roc_auc_score(y, X[c].values))))
    d = pd.DataFrame(rows).pivot_table(index=["family", "feature"], columns="lab", values="auc").reset_index().dropna()
    d["same_direction"] = np.sign(d.MTA - 0.5) == np.sign(d.MCFP - 0.5)
    d["strength"] = np.minimum(abs(d.MTA - 0.5), abs(d.MCFP - 0.5))
    d = d.sort_values("strength", ascending=False)
    os.makedirs("results/second_lab", exist_ok=True); d.to_csv("results/second_lab/feature_direction.csv", index=False)
    print("features compared:", len(d), "same direction:", int(d.same_direction.sum()))
    print("among features with |AUC-0.5|>=0.1 in both labs:", int((d.strength >= 0.1).sum()), "same direction:", int(d[d.strength >= 0.1].same_direction.sum()))
    print(d.head(10).round(3).to_string(index=False))


if __name__ == "__main__":
    main()
