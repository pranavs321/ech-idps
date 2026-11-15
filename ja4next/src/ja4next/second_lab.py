"""Second independent lab: train on one lab, test on the other (exploratory, not pre-registered).
Lab A = MTA 2013-2021 (analyst captures; connections.parquet). Lab B = Stratosphere MCFP (own VMs, 2013-2020).
Hostname-only, cap 100 labelled connections per capture-class, capture-weighted training,
bootstrap over test captures. Usage: python -I -m ja4next.second_lab"""
from __future__ import annotations
import json, os, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ja4next import features as F
from ja4next.evaluate import SETS, bootstrap_diff, cap_per_capture, capture_weights, fit_predict, metrics

WEAK = os.environ.get("MCFP_LABELS", "strict") == "weak"
OUT = "results/second_lab_weak" if WEAK else "results/second_lab"
USE = ["ENV", "TLS+BEH", "HRb+TLS+BEH", "HR+TLS+BEH", "HRd", "TLS", "BEH", "HR+TLS+BEH+SRV"]


def load():
    a = pd.read_parquet("data/processed/connections.parquet")
    a = a[a["year"] <= 2021].copy(); a["lab"] = "MTA"
    b = pd.read_parquet("data/interim/mcfp_labelled.parquet")
    b = b[b["client_ip"].astype(str).str.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")]
    b = b[~b["server_ip"].astype(str).str.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")].copy()
    if WEAK: b["y"] = b["y_weak"]
    b["lab"] = "MCFP"; b["source"] = "mcfp"; b["year"] = pd.to_datetime(b["t_clienthello"], unit="s").dt.year
    both = pd.concat([a, b], ignore_index=True)
    both = both[both["sni"].fillna("") != ""].reset_index(drop=True)
    return both


def main():
    both = load()
    fams = F.build(both)   # host-relative features are per host; no train/test mixing
    both.loc[~cap_per_capture(both, 100), "y"] = np.nan
    lab = both["y"].notna().values
    y = both["y"].values
    os.makedirs(OUT, exist_ok=True)
    rows, boots = [], {}
    for tr, te in (("MTA", "MCFP"), ("MCFP", "MTA")):
        itr = lab & (both["lab"] == tr).values; ite = lab & (both["lab"] == te).values
        print(tr, "->", te, "train", itr.sum(), "caps", both.loc[itr, "capture_id"].nunique(),
              "pos", int(y[itr].sum()), "| test", ite.sum(), "caps", both.loc[ite, "capture_id"].nunique(),
              "pos", int(y[ite].sum()), flush=True)
        if len(np.unique(y[itr])) < 2 or len(np.unique(y[ite])) < 2: continue
        w = capture_weights(both[itr].reset_index(drop=True))
        preds = {}
        for s in USE:
            X = pd.concat([fams[f] for f in SETS[s]], axis=1); X.columns = [f"{i}_{c}" for i, c in enumerate(X.columns)]
            ps = []
            for seed in (0, 1, 2):
                p, _ = fit_predict(X[itr], y[itr].astype(int), w, X[ite], seed=seed); ps.append(p)
            p = np.mean(ps, 0); preds[s] = p
            m = metrics(y[ite].astype(int), p, both.loc[ite, "capture_id"].values)
            m.update(train=tr, test=te, set=s, n_test=int(ite.sum()), n_test_caps=int(both.loc[ite, "capture_id"].nunique()),
                     n_test_mal_caps=int(both.loc[ite & (y == 1), "capture_id"].nunique()),
                     n_test_ben_caps=int(both.loc[ite & (y == 0), "capture_id"].nunique()))
            rows.append(m); print(tr, te, s, {k: round(v, 3) for k, v in m.items() if isinstance(v, float)}, flush=True)
        caps = both.loc[ite, "capture_id"].values
        for s in ("HR+TLS+BEH", "HRb+TLS+BEH"):
            b = bootstrap_diff(y[ite].astype(int), preds[s], preds["TLS+BEH"], caps)
            boots[f"{tr}->{te}:{s}-TLS+BEH"] = {"d_tpr": b["d_tpr"], "d_auc": b["d_auc"]}
    pd.DataFrame(rows).to_csv(f"{OUT}/transfer_metrics.csv", index=False)
    json.dump(boots, open(f"{OUT}/transfer_bootstrap.json", "w"), indent=2)
    print(json.dumps(boots, indent=2))


if __name__ == "__main__":
    main()
