"""Incident grouping (host, destination, 1-hour window) on the MTA same-host data, leave-one-source-out.
Idea credited to the concurrent SCBD-R student project (personal communication). Exploratory.
Incident label = 1 if any labelled-malicious connection inside, 0 if all labelled connections benign.
Incident score = max connection score (also mean). Report incident ROC-AUC, TPR at 1% incident FPR,
and false incidents per benign host at the connection threshold that gives 1% connection FPR."""
from __future__ import annotations
import json, os, sys
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ja4next import features as F
from ja4next.evaluate import SETS, cap_per_capture, capture_weights, fit_predict, tpr_at

OUT = "results/incidents"


def main():
    df = pd.read_parquet("data/processed/connections.parquet")
    df = df[(df.year <= 2021) & (df.sni.fillna("") != "")].reset_index(drop=True)
    fams = F.build(df)
    df.loc[~cap_per_capture(df, 100), "y"] = np.nan
    lab = df.y.notna().values
    df["host"] = df.capture_id.astype(str) + "|" + df.client_ip.astype(str)
    df["dest"] = F.dest_key(df)
    df["hour"] = (df.t_clienthello.astype(float) // 3600).astype(int)
    df["inc"] = df.host + "|" + df.dest + "|" + df.hour.astype(str)
    rows = []
    for s in ("TLS+BEH", "HRb+TLS+BEH", "HR+TLS+BEH"):
        X = pd.concat([fams[f] for f in SETS[s]], axis=1); X.columns = [f"{i}_{c}" for i, c in enumerate(X.columns)]
        score = np.full(len(df), np.nan)
        for src in df.source.unique():
            te = (df.source == src).values; tr = lab & ~te
            if len(np.unique(df.y.values[tr])) < 2: continue
            w = capture_weights(df[tr].reset_index(drop=True))
            score[te] = fit_predict(X[tr], df.y.values[tr].astype(int), w, X[te], seed=0)[0]
        d = df.assign(s=score)
        L = d[lab & ~np.isnan(score)]
        thr = np.quantile(L.loc[L.y == 0, "s"], 0.99)
        conn_tpr = float((L.loc[L.y == 1, "s"] > thr).mean())
        g = d[~np.isnan(score)].groupby("inc")
        inc = pd.DataFrame({"s_max": g.s.max(), "s_mean": g.s.mean(), "n": g.size(),
                            "flag_n": g.s.apply(lambda v: int((v > thr).sum())),
                            "pos": g.y.max(), "host": g.host.first(), "source": g.source.first()})
        il = inc.dropna(subset=["pos"])
        for agg in ("s_max", "s_mean"):
            yi = il.pos.astype(int).values
            rows.append(dict(set=s, agg=agg, conn_tpr_at_1pct=conn_tpr, incidents=len(il), mal_incidents=int(yi.sum()),
                             inc_auc=float(roc_auc_score(yi, il[agg])), inc_tpr_at_1pct=float(tpr_at(yi, il[agg].values, 0.01)),
                             benign_conn_alerts_per_host=float((L.loc[L.y == 0, "s"] > thr).groupby(L.loc[L.y == 0, "host"]).sum().mean()),
                             benign_inc_alerts_per_host=float(il[il.pos == 0].groupby("host").flag_n.apply(lambda v: (v > 0).sum()).mean())))
        print(s, rows[-2:], flush=True)
    os.makedirs(OUT, exist_ok=True)
    pd.DataFrame(rows).to_csv(f"{OUT}/incident_metrics.csv", index=False)


if __name__ == "__main__":
    main()
