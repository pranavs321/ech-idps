"""Clean-benign false-alarm test on Stratosphere CTU-Normal / CTU-Mixed (exploratory).
Benign ground truth = documented normal host (README 'Normal host'), or Mixed 'before.infection'/'onlynormal' files.
Malicious (Mixed only) = README C&C IPs or feed IOCs on the infected host. No allowlist needed for benign.
Train on 80% of MTA 2013-2021 captures (hostname-only, cap 100), set the threshold at 1% FPR on the
held-out 20% MTA benign, then report the share of clean foreign benign connections/hosts flagged.
Usage: PYTHONPATH=src python -m ja4next.foreign_benign"""
from __future__ import annotations
import glob, json, os, re, sys
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ja4next import features as F
from ja4next.labels import Feeds, label_frame
from ja4next.evaluate import SETS, cap_per_capture, capture_weights, fit_predict
PRIV = r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"
OUT = "results/foreign_benign"
USE = ["ENV", "TLS", "BEH", "TLS+BEH", "HRb+TLS+BEH", "HR+TLS+BEH"]


from ja4next.strat import readme, normal_ips as _normal_ips, cc_ips as _cc_ips


def load_stratosphere():
    fr = [pd.read_parquet(f) for f in glob.glob("data/interim/mcfp2/*.parquet")]
    df = pd.concat([f for f in fr if len(f)], ignore_index=True)
    df["capture_id"] = df["mcfp_dir"] + "/" + df["pcap_name"]
    df = df[df.client_ip.astype(str).str.match(PRIV) & ~df.server_ip.astype(str).str.match(PRIV)].copy()
    feeds = Feeds("data/labels")
    y = np.full(len(df), np.nan); tier = np.array(["unknown"] * len(df), dtype=object)
    for d in df.mcfp_dir.unique():
        t = readme(d); m = (df.mcfp_dir == d).values
        normal_ips = _normal_ips(t)
        cc = _cc_ips(t)
        if d.startswith("CTU-Normal"):
            hm = m & df.client_ip.isin(normal_ips).values if normal_ips else m
            y[hm] = 0; tier[hm] = "normal_host"
        else:
            clean = m & df.pcap_name.str.contains(r"before\.infection|onlynormal", regex=True).values
            y[clean] = 0; tier[clean] = "pre_infection"
            ccm = m & ~clean & df.server_ip.isin(cc).values
            y[ccm] = 1; tier[ccm] = "readme_cc"
            rest = m & ~clean & ~ccm
            if rest.any():
                lf = label_frame(df[rest], feeds, {})
                pos = (lf.label_tier.isin(["gold_mal", "weak_mal"])).values
                idx = np.where(rest)[0][pos]; y[idx] = 1; tier[idx] = lf.label_tier.values[pos]
    df["y"], df["label_tier"], df["source"], df["lab"] = y, tier, "stratosphere", "STRAT"
    df["year"] = pd.to_datetime(df.t_clienthello, unit="s").dt.year
    return df


def main():
    a = pd.read_parquet("data/processed/connections.parquet"); a = a[a.year <= 2021].copy(); a["lab"] = "MTA"
    b = load_stratosphere()
    print("stratosphere:", b.groupby(["mcfp_dir", "label_tier"]).size().unstack(fill_value=0).to_string(), flush=True)
    both = pd.concat([a, b], ignore_index=True); both = both[both.sni.fillna("") != ""].reset_index(drop=True)
    fams = F.build(both)
    lab = both.y.notna().values
    mta_caps = both.loc[both.lab == "MTA", "capture_id"].unique()
    rng = np.random.default_rng(0); cal_caps = set(rng.choice(mta_caps, len(mta_caps) // 5, replace=False))
    is_mta = (both.lab == "MTA").values; is_cal = both.capture_id.isin(cal_caps).values
    capm = cap_per_capture(both, 100)
    itr = lab & is_mta & ~is_cal & capm
    ical = lab & is_mta & is_cal & (both.y.values == 0)
    w = capture_weights(both[itr].reset_index(drop=True))
    ist = (both.lab == "STRAT").values
    rows = []
    for s in USE:
        X = pd.concat([fams[f] for f in SETS[s]], axis=1); X.columns = [f"{i}_{c}" for i, c in enumerate(X.columns)]
        ps = np.mean([fit_predict(X[itr], both.y.values[itr].astype(int), w, X, seed=k)[0] for k in (0, 1, 2)], 0)
        thr = np.quantile(ps[ical], 0.99)
        for grp, msk in (("normal_host", ist & (both.label_tier == "normal_host").values),
                         ("pre_infection", ist & (both.label_tier == "pre_infection").values),
                         ("mixed_malicious", ist & (both.y.values == 1))):
            if msk.sum() == 0: continue
            g = both[msk].assign(s=ps[msk])
            rows.append(dict(set=s, group=grp, conns=int(msk.sum()), captures=int(g.capture_id.nunique()),
                             flagged_conn=float((g.s > thr).mean()),
                             flagged_capture_mean=float(g.groupby("capture_id").s.apply(lambda v: (v > thr).mean()).mean()),
                             mta_cal_fpr=float((ps[ical] > thr).mean())))
        print(s, [(r["group"], round(r["flagged_conn"], 3)) for r in rows if r["set"] == s], flush=True)
    os.makedirs(OUT, exist_ok=True)
    pd.DataFrame(rows).to_csv(f"{OUT}/flag_rates.csv", index=False)


if __name__ == "__main__":
    main()
