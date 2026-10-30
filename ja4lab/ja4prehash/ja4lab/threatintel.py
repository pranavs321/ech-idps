"""
Stage 3 of the plan: external threat intelligence / signature databases.

Two things:
 (a) `coverage`  - how many of OUR fingerprints does an external DB know at all, and how many are
                   labelled malicious? (This quantifies the "lookup is useless when unknown" problem
                   -> strong motivation paragraph in the paper.)
 (b) `benchmark` - the JA4DB snapshot contains ~74k JA4_r raw strings, most with a User-Agent.
                   We turn that into a PUBLIC, reproducible attribution benchmark: predict the TLS
                   client stack family (Chromium, Firefox, Safari/Apple, curl, Python, Go, Java,
                   bots ...) for fingerprints never seen in training.

Data sources (download with scripts/get_threat_intel.sh):
  * JA4DB frozen snapshot (JA4DB's public API closed in 2026; this community export is frozen):
      https://github.com/Niicolaa/ja4db-export   -> csv/all_records.csv
  * FoxIO mapping file: https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv
  * abuse.ch SSLBL JA3 list (JA3 only): https://sslbl.abuse.ch/ja3-fingerprints/

    python -m ja4lab.threatintel coverage --instances data/processed/instances.csv --out results/
    python -m ja4lab.threatintel benchmark --ja4db data/ti/ja4db_all_records.csv --out results/
"""
from __future__ import annotations

import warnings
warnings.filterwarnings("ignore")

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

MAL_KW = ("cobalt", "sliver", "havoc", "icedid", "qakbot", "qbot", "emotet", "trickbot", "dridex",
          "pikabot", "lumma", "darkgate", "bumblebee", "metasploit", "meterpreter", "mythic",
          "brute ratel", "bruteratel", "covenant", "poshc2", "remcos", "asyncrat", "njrat", "stealer",
          "malware", " c2", "rat ", "evilginx", "gootloader", "latrodectus", "socgholish")


def _is_mal(*texts) -> bool:
    t = " ".join(str(x) for x in texts if isinstance(x, str)).lower()
    return any(k in t for k in MAL_KW)


def load_ja4db(path: str) -> pd.DataFrame:
    d = pd.read_csv(path, low_memory=False, dtype=str)
    d["ti_malicious"] = [
        _is_mal(a, n) for a, n in zip(d.get("application", ""), d.get("notes", ""))]
    return d


def load_foxio(path: str) -> pd.DataFrame:
    d = pd.read_csv(path, dtype=str)
    d.columns = [c.strip().lower() for c in d.columns]
    d["ti_malicious"] = [_is_mal(a, n, l) for a, n, l in
                         zip(d.get("application", ""), d.get("notes", ""), d.get("library", ""))]
    return d


def coverage(inst: pd.DataFrame, sources: dict[str, pd.DataFrame], out: Path):
    rows = []
    for name, db in sources.items():
        for fp_col_ours, fp_col_db in (("ja4", "ja4_fingerprint" if "ja4_fingerprint" in db else "ja4"),
                                        ("ja4s", "ja4s_fingerprint" if "ja4s_fingerprint" in db else "ja4s"),
                                        ("ja4t", "ja4t_fingerprint" if "ja4t_fingerprint" in db else "ja4t")):
            if fp_col_db not in db or fp_col_ours not in inst:
                continue
            known = set(db[fp_col_db].dropna())
            malset = set(db.loc[db["ti_malicious"], fp_col_db].dropna())
            for lab in ("benign", "malicious"):
                u = set(inst.loc[inst["label"] == lab, fp_col_ours].replace("", np.nan).dropna())
                if not u:
                    continue
                rows.append({"db": name, "fingerprint": fp_col_ours, "our_label": lab,
                             "our_unique": len(u), "found_in_db": len(u & known),
                             "pct_found": round(100 * len(u & known) / len(u), 2),
                             "flagged_malicious_by_db": len(u & malset)})
        rows.append({"db": name, "fingerprint": "(db stats)", "our_label": "",
                     "our_unique": "", "found_in_db": len(db), "pct_found": "",
                     "flagged_malicious_by_db": int(db["ti_malicious"].sum())})
    r = pd.DataFrame(rows)
    r.to_csv(out / "ti_coverage.csv", index=False)
    print(r.to_string(index=False))


# ----------------------------------------------------------------------------- JA4DB benchmark

def ua_family(ua: str) -> str:
    u = str(ua).lower()
    if not u or u == "nan":
        return ""
    for k, fam in (("bot", "bot/crawler"), ("spider", "bot/crawler"), ("crawler", "bot/crawler"),
                   ("curl", "curl"), ("wget", "wget"), ("python", "python"), ("go-http", "go"),
                   ("okhttp", "okhttp"), ("java", "java"), ("firefox", "firefox"), ("fxios", "apple_webkit"),
                   ("edg/", "chromium"), ("opr/", "chromium"), ("yabrowser", "chromium"),
                   ("samsungbrowser", "chromium"), ("crios", "apple_webkit"), ("chrome", "chromium"),
                   ("safari", "apple_webkit")):
        if k in u:
            return fam
    return ""


def ja4r_to_components(r: str) -> dict:
    """Parse a JA4_r string 'a_ciphers_exts[_sigs]' into the column names our Featurizer uses."""
    p = str(r).split("_")
    if len(p) < 3:
        return {}
    a, ciphers, exts = p[0], p[1], p[2]
    sigs = p[3] if len(p) > 3 else ""
    ext_list = [e for e in exts.split(",") if e]
    if len(a) >= 4 and a[3] == "d":
        ext_list = ["0000"] + ext_list
    if len(a) >= 10 and a[8:10] != "00":
        ext_list = ext_list + ["0010"]
    return {"ja4_a": a, "ch_ciphers": ciphers.replace(",", "-"),
            "ch_extensions": "-".join(ext_list), "ch_sig_algs": sigs.replace(",", "-"),
            "ch_alpn": a[8:10] if len(a) >= 10 and a[8:10] != "00" else ""}


def benchmark(ja4db_path: str, out: Path, min_fps: int = 5):
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import f1_score, balanced_accuracy_score
    from sklearn.model_selection import StratifiedGroupKFold
    from .features import Featurizer

    d = load_ja4db(ja4db_path)
    d = d[d["ja4_fingerprint_string"].notna()].copy()
    d["stack"] = d["user_agent_string"].map(ua_family)
    d = d[d["stack"] != ""]
    # one row per (raw string, stack): observation counts must not inflate the benchmark
    d = d.drop_duplicates(subset=["ja4_fingerprint_string", "stack"])
    # drop raw strings claimed by several stacks (UA spoofing / shared libraries) - report how many
    multi = d.groupby("ja4_fingerprint_string")["stack"].nunique()
    ambiguous = multi[multi > 1].index
    n_amb = len(ambiguous)
    d = d[~d["ja4_fingerprint_string"].isin(ambiguous)]
    comp = pd.DataFrame([ja4r_to_components(s) for s in d["ja4_fingerprint_string"]], index=d.index)
    d = pd.concat([d, comp], axis=1)
    d["ja4"] = d["ja4_fingerprint"]
    keep = d.groupby("stack")["ja4"].nunique()
    d = d[d["stack"].isin(keep[keep >= min_fps].index)].reset_index(drop=True)
    y = d["stack"].values
    print(f"JA4DB benchmark: {len(d)} raw strings, {d['ja4'].nunique()} JA4, stacks={dict(d['stack'].value_counts())}")
    print(f"  ambiguous raw strings removed (claimed by >1 stack): {n_amb}")
    rows, preds = [], []
    for fi, (tr, te) in enumerate(StratifiedGroupKFold(5, shuffle=True, random_state=42).split(d, y, d["ja4"])):
        fz = Featurizer(groups=["CH_STRICT"]).fit(d.iloc[tr])
        m = HistGradientBoostingClassifier(max_iter=300, class_weight="balanced", random_state=42)
        m.fit(fz.transform(d.iloc[tr]).values, y[tr])
        pr = m.predict_proba(fz.transform(d.iloc[te]).values)
        pred, conf = m.classes_[pr.argmax(1)], pr.max(1)
        # exact-lookup baseline: JA4 seen in train -> its majority stack; here always unseen
        maj = pd.Series(y[tr]).value_counts().index[0]
        seen = set(d.iloc[tr]["ja4"])
        cov = float(d.iloc[te]["ja4"].isin(seen).mean())
        for tau in (0.0, 0.5, 0.7, 0.9):
            mk = conf >= tau
            rows.append({"fold": fi, "tau": tau, "lookup_coverage": cov, "coverage": mk.mean(),
                         "majority_baseline_acc": float((y[te] == maj).mean()),
                         "acc": (pred[mk] == y[te][mk]).mean() if mk.any() else np.nan,
                         "macro_f1": f1_score(y[te][mk], pred[mk], average="macro") if mk.any() else np.nan,
                         "bal_acc": balanced_accuracy_score(y[te][mk], pred[mk]) if mk.any() else np.nan})
        preds += list(zip(y[te], pred))
    r = pd.DataFrame(rows).groupby("tau").agg(["mean", "std"]).round(4)
    r.columns = [f"{a}_{b}" for a, b in r.columns]
    r = r.drop(columns=[c for c in r.columns if c.startswith("fold")]).reset_index()
    r.to_csv(out / "ja4db_attribution.csv", index=False)
    cm = pd.crosstab(pd.Series([a for a, _ in preds], name="true"), pd.Series([b for _, b in preds], name="pred"))
    cm.to_csv(out / "ja4db_confusion.csv")
    print(r.to_string(index=False))
    print(cm)


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("coverage")
    c.add_argument("--instances", required=True)
    c.add_argument("--ja4db", default="data/ti/ja4db_all_records.csv")
    c.add_argument("--foxio", default="data/ti/ja4plus-mapping.csv")
    c.add_argument("--out", default="results")
    b = sub.add_parser("benchmark")
    b.add_argument("--ja4db", default="data/ti/ja4db_all_records.csv")
    b.add_argument("--out", default="results")
    a = ap.parse_args(argv)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    if a.cmd == "coverage":
        inst = pd.read_csv(a.instances, dtype=str, keep_default_na=False)
        srcs = {}
        if Path(a.ja4db).exists():
            srcs["JA4DB-snapshot"] = load_ja4db(a.ja4db)
        if Path(a.foxio).exists():
            srcs["FoxIO-mapping"] = load_foxio(a.foxio)
        if not srcs:
            raise SystemExit("run scripts/get_threat_intel.sh first")
        coverage(inst, srcs, out)
    else:
        benchmark(a.ja4db, out)


if __name__ == "__main__":
    main()
