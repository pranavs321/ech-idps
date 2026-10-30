"""Evaluation protocols. Each yields (fold_name, train_idx, test_idx) on the rows with label in {0,1}.

P1_random        random stratified flow split (what most papers report; reference only)
P2_capture       capture-disjoint (StratifiedGroupKFold on capture_id)
P3_ja4           JA4-disjoint: no test fingerprint was seen in training (GroupKFold on ja4)
P4_family        family-disjoint: malware families (and benign apps) held out (GroupKFold on family)
P5_temporal      train on year <= y, test on year > y
P6_domain        leave-one-domain-out, domain = --domain-col (default platform: desktop vs mobile)
P7_source        leave-one-source-out (cross-corpus)
P8_env_matched   only environments that contain BOTH classes, capture-disjoint inside them

A fold is skipped (and logged with the reason) if its train or test part lacks a class.
Nothing is ever silently replaced by a constant prediction.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupKFold, StratifiedGroupKFold, StratifiedKFold

PROTOCOLS = ["P1_random", "P2_capture", "P3_ja4", "P4_family", "P5_temporal", "P6_domain",
             "P7_source", "P8_env_matched"]


@dataclass
class Fold:
    protocol: str
    name: str
    train: np.ndarray
    test: np.ndarray


@dataclass
class Skip:
    protocol: str
    name: str
    reason: str


def _ok(y: np.ndarray, tr: np.ndarray, te: np.ndarray) -> str | None:
    if len(set(y[tr])) < 2:
        return "train fold has one class"
    if len(set(y[te])) < 2:
        return "test fold has one class"
    return None


def generate(df: pd.DataFrame, protocol: str, k: int = 5, seed: int = 42,
             domain_col: str = "platform"):
    """Yield Fold or Skip objects. df must already be filtered to label in {0,1}."""
    y = df["label"].to_numpy()
    idx = np.arange(len(df))

    def emit(name, tr, te):
        r = _ok(y, tr, te)
        return Skip(protocol, name, r) if r else Fold(protocol, name, tr, te)

    if protocol == "P1_random":
        for i, (tr, te) in enumerate(StratifiedKFold(k, shuffle=True, random_state=seed).split(idx, y)):
            yield emit(f"fold{i}", tr, te)
    elif protocol == "P2_capture":
        g = df["capture_id"].to_numpy()
        sgk = StratifiedGroupKFold(k, shuffle=True, random_state=seed)
        for i, (tr, te) in enumerate(sgk.split(idx, y, g)):
            yield emit(f"fold{i}", tr, te)
    elif protocol in ("P3_ja4", "P4_family"):
        col = "ja4" if protocol == "P3_ja4" else "family"
        g = df[col].astype(str).to_numpy()
        if len(set(g)) < k:
            yield Skip(protocol, "all", f"fewer than {k} distinct {col}")
            return
        # shuffle group order deterministically so folds are not alphabetical
        uniq = np.array(sorted(set(g)))
        rng = np.random.default_rng(seed)
        perm = {u: j for j, u in enumerate(rng.permutation(uniq))}
        gnum = np.array([perm[x] for x in g])
        for i, (tr, te) in enumerate(GroupKFold(k).split(idx, y, gnum)):
            yield emit(f"fold{i}", tr, te)
    elif protocol == "P5_temporal":
        years = sorted(set(df["year"].astype(int)))
        if len(years) < 2:
            yield Skip(protocol, "all", f"only one capture year in table: {years}")
            return
        for cut in years[:-1]:
            tr = idx[df["year"].to_numpy() <= cut]
            te = idx[df["year"].to_numpy() > cut]
            yield emit(f"train<= {cut}", tr, te)
    elif protocol in ("P6_domain", "P7_source"):
        col = domain_col if protocol == "P6_domain" else "source"
        vals = df[col].astype(str).to_numpy()
        doms = sorted(set(vals))
        if len(doms) < 2:
            yield Skip(protocol, "all", f"only one value of {col}: {doms}")
            return
        for d in doms:
            yield emit(f"test={d}", idx[vals != d], idx[vals == d])
    elif protocol == "P8_env_matched":
        both = df.groupby("env_group")["label"].nunique()
        envs = sorted(both[both == 2].index)
        if not envs:
            yield Skip(protocol, "all", "no env_group contains both classes (class == environment)")
            return
        sub = idx[df["env_group"].isin(envs).to_numpy()]
        g = df["capture_id"].to_numpy()[sub]
        sgk = StratifiedGroupKFold(k, shuffle=True, random_state=seed)
        for i, (tr, te) in enumerate(sgk.split(sub, y[sub], g)):
            yield emit(f"fold{i} envs={'+'.join(envs)}", sub[tr], sub[te])
    else:
        raise ValueError(f"unknown protocol {protocol}; choose from {PROTOCOLS}")
