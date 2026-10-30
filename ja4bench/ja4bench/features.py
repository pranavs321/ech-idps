"""Feature sets. Every vocabulary / encoding is fitted on the TRAINING fold only.

Feature sets
  ja4_components  parsed JA4_a fields + JA4_b / JA4_c hash indicators (+ cipher/ext tokens only if
                  the raw lists exist for EVERY row; a column that is missing for one class is itself a
                  dataset-construction artefact, so we refuse to use it)
  ja4_plus_sni    ja4_components + registrable SNI domain  (the ECH ablation: what ECH would remove)
  env_only        DIAGNOSTIC ONLY: capture-environment fields (client /24, dst port, proto, TTL, window,
                  MSS, wscale). If this predicts the label, the dataset confounds class with environment.
  flow            flow_* behaviour columns (bytes, packets, durations, timing)
  ja4_flow        ja4_components + flow
"""
from __future__ import annotations

import logging

import numpy as np
import pandas as pd

from .ja4parse import decompose

log = logging.getLogger(__name__)
FEATURE_SETS = ["ja4_components", "ja4_plus_sni", "env_only", "flow", "ja4_flow"]


def _tokens(s: pd.Series) -> pd.Series:
    return s.fillna("").astype(str).str.replace(",", "-").str.split("-")


def _sni_domain(s: pd.Series) -> pd.Series:
    x = s.fillna("").astype(str).str.lower().str.strip(".")
    return x.str.split(".").map(lambda p: ".".join(p[-2:]) if len(p) >= 2 and p[0] else "__none__")


def _subnet24(s: pd.Series) -> pd.Series:
    return s.fillna("?").astype(str).str.rsplit(".", n=1).str[0]


class _Cat:
    """One-hot with a train-only vocabulary; unseen and rare values go to __other__."""

    def __init__(self, name: str, min_count: int = 2):
        self.name, self.min_count, self.vocab = name, min_count, []

    def fit(self, s: pd.Series):
        vc = s.value_counts()
        self.vocab = sorted(vc[vc >= self.min_count].index.astype(str).tolist())
        return self

    def transform(self, s: pd.Series) -> pd.DataFrame:
        s = s.astype(str)
        cols = {f"{self.name}={v}": (s == v).astype(np.float32).values for v in self.vocab}
        cols[f"{self.name}=__other__"] = (~s.isin(self.vocab)).astype(np.float32).values
        return pd.DataFrame(cols, index=s.index)


class _Bag:
    """Multi-hot bag of tokens (cipher suites, extensions) with a train-only vocabulary."""

    def __init__(self, name: str, min_count: int = 2):
        self.name, self.min_count, self.vocab = name, min_count, []

    def fit(self, s: pd.Series):
        vc = pd.Series([t for row in _tokens(s) for t in set(row) if t]).value_counts()
        self.vocab = sorted(vc[vc >= self.min_count].index.tolist())
        return self

    def transform(self, s: pd.Series) -> pd.DataFrame:
        toks = _tokens(s).map(set)
        cols = {f"{self.name}:{v}": toks.map(lambda r, v=v: v in r).astype(np.float32).values
                for v in self.vocab}
        cols[f"{self.name}:__n__"] = toks.map(len).astype(np.float32).values
        return pd.DataFrame(cols, index=s.index)


class FeatureBuilder:
    def __init__(self, feature_set: str):
        if feature_set not in FEATURE_SETS:
            raise ValueError(f"unknown feature set {feature_set}; choose from {FEATURE_SETS}")
        self.fs = feature_set
        self.parts = []
        self.use_tokens = False
        self.flow_cols: list[str] = []
        self.env_num: list[str] = []
        self.notes: list[str] = []

    # ---------------------------------------------------------------- fit
    def fit(self, df: pd.DataFrame) -> "FeatureBuilder":
        fs = self.fs
        if fs in ("ja4_components", "ja4_plus_sni", "ja4_flow"):
            d = decompose(df["ja4"])
            self.parts = [("a_proto", _Cat("a_proto", 1).fit(d["a_proto"])),
                          ("a_alpn", _Cat("a_alpn", 1).fit(d["a_alpn"])),
                          ("ja4_b", _Cat("ja4_b").fit(d["ja4_b"])),
                          ("ja4_c", _Cat("ja4_c").fit(d["ja4_c"]))]
            have = all(c in df and df[c].notna().all() for c in ["cipher_list", "ext_list"])
            self.use_tokens = have
            if have:
                self.parts += [("cipher_list", _Bag("cs").fit(df["cipher_list"])),
                               ("ext_list", _Bag("ext").fit(df["ext_list"]))]
            else:
                self.notes.append("cipher/ext tokens skipped: raw lists missing for some rows")
            if fs == "ja4_plus_sni":
                self.parts.append(("sni_dom", _Cat("sni").fit(_sni_domain(df.get("sni", pd.Series("", index=df.index))))))
        if fs == "env_only":
            if "src_ip" in df:
                self.parts.append(("src24", _Cat("src24", 1).fit(_subnet24(df["src_ip"]))))
            self.parts.append(("proto", _Cat("proto", 1).fit(df["proto"])))
            self.env_num = [c for c in ["dst_port", "ttl", "win", "mss", "wscale"] if c in df]
        if fs in ("flow", "ja4_flow"):
            self.flow_cols = [c for c in df.columns if c.startswith("flow_")]
            if not self.flow_cols:
                self.notes.append("no flow_* columns in this table")
        return self

    # ---------------------------------------------------------- transform
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        blocks = []
        if self.fs in ("ja4_components", "ja4_plus_sni", "ja4_flow"):
            d = decompose(df["ja4"])
            blocks.append(d[["a_ok", "a_ver", "a_sni", "a_nciph", "a_next"]].astype(np.float32))
            src = {"a_proto": d["a_proto"], "a_alpn": d["a_alpn"], "ja4_b": d["ja4_b"],
                   "ja4_c": d["ja4_c"]}
            if self.use_tokens:
                src["cipher_list"], src["ext_list"] = df["cipher_list"], df["ext_list"]
            if self.fs == "ja4_plus_sni":
                src["sni_dom"] = _sni_domain(df.get("sni", pd.Series("", index=df.index)))
            for key, enc in self.parts:
                blocks.append(enc.transform(src[key]))
        if self.fs == "env_only":
            src = {"src24": _subnet24(df["src_ip"]) if "src_ip" in df else None, "proto": df["proto"]}
            for key, enc in self.parts:
                blocks.append(enc.transform(src[key]))
            if self.env_num:
                blocks.append(df[self.env_num].apply(pd.to_numeric, errors="coerce").astype(np.float32))
        if self.fs in ("flow", "ja4_flow") and self.flow_cols:
            blocks.append(df[self.flow_cols].apply(pd.to_numeric, errors="coerce").astype(np.float32))
        if not blocks:
            raise ValueError(f"feature set {self.fs} produced no columns for this table: {self.notes}")
        X = pd.concat(blocks, axis=1)
        X.columns = [str(c) for c in X.columns]
        return X
