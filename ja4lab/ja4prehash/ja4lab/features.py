"""
Turn pre-hash JA4+ components into a numeric matrix.

Feature groups (used for the ablation table in the paper):
  CH_STRICT : exactly the information that goes into JA4 (version, SNI flag, cipher SET,
              extension SET, sig-alg LIST, first ALPN). A model on this group answers
              "is the JA4 input itself enough?"
  CH_EXT    : ClientHello info JA4 DISCARDS: extension ORDER, GREASE usage, supported groups,
              key-share groups, point formats, PSK modes, cert compression, lengths, ECH ...
  JA4S      : ServerHello (chosen cipher, server extensions, version, ALPN)
  JA4T      : TCP SYN (window, option layout, MSS, window scale) - NOT latency (per guide)
  JA4H      : plaintext HTTP request header layout (only exists for cleartext HTTP)

Design rules that make "unseen fingerprint" evaluation honest:
  * Vocabularies (which cipher / extension IDs become columns) are fitted on TRAIN folds only.
  * Tokens never seen in training are counted in n_unknown_<field> instead of being dropped.
  * The fingerprint hash strings and the SNI are NEVER features (that would be a lookup).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .tlsparse import is_grease

LIST_FIELDS = {
    # field name              group
    "ch_ciphers":            "CH_STRICT",
    "ch_extensions":         "CH_STRICT",
    "ch_sig_algs":           "CH_STRICT",
    "ch_groups":             "CH_EXT",
    "ch_key_share_groups":   "CH_EXT",
    "ch_ec_point_formats":   "CH_EXT",
    "ch_psk_modes":          "CH_EXT",
    "ch_cert_compression":   "CH_EXT",
    "ch_supported_versions": "CH_EXT",
    "ch_sig_algs_cert":      "CH_EXT",
    "sh_extensions":         "JA4S",
    "tcp_options":           "JA4T",
    "http_headers":          "JA4H",
}
CAT_FIELDS = {
    "alpn_first": "CH_STRICT",
    "sh_cipher": "JA4S",
    "sh_version_eff": "JA4S",
    "sh_alpn": "JA4S",
    "http_method": "JA4H",
}
ORDER_EXTS = ["0000", "0005", "000a", "000b", "000d", "0010", "0012", "0015", "0017",
              "001b", "0023", "002b", "002d", "0033", "ff01", "4469", "44cd", "fe0d", "0029"]
GROUPS = ["CH_STRICT", "CH_EXT", "JA4S", "JA4T", "JA4H"]


def _split(s, sep="-") -> list[str]:
    if not isinstance(s, str) or not s:
        return []
    if sep == "," or "," in s:
        return [t for t in s.split(",") if t]
    return [t for t in s.split(sep) if t]


def _nogrease(tokens: list[str]) -> list[str]:
    out = []
    for t in tokens:
        try:
            if len(t) == 4 and is_grease(int(t, 16)):
                continue
        except ValueError:
            pass
        out.append(t)
    return out


def prepare(df: pd.DataFrame) -> pd.DataFrame:
    """Derive helper columns (idempotent)."""
    d = df.copy()
    for c in list(LIST_FIELDS) + ["ch_alpn", "sh_supported_version", "sh_legacy_version",
                                  "ch_legacy_version", "ja4_a", "sni", "ttl"]:
        if c not in d.columns:
            d[c] = ""
    d["alpn_first"] = d["ch_alpn"].map(lambda s: s.split(",")[0] if isinstance(s, str) and s else "none")
    d["sh_version_eff"] = [sv if sv else lv for sv, lv in zip(d["sh_supported_version"], d["sh_legacy_version"])]
    for c in ["sh_cipher", "sh_alpn", "http_method"]:
        if c not in d.columns:
            d[c] = ""
    return d


def _col(d: pd.DataFrame, c: str, default=""):
    return d[c] if c in d.columns else pd.Series([default] * len(d), index=d.index)


def _num(d, c):
    return pd.to_numeric(_col(d, c, -1), errors="coerce").fillna(-1)


class Featurizer:
    def __init__(self, groups=GROUPS, min_df: int = 2, max_tokens_per_field: int = 400):
        self.groups = list(groups)
        self.min_df = min_df
        self.max_tokens = max_tokens_per_field
        self.vocab: dict[str, list[str]] = {}
        self.columns_: list[str] = []
        self.group_of_: dict[str, str] = {}

    # ---------------------------------------------------------------- fit / transform
    def fit(self, df: pd.DataFrame):
        d = prepare(df)
        for f, g in {**LIST_FIELDS, **CAT_FIELDS}.items():
            if g not in self.groups:
                continue
            if f in LIST_FIELDS:
                toks = d[f].map(lambda s: set(_nogrease(_split(s, "," if f == "http_headers" else "-"))))
            else:
                toks = d[f].map(lambda s: {s if s else "none"})
            vc = pd.Series([t for ts in toks for t in ts]).value_counts()
            self.vocab[f] = list(vc[vc >= self.min_df].index[: self.max_tokens])
        X = self.transform(df)
        self.columns_ = list(X.columns)
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        d = prepare(df)
        cols: dict[str, np.ndarray] = {}

        def put(name, values, group):
            cols[name] = np.asarray(values, dtype=float)
            self.group_of_[name] = group

        n = len(d)
        # --- token multi-hot + unknown counts
        for f, g in {**LIST_FIELDS, **CAT_FIELDS}.items():
            if g not in self.groups or f not in self.vocab:
                continue
            sep = "," if f == "http_headers" else "-"
            if f in LIST_FIELDS:
                toks = d[f].map(lambda s: set(_nogrease(_split(s, sep)))).tolist()
            else:
                toks = d[f].map(lambda s: {s if s else "none"}).tolist()
            vocab = self.vocab[f]
            vs = set(vocab)
            for t in vocab:
                put(f"{f}={t}", [t in ts for ts in toks], g)
            put(f"n_unknown__{f}", [len(ts - vs) for ts in toks], g)
            if f in LIST_FIELDS:
                put(f"len__{f}", [len(ts) for ts in toks], g)

        if "CH_STRICT" in self.groups:
            v = d["ja4_a"].astype(str)
            put("tls_ver_13", v.str[1:3].eq("13"), "CH_STRICT")
            put("tls_ver_12", v.str[1:3].eq("12"), "CH_STRICT")
            put("tls_ver_old", v.str[1:3].isin(["10", "11", "s3", "s2"]), "CH_STRICT")
            put("sni_present", v.str[3:4].eq("d"), "CH_STRICT")
            put("n_sigalgs_ordered", d["ch_sig_algs"].map(lambda s: len(_nogrease(_split(s)))), "CH_STRICT")

        if "CH_EXT" in self.groups:
            ext_lists = d["ch_extensions"].map(_split).tolist()
            put("grease_in_ciphers", d["ch_ciphers"].map(lambda s: len(_split(s)) != len(_nogrease(_split(s)))), "CH_EXT")
            put("grease_in_exts", [len(e) != len(_nogrease(e)) for e in ext_lists], "CH_EXT")
            put("grease_ext_first", [bool(e) and len(_nogrease(e[:1])) == 0 for e in ext_lists], "CH_EXT")
            clean = [_nogrease(e) for e in ext_lists]
            for x in ORDER_EXTS:          # relative position of key extensions (order JA4 discards)
                put(f"pos__{x}", [(e.index(x) / max(1, len(e) - 1)) if x in e else -1 for e in clean], "CH_EXT")
            put("exts_sorted_on_wire", [e == sorted(e) and len(e) > 1 for e in clean], "CH_EXT")
            for c in ["ch_len", "ch_session_id_len", "ch_padding_len", "ch_record_size_limit",
                      "ch_has_ech", "ch_has_psk", "ch_has_early_data", "ch_tls_records"]:
                put(c, _num(d, c), "CH_EXT")
            put("legacy_ver_0303", d["ch_legacy_version"].eq("0303"), "CH_EXT")
            put("compression_nonnull", _col(d, "ch_compression").map(lambda s: s not in ("", "0")), "CH_EXT")

        if "JA4S" in self.groups:
            put("has_server_hello", _col(d, "ja4s").astype(str).ne(""), "JA4S")
            put("sh_is_hrr", _num(d, "sh_is_hrr").clip(lower=0), "JA4S")

        if "JA4T" in self.groups:
            put("has_syn", _col(d, "ja4t").astype(str).ne(""), "JA4T")
            for c in ["tcp_window", "tcp_mss", "tcp_wscale"]:
                put(c, _num(d, c), "JA4T")
            ttl = pd.to_numeric(d["ttl"], errors="coerce").fillna(-1)
            put("init_ttl_64", (ttl > 0) & (ttl <= 64), "JA4T")
            put("init_ttl_128", (ttl > 64) & (ttl <= 128), "JA4T")
            put("init_ttl_255", ttl > 128, "JA4T")

        if "JA4H" in self.groups:
            put("is_http", _col(d, "kind").eq("http"), "JA4H")

        X = pd.DataFrame(cols, index=d.index)
        if self.columns_:
            X = X.reindex(columns=self.columns_, fill_value=0.0)
        return X

    def fit_transform(self, df):
        self.fit(df)
        return self.transform(df)

    def groups_of(self, cols):
        return [self.group_of_.get(c, "?") for c in cols]
