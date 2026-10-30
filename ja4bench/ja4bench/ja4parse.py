"""Parse a JA4 string (a_b_c) into interpretable components.

JA4 = <proto><version><sni><nciphers><nexts><alpn> _ <cipher_hash12> _ <ext+sigalg_hash12>
e.g. t13d1516h2_8daaf6152771_02713d6af862
  proto   t=TCP, q=QUIC, d=DTLS
  version 13,12,11,10,s3,s2,00
  sni     d = domain present, i = no SNI (IP)
  counts  two digits each (capped at 99)
  alpn    first+last char of first ALPN value, 00 if none
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd

_A = re.compile(r"^([tqd])(13|12|11|10|s3|s2|00)([di])(\d{2})(\d{2})(..)$")
_VER = {"13": 1.3, "12": 1.2, "11": 1.1, "10": 1.0, "s3": 0.3, "s2": 0.2, "00": np.nan}


def split_ja4(ja4: str):
    parts = str(ja4).split("_")
    if len(parts) != 3:
        return None
    return parts


def parse_a(a: str) -> dict:
    m = _A.match(str(a))
    if not m:
        return {"a_ok": 0, "a_proto": "?", "a_ver": np.nan, "a_sni": np.nan,
                "a_nciph": np.nan, "a_next": np.nan, "a_alpn": "??"}
    p, v, s, nc, ne, al = m.groups()
    return {"a_ok": 1, "a_proto": p, "a_ver": _VER[v], "a_sni": 1.0 if s == "d" else 0.0,
            "a_nciph": float(nc), "a_next": float(ne), "a_alpn": al}


def decompose(series: pd.Series) -> pd.DataFrame:
    """Vectorised decomposition of a JA4 column. Unparseable values get a_ok=0."""
    s = series.astype(str)
    parts = s.str.split("_", n=2, expand=True)
    if parts.shape[1] < 3:
        parts = parts.reindex(columns=[0, 1, 2])
    a = parts[0].fillna("")
    parsed = pd.DataFrame([parse_a(x) for x in a], index=series.index)
    parsed["ja4_a"] = a
    parsed["ja4_b"] = parts[1].fillna("?")
    parsed["ja4_c"] = parts[2].fillna("?")
    parsed["ja4_ab"] = parsed["ja4_a"] + "_" + parsed["ja4_b"]
    return parsed
