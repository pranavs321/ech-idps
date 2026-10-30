"""Canonical table schema.

Every source (Matousek CSVs, ja4lab connections.csv, CTU, MTA, Triage, ...) is converted by an
adapter into ONE row-per-TLS-connection table with these columns. Downstream code only ever
reads this table, so every protocol and model is comparable across sources.

Design rules
- Labels are never overwritten. A row's label comes with `label_basis` saying WHY it has that label.
- Environment is a first-class column (`env_group`, `platform`, `os`, `vantage`). Most published
  datasets do not record it; that omission is exactly what hides the shortcut.
- Identifier columns (IPs, ports, capture ids, SNI, family) are carried for grouping and auditing
  but are NEVER model features (see IDENTIFIER_COLUMNS). SNI may be used only in the explicit
  ECH/SNI ablation feature set.
"""
from __future__ import annotations

import pandas as pd

REQUIRED = {
    "source": "dataset id from config/sources.yaml, e.g. matousek2024, mta2024, ctu13",
    "capture_id": "unique id of the pcap the row came from (unit of splitting and of bootstrap)",
    "env_group": "who/where captured it, e.g. triage_win10_sandbox, but_lab_windows, hashapp_avd",
    "platform": "desktop | mobile | iot | server | unknown",
    "os": "windows | android | macos | linux | ios | unknown",
    "year": "capture year (int)",
    "family": "malware family for malicious rows; application name for benign rows",
    "label": "1 malicious, 0 benign, -1 excluded (gray / ads / unknown). Never overwritten.",
    "label_basis": "ioc_verified | source_asserted | sandbox_verdict | inferred | ads | os_background | unknown",
    "proto": "tcp | quic",
    "ja4": "JA4 client fingerprint string a_b_c",
}

OPTIONAL = {
    "row_id": "stable row id",
    "src_ip": "identifier only", "dst_ip": "identifier only",
    "src_port": "identifier only", "dst_port": "environment/destination feature (env_only set)",
    "sni": "server name; leakage feature, used only in ja4_plus_sni (ECH ablation)",
    "ja4_r": "raw (unhashed) JA4 string", "ja3": "JA3 hash", "ja4s": "JA4S server fingerprint",
    "ja4t": "JA4T TCP fingerprint (window_options_mss_wscale)", "ja4x": "certificate fingerprint",
    "cipher_list": "dash- or comma-separated client cipher suite ids (decimal or hex)",
    "ext_list": "dash- or comma-separated client extension ids",
    "ttl": "IP TTL of client packets (environment)", "win": "TCP window (environment)",
    "mss": "TCP MSS (environment)", "wscale": "TCP window scale (environment)",
    "vantage": "where the sensor was: sandbox_gateway | host | lan_tap | isp_backbone",
    "ts": "flow start time (epoch seconds)",
}
# any column starting with flow_ is a behaviour feature (bytes, packets, timing, ...)
FLOW_PREFIX = "flow_"

IDENTIFIER_COLUMNS = {"row_id", "src_ip", "dst_ip", "src_port", "capture_id", "sni", "family",
                      "source", "env_group", "label", "label_basis", "ts", "ja4_r", "ja3", "year"}

VALID_LABELS = {-1, 0, 1}


def validate(df: pd.DataFrame) -> list[str]:
    """Return a list of problems (empty list = valid). Never mutates df."""
    problems = []
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        problems.append(f"missing required columns: {missing}")
        return problems
    bad = set(pd.unique(df["label"])) - VALID_LABELS
    if bad:
        problems.append(f"invalid label values: {sorted(bad)}")
    for c in ["capture_id", "env_group", "source", "ja4"]:
        n = int(df[c].isna().sum())
        if n:
            problems.append(f"{n} rows with empty {c}")
    if not pd.api.types.is_integer_dtype(df["year"]):
        problems.append("year must be integer")
    # a capture must belong to exactly one env_group and one source
    for c in ["env_group", "source"]:
        k = df.groupby("capture_id")[c].nunique()
        if (k > 1).any():
            problems.append(f"{int((k > 1).sum())} captures map to >1 {c}")
    return problems
