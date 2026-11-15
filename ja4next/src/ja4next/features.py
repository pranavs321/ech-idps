"""Feature families.

ENV  TCP/IP environment (JA4T/JA4TS content): what the lab/path looks like
TLS  ClientHello per element (pre-hash JA4): ciphers, extensions, sig algs, groups
BEH  post-handshake behaviour of the connection itself
SRV  server side: JA4S elements + leaf-certificate facts (TLS <= 1.2)
HR   HOST-RELATIVE (new): every connection described against the SAME host's
     other TLS connections in the same capture, using no labels:
       - robust z-scores and ranks of behaviour inside the host and inside the
         host's own JA4 stack (cancels OS, path, MTU and lab effects)
       - destination context inside the host (share of the host's traffic,
         first-seen offset, how many stacks/servers reach it)
       - beaconing to the same destination (count, inter-arrival median/CV,
         periodicity)
       - stack context (how common this JA4 is on this host, how many
         destinations it serves)
       - server-side rarity on this host (JA4S, certificate validity)
"""
from __future__ import annotations

import numpy as np
import pandas as pd

ENV_COLS = ["env_c_win", "env_c_mss", "env_c_ws", "env_c_iplen", "env_c_df", "env_c_ttl0",
            "env_s_win", "env_s_mss", "env_s_ws", "env_s_iplen", "env_s_df", "env_s_ttl0"]
BEH_COLS = ["b_n_up", "b_n_down", "b_bytes_up", "b_bytes_down", "b_byte_ratio", "b_up_frac",
            "b_mean_up", "b_std_up", "b_max_up", "b_mean_down", "b_std_down", "b_max_down",
            "b_dir_changes", "b_med_gap_rtt", "b_cv_gap", "duration", "n_pkts_total",
            "closed_fin", "closed_rst"] + [f"b_splt_{i}" for i in range(8)]
# behaviour features that carry the network path (MTU / packet ceilings); dropped in "path-robust" sets
PATH_COLS = ["b_max_up", "b_max_down", "b_mean_down", "b_mean_up"]
HR_BASE = ["b_bytes_up", "b_bytes_down", "b_byte_ratio", "b_up_frac", "b_mean_up", "b_mean_down",
           "b_dir_changes", "b_med_gap_rtt", "duration", "n_pkts_total", "b_n_up", "b_n_down",
           "b_splt_0", "b_splt_1", "b_splt_2", "b_splt_3"]


def dest_key(df: pd.DataFrame) -> pd.Series:
    return df["sni"].fillna("").where(df["sni"].fillna("") != "", df["server_ip"])


def _robust_z(x: pd.Series, grp) -> pd.Series:
    med = x.groupby(grp).transform("median")
    mad = (x - med).abs().groupby(grp).transform("median")
    return (x - med) / (1.4826 * mad + 1e-6 + 0.05 * med.abs())


def host_relative(df: pd.DataFrame, min_stack: int = 3) -> pd.DataFrame:
    """df must hold ALL TLS connections of each host (labelled or not)."""
    d = df.copy()
    d["host"] = d["capture_id"].astype(str) + "|" + d["client_ip"].astype(str)
    d["dest"] = dest_key(d)
    d["stack"] = d["ja4"]
    out = pd.DataFrame(index=d.index)
    host_n = d.groupby("host")["ja4"].transform("size")
    hs = d["host"] + "|" + d["stack"]
    stack_n = d.groupby(hs)["ja4"].transform("size")
    out["hr_host_n_conns"] = np.log1p(host_n)
    for c in HR_BASE:
        x = d[c].astype(float)
        out[f"hr_z_host_{c}"] = _robust_z(x, d["host"]).clip(-50, 50)
        out[f"hr_rank_host_{c}"] = x.groupby(d["host"]).rank(pct=True)
        zs = _robust_z(x, hs).clip(-50, 50)
        out[f"hr_z_stack_{c}"] = zs.where(stack_n >= min_stack, out[f"hr_z_host_{c}"])
    # stack context
    out["hr_stack_share"] = stack_n / host_n
    out["hr_stack_n_dests"] = d.groupby(hs)["dest"].transform("nunique")
    out["hr_host_n_stacks"] = d.groupby("host")["stack"].transform("nunique")
    # destination context inside the host
    hd = d["host"] + "|" + d["dest"]
    dest_n = d.groupby(hd)["ja4"].transform("size")
    out["hr_dest_share"] = dest_n / host_n
    out["hr_dest_n_conns"] = np.log1p(dest_n)
    out["hr_dest_n_stacks"] = d.groupby(hd)["stack"].transform("nunique")
    t = d["t_clienthello"].astype(float)
    t0 = t.groupby(d["host"]).transform("min")
    t1 = t.groupby(d["host"]).transform("max")
    span = (t1 - t0).clip(lower=1.0)
    first_dest = t.groupby(hd).transform("min")
    out["hr_dest_first_seen_frac"] = (first_dest - t0) / span
    out["hr_conn_time_frac"] = (t - t0) / span
    srv = d["host"] + "|" + d["server_ip"].astype(str)
    out["hr_srv_n_dests"] = d.groupby(srv)["dest"].transform("nunique")
    # beaconing per (host, dest)
    beacon = {}
    for key, g in d.groupby(hd):
        ts = np.sort(g["t_clienthello"].astype(float).values)
        if len(ts) >= 3:
            gaps = np.diff(ts)
            med = float(np.median(gaps))
            cv = float(np.std(gaps) / (np.mean(gaps) + 1e-9))
            per = float(np.mean(np.abs(gaps - med) <= 0.1 * med + 0.5)) if med > 0 else 0.0
            beacon[key] = (np.log1p(med), cv, per)
        else:
            beacon[key] = (-1.0, -1.0, 0.0)
    b = hd.map(beacon)
    out["hr_beacon_log_med_gap"] = b.map(lambda v: v[0])
    out["hr_beacon_cv_gap"] = b.map(lambda v: v[1])
    out["hr_beacon_periodicity"] = b.map(lambda v: v[2])
    # client SYN against the host's own usual SYN: the OS and path are shared by
    # every connection of the host, so a deviation reflects the application's
    # socket settings, not the lab
    for c in ("env_c_win", "env_c_ws", "env_c_mss", "env_c_iplen", "env_c_ttl0"):
        if c in d:
            v = d[c].fillna(-1)
            mode = v.groupby(d["host"]).transform(lambda s: s.value_counts().index[0])
            out[f"hr_syn_dev_{c[6:]}"] = (v != mode).astype(int)
            out[f"hr_syn_share_{c[6:]}"] = v.groupby([d["host"], v]).transform("size") / host_n
    # server-side rarity on this host
    if "ja4s" in d:
        js = d["host"] + "|" + d["ja4s"].fillna("")
        out["hr_ja4s_share"] = d.groupby(js)["ja4"].transform("size") / host_n
    if "cert_validity_days" in d:
        cv_ = d["cert_validity_days"].astype(float)
        out["hr_z_host_cert_validity"] = _robust_z(cv_.fillna(-1), d["host"]).clip(-50, 50)
    return out


def tls_tokens(df: pd.DataFrame) -> pd.DataFrame:
    """Per-element ClientHello tokens (binary) + counts + prefix fields."""
    toks = {}
    for col, pre in (("ch_ciphers", "c_"), ("ch_exts", "e_"), ("ch_sigalgs", "s_"), ("ch_groups", "g_")):
        for i, s in enumerate(df[col].fillna("")):
            for t in s.split():
                toks.setdefault(pre + t, {})[i] = 1
    m = pd.DataFrame({k: pd.Series(v) for k, v in toks.items()}, index=range(len(df))).fillna(0).astype(np.int8)
    m.index = df.index
    pre = df["ja4"].str.split("_").str[0]
    m["tls_ver"] = pre.str[1:3].map({"13": 13, "12": 12, "11": 11, "10": 10}).fillna(0)
    m["tls_n_ciphers"] = pd.to_numeric(pre.str[4:6], errors="coerce").fillna(0)
    m["tls_n_exts"] = pd.to_numeric(pre.str[6:8], errors="coerce").fillna(0)
    m["tls_alpn_h2"] = (pre.str[8:10] == "h2").astype(int)
    m["tls_alpn_none"] = (pre.str[8:10] == "00").astype(int)
    m["tls_n_sigalgs"] = df["ch_sigalgs"].fillna("").str.split().str.len()
    return m


def srv_features(df: pd.DataFrame) -> pd.DataFrame:
    s = pd.DataFrame(index=df.index)
    js = df["ja4s"].fillna("")
    s["srv_ver"] = js.str[1:3].map({"13": 13, "12": 12, "11": 11, "10": 10}).fillna(0)
    s["srv_n_exts"] = pd.to_numeric(js.str[3:5], errors="coerce").fillna(-1)
    ciph = js.str.split("_").str[1].fillna("")
    for c in ciph.value_counts().index[:30]:
        if c:
            s[f"srv_cipher_{c}"] = (ciph == c).astype(int)
    for c in ("cert_present", "cert_validity_days", "cert_self_signed", "cert_n_san", "cert_chain_len"):
        s[c] = df[c].astype(float).fillna(-1) if c in df else -1
    if "cert_not_before" in df:
        s["cert_age_days"] = ((df["t_clienthello"] - df["cert_not_before"]) / 86400).fillna(-1)
    return s


# Host-relative columns are split three ways so each claim can be tested alone:
#   HRb  relative BEHAVIOUR (z-scores / ranks inside host and host x JA4 stack, SYN deviation):
#        the core method; cancels anything constant within a host
#   HRd  destination / server / beacon CONTEXT inside the host: useful, but partly mirrors how
#        IOC labels are made (malicious destinations are rare by construction) -> reported apart
#   POS  position inside the capture: audit only (infections often start early in a capture),
#        never part of a proposed model
POS_COLS = ["hr_conn_time_frac", "hr_dest_first_seen_frac"]


def split_hr(hr: pd.DataFrame) -> dict[str, pd.DataFrame]:
    b = [c for c in hr if c.startswith(("hr_z_host_b", "hr_z_host_d", "hr_z_host_n", "hr_rank_", "hr_z_stack_", "hr_syn_"))]
    pos = [c for c in POS_COLS if c in hr]
    dctx = [c for c in hr if c not in b and c not in pos]
    return {"HRb": hr[b], "HRd": hr[dctx], "POS": hr[pos]}


def per_source_standardised(df: pd.DataFrame) -> pd.DataFrame:
    """Domain-generalisation strawman (AdaBN-like): z-score BEH within each source."""
    x = df[[c for c in BEH_COLS if c in df]].astype(float).fillna(-1)
    g = df["source"]
    return ((x - x.groupby(g).transform("mean")) / (x.groupby(g).transform("std") + 1e-6)).add_prefix("srcz_")


def unsupervised_stack_outlier(hrb: pd.DataFrame) -> pd.Series:
    """Label-free score: how far a connection sits from its own host x JA4 peers
    (mean absolute robust z over behaviour). 'Mimicry as a control'."""
    z = hrb[[c for c in hrb if c.startswith("hr_z_stack_")]].abs()
    return z.mean(axis=1)


def build(df: pd.DataFrame) -> dict[str, pd.DataFrame]:
    hr = host_relative(df).astype(float).fillna(-1)
    fam = {
        "ENV": df[[c for c in ENV_COLS if c in df]].astype(float).fillna(-1),
        "TLS": tls_tokens(df),
        "BEH": df[[c for c in BEH_COLS if c in df]].astype(float).fillna(-1),
        "SRV": srv_features(df),
        "BEHsrc": per_source_standardised(df),
    }
    fam.update(split_hr(hr))
    return fam
