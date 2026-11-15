"""PCAP -> one row per TLS-over-TCP connection.

One tshark pass per pcap (tshark >= 4.2). JA4, JA4S, JA4T and JA4TS are
computed here from the raw handshake fields following the FoxIO
specification (https://github.com/FoxIO-LLC/ja4), so the same code runs on
any tshark version. tshark's own `tls.handshake.ja4` is kept beside it as a
cross-check (`ja4_tshark`).

Behaviour features are computed on TLS application-data packets only
(content type 23), i.e. after the handshake, so they describe what the
connection did, not how it was set up.

Usage:
    python -I -m ja4next.extract <pcap> <out.parquet> [--source NAME] [--capture-id ID]
"""
from __future__ import annotations

import argparse
import hashlib
import math
import subprocess
import sys
from collections import defaultdict
from statistics import median

import warnings
import numpy as np
warnings.filterwarnings("ignore")
import pandas as pd

FIELDS = [
    "frame.time_epoch", "tcp.stream",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.len",
    "ip.ttl", "ipv6.hlim", "ip.len", "ipv6.plen", "ip.flags.df",
    "tcp.window_size_value", "tcp.option_kind", "tcp.options.mss_val",
    "tcp.options.wscale.shift",
    "tls.record.content_type", "tls.handshake.type", "tls.handshake.version",
    "tls.handshake.ciphersuite", "tls.handshake.extension.type",
    "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str",
    "tls.handshake.sig_hash_alg", "tls.handshake.sig_hash_alg_len",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.extensions_supported_group",
    "tls.handshake.ja4", "tls.handshake.certificate",
]
IDX = {f: i for i, f in enumerate(FIELDS)}

TLS_VER = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
           0x0300: "s3", 0x0002: "s2", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}


def is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def _ints(s: str, base: int) -> list[int]:
    out = []
    for t in s.split(","):
        t = t.strip()
        if not t:
            continue
        try:
            out.append(int(t, base))
        except ValueError:
            pass
    return out


def _sha12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _alpn2(alpn: str) -> str:
    if not alpn:
        return "00"
    first = alpn.split(",")[0]
    if not first:
        return "00"
    a, b = first[0], first[-1]
    if a.isascii() and a.isalnum() and b.isascii() and b.isalnum():
        return a + b
    hx = first.encode("utf-8", "surrogateescape").hex()
    return hx[0] + hx[-1]


SIGLIST_EXTS = (13, 34, 50)  # signature_algorithms, delegated_credentials, signature_algorithms_cert


def _sigalgs_ext13(exts: str, sigalgs: str, sig_lens: str) -> list[int]:
    """tshark aggregates every signature-algorithm list in the ClientHello into
    one field; keep only the list that belongs to extension 13."""
    allv = _ints(sigalgs, 16)
    lens = _ints(sig_lens, 10)
    order = [x for x in _ints(exts, 10) if x in SIGLIST_EXTS]
    if not lens or len(lens) != len(order) or 13 not in order:
        return allv if order == [13] or not order else []
    pos = 0
    for ext, ln in zip(order, lens):
        n = ln // 2
        if ext == 13:
            return allv[pos:pos + n]
        pos += n
    return []


def ja4_from_raw(ver_hs: str, sup_versions: str, ciphers: str, exts: str,
                 sigalgs: str, alpn: str, proto: str = "t", sig_lens: str = "") -> tuple[str, str, dict]:
    """Return (ja4, ja4_r, elements) from tshark field strings."""
    c = [x for x in _ints(ciphers, 16) if not is_grease(x)]
    e = [x for x in _ints(exts, 10) if not is_grease(x)]
    sv = [x for x in _ints(sup_versions, 16) if not is_grease(x)]
    s = [x for x in _sigalgs_ext13(exts, sigalgs, sig_lens) if not is_grease(x)]
    if sv:
        ver = TLS_VER.get(max(sv), "00")
    else:
        hv = _ints(ver_hs, 16)
        ver = TLS_VER.get(hv[0], "00") if hv else "00"
    sni = "d" if 0 in e else "i"
    nc, ne = min(len(c), 99), min(len(e), 99)
    a = f"{proto}{ver}{sni}{nc:02d}{ne:02d}{_alpn2(alpn)}"
    cs = ",".join(f"{x:04x}" for x in sorted(c))
    es = ",".join(f"{x:04x}" for x in sorted(x for x in e if x not in (0, 16)))
    ss = ",".join(f"{x:04x}" for x in s)
    b = _sha12(cs) if c else "000000000000"
    cpart = es + ("_" + ss if ss else "")
    cc = _sha12(cpart) if cpart else "000000000000"
    elements = {"ciphers": [f"{x:04x}" for x in c], "exts": [f"{x:04x}" for x in e],
                "sigalgs": [f"{x:04x}" for x in s]}
    return f"{a}_{b}_{cc}", f"{a}_{cs}_{cpart}", elements


def ja4s_from_raw(ver_hs: str, sup_versions: str, cipher: str, exts: str,
                  alpn: str, proto: str = "t") -> tuple[str, str]:
    e = _ints(exts, 10)
    sv = [x for x in _ints(sup_versions, 16) if not is_grease(x)]
    if sv:
        ver = TLS_VER.get(max(sv), "00")
    else:
        hv = _ints(ver_hs, 16)
        ver = TLS_VER.get(hv[0], "00") if hv else "00"
    cl = _ints(cipher, 16)
    ch = f"{cl[0]:04x}" if cl else "0000"
    a = f"{proto}{ver}{min(len(e), 99):02d}{_alpn2(alpn)}"
    es = ",".join(f"{x:04x}" for x in e)
    return f"{a}_{ch}_{_sha12(es) if e else '000000000000'}", f"{a}_{ch}_{es}"


def ja4t_from_raw(win: str, opts: str, mss: str, ws: str) -> str:
    ok = [str(x) for x in _ints(opts, 10)]
    return f"{win or 0}_{'-'.join(ok) if ok else '00'}_{(mss.split(',')[0] if mss else '00')}_{(ws.split(',')[0] if ws else '00')}"


def _initial_ttl(ttl: int) -> int:
    for t in (32, 64, 128, 255):
        if ttl <= t:
            return t
    return 255


def _cert_features(hexcerts: str) -> dict:
    """Leaf-certificate features (TLS <= 1.2 only; TLS 1.3 certs are encrypted)."""
    out = {"cert_present": 0}
    if not hexcerts:
        return out
    try:
        from cryptography import x509
        leaf_hex = hexcerts.split(",")[0].replace(":", "")
        der = bytes.fromhex(leaf_hex)
        cert = x509.load_der_x509_certificate(der)
        nb = cert.not_valid_before_utc.timestamp() if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.timestamp()
        na = cert.not_valid_after_utc.timestamp() if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.timestamp()
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            n_san = len(san.get_values_for_type(x509.DNSName))
        except Exception:
            n_san = 0
        n_chain = len(hexcerts.split(","))
        out.update({
            "cert_present": 1,
            "cert_validity_days": (na - nb) / 86400.0,
            "cert_not_before": nb,
            "cert_self_signed": int(issuer == subject),
            "cert_n_san": n_san,
            "cert_chain_len": n_chain,
            "cert_issuer": issuer[:200],
            "cert_sha1": hashlib.sha1(der).hexdigest(),
        })
    except Exception:
        out["cert_parse_error"] = 1
    return out


def run_tshark(pcap: str) -> list[list[str]]:
    cmd = ["tshark", "-r", pcap, "-n", "-Y", "tcp",
           "-o", "tcp.desegment_tcp_streams:TRUE",
           "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
           "-E", "aggregator=,", "-E", "quote=n"]
    for f in FIELDS:
        cmd += ["-e", f]
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    rows = []
    for line in p.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < len(FIELDS):
            parts += [""] * (len(FIELDS) - len(parts))
        rows.append(parts)
    return rows


def _fnum(x, default=0.0):
    try:
        return float(x.split(",")[0])
    except Exception:
        return default


def extract(pcap: str, source: str = "", capture_id: str = "") -> pd.DataFrame:
    rows = run_tshark(pcap)
    by_stream: dict[str, list[list[str]]] = defaultdict(list)
    for r in rows:
        st = r[IDX["tcp.stream"]]
        if st:
            by_stream[st].append(r)

    out = []
    for st, pk in by_stream.items():
        ch = next((r for r in pk if "1" in r[IDX["tls.handshake.type"]].split(",")), None)
        if ch is None:
            continue  # only connections with a ClientHello
        g = lambda r, f: r[IDX[f]]
        cli = (g(ch, "ip.src") or g(ch, "ipv6.src"), g(ch, "tcp.srcport"))
        srv = (g(ch, "ip.dst") or g(ch, "ipv6.dst"), g(ch, "tcp.dstport"))
        ja4, ja4_r, el = ja4_from_raw(g(ch, "tls.handshake.version"),
                                      g(ch, "tls.handshake.extensions.supported_version"),
                                      g(ch, "tls.handshake.ciphersuite"),
                                      g(ch, "tls.handshake.extension.type"),
                                      g(ch, "tls.handshake.sig_hash_alg"),
                                      g(ch, "tls.handshake.extensions_alpn_str"),
                                      sig_lens=g(ch, "tls.handshake.sig_hash_alg_len"))
        rec = {
            "source": source, "capture_id": capture_id, "stream": int(st),
            "client_ip": cli[0], "client_port": int(cli[1] or 0),
            "server_ip": srv[0], "server_port": int(srv[1] or 0),
            "sni": g(ch, "tls.handshake.extensions_server_name").split(",")[0],
            "alpn": g(ch, "tls.handshake.extensions_alpn_str"),
            "ja4": ja4, "ja4_r": ja4_r, "ja4_tshark": g(ch, "tls.handshake.ja4").split(",")[0],
            "ch_ciphers": " ".join(el["ciphers"]), "ch_exts": " ".join(el["exts"]),
            "ch_sigalgs": " ".join(el["sigalgs"]),
            "ch_groups": " ".join(f"{x:04x}" for x in _ints(g(ch, "tls.handshake.extensions_supported_group"), 16) if not is_grease(x)),
            "t_clienthello": float(g(ch, "frame.time_epoch")),
        }
        sh = next((r for r in pk if "2" in r[IDX["tls.handshake.type"]].split(",")
                   and (g(r, "ip.src") or g(r, "ipv6.src")) == srv[0]), None)
        if sh is not None:
            hs_types = g(sh, "tls.handshake.type").split(",")
            # ServerHello is the first handshake message in its packet; extension
            # types listed before any later message belong to it.
            rec["ja4s"], rec["ja4s_r"] = ja4s_from_raw(
                g(sh, "tls.handshake.version").split(",")[0],
                g(sh, "tls.handshake.extensions.supported_version"),
                g(sh, "tls.handshake.ciphersuite"),
                g(sh, "tls.handshake.extension.type"),
                g(sh, "tls.handshake.extensions_alpn_str"))
        else:
            rec["ja4s"] = rec["ja4s_r"] = ""
        cert_pkt = next((r for r in pk if g(r, "tls.handshake.certificate")
                         and (g(r, "ip.src") or g(r, "ipv6.src")) == srv[0]), None)
        rec.update(_cert_features(g(cert_pkt, "tls.handshake.certificate") if cert_pkt else ""))

        # TCP handshake: JA4T / JA4TS and environment fields
        syn = next((r for r in pk if g(r, "tcp.flags") and int(g(r, "tcp.flags"), 16) & 0x12 == 0x02), None)
        synack = next((r for r in pk if g(r, "tcp.flags") and int(g(r, "tcp.flags"), 16) & 0x12 == 0x12), None)
        if syn is not None:
            ttl = int(_fnum(g(syn, "ip.ttl") or g(syn, "ipv6.hlim")))
            rec.update({"ja4t": ja4t_from_raw(g(syn, "tcp.window_size_value"), g(syn, "tcp.option_kind"),
                                              g(syn, "tcp.options.mss_val"), g(syn, "tcp.options.wscale.shift")),
                        "env_c_win": _fnum(g(syn, "tcp.window_size_value")),
                        "env_c_mss": _fnum(g(syn, "tcp.options.mss_val"), -1),
                        "env_c_ws": _fnum(g(syn, "tcp.options.wscale.shift"), -1),
                        "env_c_iplen": _fnum(g(syn, "ip.len") or g(syn, "ipv6.plen")),
                        "env_c_df": _fnum(g(syn, "ip.flags.df"), -1),
                        "env_c_ttl0": _initial_ttl(ttl), "t_syn": float(g(syn, "frame.time_epoch"))})
        if synack is not None:
            ttl = int(_fnum(g(synack, "ip.ttl") or g(synack, "ipv6.hlim")))
            rec.update({"ja4ts": ja4t_from_raw(g(synack, "tcp.window_size_value"), g(synack, "tcp.option_kind"),
                                               g(synack, "tcp.options.mss_val"), g(synack, "tcp.options.wscale.shift")),
                        "env_s_win": _fnum(g(synack, "tcp.window_size_value")),
                        "env_s_mss": _fnum(g(synack, "tcp.options.mss_val"), -1),
                        "env_s_ws": _fnum(g(synack, "tcp.options.wscale.shift"), -1),
                        "env_s_iplen": _fnum(g(synack, "ip.len") or g(synack, "ipv6.plen")),
                        "env_s_df": _fnum(g(synack, "ip.flags.df"), -1),
                        "env_s_ttl0": _initial_ttl(ttl), "t_synack": float(g(synack, "frame.time_epoch"))})
        if syn is not None and synack is not None:
            rec["rtt"] = max(rec["t_synack"] - rec["t_syn"], 1e-4)

        # Behaviour: application-data packets only (TLS content type 23)
        ups, downs, seq, times = [], [], [], []
        for r in pk:
            ct = g(r, "tls.record.content_type")
            tl = int(_fnum(g(r, "tcp.len")))
            if tl <= 0 or "23" not in ct.split(","):
                continue
            src = g(r, "ip.src") or g(r, "ipv6.src")
            up = src == cli[0] and g(r, "tcp.srcport") == cli[1]
            (ups if up else downs).append(tl)
            seq.append(tl if up else -tl)
            times.append(float(g(r, "frame.time_epoch")))
        allt = [float(g(r, "frame.time_epoch")) for r in pk]
        rec["duration"] = (max(allt) - min(allt)) if allt else 0.0
        rec["n_pkts_total"] = len(pk)
        rec["closed_fin"] = int(any(g(r, "tcp.flags") and int(g(r, "tcp.flags"), 16) & 0x01 for r in pk))
        rec["closed_rst"] = int(any(g(r, "tcp.flags") and int(g(r, "tcp.flags"), 16) & 0x04 for r in pk))
        bu, bd = sum(ups), sum(downs)
        n = len(seq)
        rec.update({
            "b_n_up": len(ups), "b_n_down": len(downs),
            "b_bytes_up": bu, "b_bytes_down": bd,
            "b_byte_ratio": bu / (bu + bd) if (bu + bd) else 0.5,
            "b_up_frac": len(ups) / n if n else 0.5,
            "b_mean_up": float(np.mean(ups)) if ups else 0.0,
            "b_std_up": float(np.std(ups)) if ups else 0.0,
            "b_max_up": max(ups) if ups else 0,
            "b_mean_down": float(np.mean(downs)) if downs else 0.0,
            "b_std_down": float(np.std(downs)) if downs else 0.0,
            "b_max_down": max(downs) if downs else 0,
            "b_dir_changes": (sum(1 for i in range(1, n) if (seq[i] > 0) != (seq[i - 1] > 0)) / (n - 1)) if n > 1 else 0.0,
        })
        if len(times) > 2:
            gaps = np.diff(sorted(times))
            rtt = rec.get("rtt", 0.05)
            rec["b_med_gap_rtt"] = float(np.median(gaps)) / rtt
            rec["b_cv_gap"] = float(np.std(gaps) / (np.mean(gaps) + 1e-9))
        else:
            rec["b_med_gap_rtt"] = -1.0
            rec["b_cv_gap"] = -1.0
        for i in range(8):  # signed first-8 application-data packet lengths (SPLT style)
            rec[f"b_splt_{i}"] = seq[i] if i < n else 0
        out.append(rec)
    return pd.DataFrame(out)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("out")
    ap.add_argument("--source", default="")
    ap.add_argument("--capture-id", default="")
    a = ap.parse_args(argv)
    df = extract(a.pcap, a.source, a.capture_id)
    if a.out.endswith(".parquet"):
        df.to_parquet(a.out, index=False)
    else:
        df.to_csv(a.out, index=False)
    print(f"{a.pcap}: {len(df)} TLS connections", file=sys.stderr)


if __name__ == "__main__":
    main()
