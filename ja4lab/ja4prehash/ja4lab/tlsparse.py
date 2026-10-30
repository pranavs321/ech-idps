"""
Parsing of TLS ClientHello / ServerHello, HTTP/1.x requests and TCP SYN options,
plus computation of JA4, JA4S, JA4H, JA4T/JA4TS *and* their raw (pre-hash) components.

Why our own parser instead of only calling a fingerprint library?
  * The research question is about the PRE-HASH components, so we need every list
    (ciphers, extensions, sig-algs, groups, key-shares ...) in wire order, not just the hash.
  * We also keep fields that JA4 throws away (supported groups, point formats, key-share
    groups, PSK modes, cert-compression...). This lets us test "does the information
    discarded by the hash matter?" as an ablation.

Spec reference: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details
JA4 (TLS client) is BSD-3. JA4S/JA4H/JA4T are FoxIO License 1.1 (academic use is permitted).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict

# ----------------------------------------------------------------------------- helpers

def is_grease(v: int) -> bool:
    """GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa (RFC 8701)."""
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def h4(v: int) -> str:
    return f"{v:04x}"


def sha12(s: str) -> str:
    return hashlib.sha256(s.encode("utf8")).hexdigest()[:12]


TLS_VERSION_MAP = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
    0x0300: "s3", 0x0002: "s2", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}


def _alnum(b: int) -> bool:
    return 0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A


def alpn_code(first_alpn: bytes | None) -> str:
    """First+last char of the first ALPN value (JA4 spec, incl. the non-alphanumeric hex rule)."""
    if not first_alpn:
        return "00"
    a, z = first_alpn[0], first_alpn[-1]
    if _alnum(a) and _alnum(z):
        return chr(a) + chr(z)
    hx = first_alpn.hex()
    return hx[0] + hx[-1]


class _R:
    """Tiny bounds-checked byte reader. Raises ValueError on truncation."""

    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def left(self) -> int:
        return len(self.b) - self.i

    def take(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.b):
            raise ValueError("truncated")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")


def _u16_list(b: bytes) -> list[int]:
    return [int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b) - 1, 2)]


# ----------------------------------------------------------------------------- ClientHello

@dataclass
class ClientHello:
    legacy_version: int = 0
    session_id_len: int = 0
    ciphers: list[int] = field(default_factory=list)          # wire order, incl. GREASE
    compression: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)       # wire order, incl. GREASE
    sni: str = ""
    alpn: list[bytes] = field(default_factory=list)
    sig_algs: list[int] = field(default_factory=list)         # ext 0x000d only, wire order
    sig_algs_cert: list[int] = field(default_factory=list)    # ext 0x0032
    supported_versions: list[int] = field(default_factory=list)
    groups: list[int] = field(default_factory=list)           # ext 0x000a
    ec_point_formats: list[int] = field(default_factory=list) # ext 0x000b
    key_share_groups: list[int] = field(default_factory=list) # ext 0x0033
    psk_modes: list[int] = field(default_factory=list)        # ext 0x002d
    cert_compression: list[int] = field(default_factory=list) # ext 0x001b
    record_size_limit: int = -1                               # ext 0x001c
    padding_len: int = -1                                     # ext 0x0015
    has_ech: bool = False                                     # ext 0xfe0d
    has_psk: bool = False                                     # ext 0x0029
    has_early_data: bool = False                              # ext 0x002a
    hello_len: int = 0


def parse_client_hello(body: bytes) -> ClientHello:
    """body = handshake message body (after the 4-byte handshake header)."""
    r = _R(body)
    ch = ClientHello(hello_len=len(body))
    ch.legacy_version = r.u16()
    r.take(32)
    ch.session_id_len = r.u8()
    r.take(ch.session_id_len)
    ch.ciphers = _u16_list(r.take(r.u16()))
    ch.compression = list(r.take(r.u8()))
    if r.left() < 2:
        return ch
    er = _R(r.take(r.u16()))
    while er.left() >= 4:
        et, el = er.u16(), er.u16()
        data = er.take(el)
        ch.extensions.append(et)
        try:
            _parse_ch_ext(ch, et, data)
        except ValueError:
            pass  # malformed extension body: keep the type, skip the content
    return ch


def _parse_ch_ext(ch: ClientHello, et: int, d: bytes) -> None:
    x = _R(d)
    if et == 0x0000 and len(d) >= 5:          # server_name
        x.u16(); x.u8(); ch.sni = x.take(x.u16()).decode("utf8", "replace")
    elif et == 0x0010 and len(d) >= 2:        # ALPN
        lr = _R(x.take(x.u16()))
        while lr.left() >= 1:
            ch.alpn.append(lr.take(lr.u8()))
    elif et == 0x000D and len(d) >= 2:
        ch.sig_algs = _u16_list(x.take(x.u16()))
    elif et == 0x0032 and len(d) >= 2:
        ch.sig_algs_cert = _u16_list(x.take(x.u16()))
    elif et == 0x002B and len(d) >= 1:
        ch.supported_versions = _u16_list(x.take(x.u8()))
    elif et == 0x000A and len(d) >= 2:
        ch.groups = _u16_list(x.take(x.u16()))
    elif et == 0x000B and len(d) >= 1:
        ch.ec_point_formats = list(x.take(x.u8()))
    elif et == 0x0033 and len(d) >= 2:
        kr = _R(x.take(x.u16()))
        while kr.left() >= 4:
            g = kr.u16(); kr.take(kr.u16()); ch.key_share_groups.append(g)
    elif et == 0x002D and len(d) >= 1:
        ch.psk_modes = list(x.take(x.u8()))
    elif et == 0x001B and len(d) >= 1:
        ch.cert_compression = _u16_list(x.take(x.u8()))
    elif et == 0x001C and len(d) >= 2:
        ch.record_size_limit = x.u16()
    elif et == 0x0015:
        ch.padding_len = len(d)
    elif et == 0xFE0D:
        ch.has_ech = True
    elif et == 0x0029:
        ch.has_psk = True
    elif et == 0x002A:
        ch.has_early_data = True


def ja4_from_ch(ch: ClientHello, proto: str = "t") -> dict:
    """Returns JA4, JA4_r (sorted raw), JA4_o (original-order hash), JA4_ro (original raw)."""
    sv = [v for v in ch.supported_versions if not is_grease(v)]
    ver = max(sv) if sv else ch.legacy_version
    ver_s = TLS_VERSION_MAP.get(ver, "00")
    sni = "d" if 0x0000 in ch.extensions else "i"
    ciphers = [c for c in ch.ciphers if not is_grease(c)]
    exts = [e for e in ch.extensions if not is_grease(e)]
    nc, ne = f"{min(len(ciphers), 99):02d}", f"{min(len(exts), 99):02d}"
    alpn = alpn_code(ch.alpn[0] if ch.alpn else None)
    a = f"{proto}{ver_s}{sni}{nc}{ne}{alpn}"

    sigs = [s for s in ch.sig_algs if not is_grease(s)]
    c_sorted = ",".join(sorted(h4(c) for c in ciphers))
    c_orig = ",".join(h4(c) for c in ciphers)
    e_sorted = ",".join(sorted(h4(e) for e in exts if e not in (0x0000, 0x0010)))
    e_orig = ",".join(h4(e) for e in exts)   # original rendering keeps SNI/ALPN (FoxIO -o)
    sig_s = ",".join(h4(s) for s in sigs)

    def _c(s): return s + (("_" + sig_s) if sig_s else "")
    b_s = sha12(c_sorted) if ciphers else "000000000000"
    b_o = sha12(c_orig) if ciphers else "000000000000"
    c_s = sha12(_c(e_sorted)) if e_sorted else "000000000000"
    c_o = sha12(_c(e_orig)) if e_orig else "000000000000"
    return {
        "ja4": f"{a}_{b_s}_{c_s}",
        "ja4_o": f"{a}_{b_o}_{c_o}",
        "ja4_r": f"{a}_{c_sorted}_{_c(e_sorted)}",
        "ja4_ro": f"{a}_{c_orig}_{_c(e_orig)}",
        "ja4_a": a, "ja4_b": b_s, "ja4_c": c_s,
    }


def ja3_from_ch(ch: ClientHello) -> dict:
    """JA3 (Salesforce) for comparison with the earlier JA3 study. Uses decimal values, GREASE removed."""
    ng = lambda v: [x for x in v if not is_grease(x)]
    s = ",".join([str(ch.legacy_version),
                  "-".join(str(x) for x in ng(ch.ciphers)),
                  "-".join(str(x) for x in ng(ch.extensions)),
                  "-".join(str(x) for x in ng(ch.groups)),
                  "-".join(str(x) for x in ch.ec_point_formats)])
    return {"ja3": hashlib.md5(s.encode()).hexdigest(), "ja3_r": s}


# ----------------------------------------------------------------------------- ServerHello

HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


@dataclass
class ServerHello:
    legacy_version: int = 0
    cipher: int = -1
    extensions: list[int] = field(default_factory=list)
    supported_version: int = -1
    alpn: bytes = b""
    key_share_group: int = -1
    is_hrr: bool = False


def parse_server_hello(body: bytes) -> ServerHello:
    r = _R(body)
    sh = ServerHello()
    sh.legacy_version = r.u16()
    sh.is_hrr = r.take(32) == HRR_RANDOM
    r.take(r.u8())
    sh.cipher = r.u16()
    r.u8()
    if r.left() < 2:
        return sh
    er = _R(r.take(r.u16()))
    while er.left() >= 4:
        et, el = er.u16(), er.u16()
        d = er.take(el)
        sh.extensions.append(et)
        try:
            if et == 0x002B and len(d) >= 2:
                sh.supported_version = int.from_bytes(d[:2], "big")
            elif et == 0x0010 and len(d) >= 3:
                x = _R(d); x.u16(); sh.alpn = x.take(x.u8())
            elif et == 0x0033 and len(d) >= 2:
                sh.key_share_group = int.from_bytes(d[:2], "big")
        except ValueError:
            pass
    return sh


def ja4s_from_sh(sh: ServerHello, proto: str = "t") -> dict:
    ver = sh.supported_version if sh.supported_version > 0 else sh.legacy_version
    ver_s = TLS_VERSION_MAP.get(ver, "00")
    ne = f"{min(len(sh.extensions), 99):02d}"
    alpn = alpn_code(sh.alpn or None)
    e = ",".join(h4(x) for x in sh.extensions)
    a = f"{proto}{ver_s}{ne}{alpn}"
    return {
        "ja4s": f"{a}_{h4(sh.cipher)}_{sha12(e) if e else '000000000000'}",
        "ja4s_r": f"{a}_{h4(sh.cipher)}_{e}",
    }


# ----------------------------------------------------------------------------- JA4T / JA4TS

def tcp_option_summary(opts: bytes) -> tuple[list[int], int, int]:
    kinds, mss, ws, i = [], None, None, 0
    while i < len(opts):
        k = opts[i]
        if k in (0, 1):
            kinds.append(k); i += 1; continue
        if i + 1 >= len(opts):
            break
        ln = opts[i + 1]
        if ln < 2 or i + ln > len(opts):
            break
        kinds.append(k)
        if k == 2 and ln == 4 and mss is None:
            mss = int.from_bytes(opts[i + 2:i + 4], "big")
        elif k == 3 and ln == 3 and ws is None:
            ws = opts[i + 2]
        i += ln
    return kinds, mss or 0, ws or 0


def ja4t(window: int, opts: bytes) -> dict:
    kinds, mss, ws = tcp_option_summary(opts)
    kb = "-".join(str(k) for k in kinds) if kinds else "00"
    return {"fp": f"{window}_{kb}_{mss:02d}_{'00' if ws == 0 else ws}",
            "window": window, "options": kb, "mss": mss, "wscale": ws}


# ----------------------------------------------------------------------------- JA4H

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
                b"PATCH ", b"CONNECT ", b"TRACE ")


def looks_like_http_request(b: bytes) -> bool:
    return b.startswith(HTTP_METHODS)


def ja4h_from_request(raw: bytes) -> dict | None:
    end = raw.find(b"\r\n\r\n")
    if end < 0:
        return None
    lines = raw[:end].decode("latin1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 3:
        return None
    method, version = parts[0], parts[-1]
    ver = version.split("/")[-1].replace(".", "") if "/" in version else "11"
    ver = ver[:2] if ver else "11"
    names, cookies, referer, lang = [], [], False, None
    for ln in lines[1:]:
        if ":" not in ln:
            continue
        n, v = ln.split(":", 1)
        nl = n.strip().lower()
        if nl == "cookie":
            cookies += [c.strip() for c in v.split(";") if c.strip()]
            continue
        if nl == "referer":
            referer = True
            continue
        if nl == "accept-language":
            lang = v.strip()
        names.append(n.strip())
    if lang:
        lg = lang.replace("-", "").replace(";", ",").lower().split(",")[0][:4]
        lg = lg + "0" * (4 - len(lg))
    else:
        lg = "0000"
    a = (f"{method.lower()[:2]}{ver}{'c' if cookies else 'n'}{'r' if referer else 'n'}"
         f"{min(len(names), 99):02d}{lg}")
    pairs = sorted(((c.split("=", 1)[0].strip(), c) for c in cookies), key=lambda p: p[0])
    cf = sha12(",".join(p[0] for p in pairs)) if cookies else "0" * 12
    cv = sha12(",".join(p[1] for p in pairs)) if cookies else "0" * 12
    return {
        "ja4h": f"{a}_{sha12(','.join(names))}_{cf}_{cv}",
        "ja4h_r": f"{a}_{','.join(names)}_",
        "http_method": method, "http_headers": ",".join(names),
    }


# ----------------------------------------------------------------------------- serialise

def lst(v: list[int]) -> str:
    """Store int lists as '-'-joined 4-hex strings (CSV friendly, order preserved)."""
    return "-".join(h4(x) for x in v)


def ch_to_row(ch: ClientHello) -> dict:
    d = {
        "ch_legacy_version": h4(ch.legacy_version),
        "ch_session_id_len": ch.session_id_len,
        "ch_ciphers": lst(ch.ciphers),
        "ch_compression": "-".join(str(c) for c in ch.compression),
        "ch_extensions": lst(ch.extensions),
        "ch_sig_algs": lst(ch.sig_algs),
        "ch_sig_algs_cert": lst(ch.sig_algs_cert),
        "ch_supported_versions": lst(ch.supported_versions),
        "ch_groups": lst(ch.groups),
        "ch_ec_point_formats": "-".join(str(c) for c in ch.ec_point_formats),
        "ch_key_share_groups": lst(ch.key_share_groups),
        "ch_psk_modes": "-".join(str(c) for c in ch.psk_modes),
        "ch_cert_compression": lst(ch.cert_compression),
        "ch_alpn": ",".join(a.decode("latin1") for a in ch.alpn),
        "ch_record_size_limit": ch.record_size_limit,
        "ch_padding_len": ch.padding_len,
        "ch_has_ech": int(ch.has_ech),
        "ch_has_psk": int(ch.has_psk),
        "ch_has_early_data": int(ch.has_early_data),
        "ch_len": ch.hello_len,
        "sni": ch.sni,
    }
    return d


def sh_to_row(sh: ServerHello) -> dict:
    return {
        "sh_legacy_version": h4(sh.legacy_version),
        "sh_cipher": h4(sh.cipher) if sh.cipher >= 0 else "",
        "sh_extensions": lst(sh.extensions),
        "sh_supported_version": h4(sh.supported_version) if sh.supported_version > 0 else "",
        "sh_alpn": sh.alpn.decode("latin1"),
        "sh_key_share_group": h4(sh.key_share_group) if sh.key_share_group >= 0 else "",
        "sh_is_hrr": int(sh.is_hrr),
    }
