"""
JA4 fingerprinting of the outer ClientHello, and structural similarity to
reference browser profiles.

Why this exists in an ECH-aware system
--------------------------------------
ECH encrypts the *inner* ClientHello, which is where the SNI lives. The outer
ClientHello is still a plain ClientHello on the wire: cipher suites, extension
list, supported groups, ALPN and GREASE placement are all observable. So a JA4
fingerprint remains computable post-ECH. What is lost is the destination, not
the fingerprint.

That is precisely the awkward position the project addresses: the one thing
still visible is the one thing uTLS and curl-impersonate forge byte-perfectly.
So this module does two jobs:

  1. compute JA4_a/b/c from the raw handshake bytes (Module 2's crypto path);
  2. score how structurally close the observed fingerprint is to the reference
     profile of the class it *claims* to be -- feature 13.

Feature 13 on its own is deliberately weak evidence. A spoofed beacon will
score ~1.0 here. Its value comes only from being read jointly with f1-f12 by
the dissonance statistic: a perfect browser fingerprint attached to robotic
physics is the signature the whole system hunts.

JA4 reference: Althouse et al., "JA4+ Network Fingerprinting", FoxIO 2023.
Format: JA4_a = (q|t)(version)(d|i)(nciphers)(nextensions)(alpn)
        JA4_b = first 12 hex of sha256 of the sorted cipher list
        JA4_c = first 12 hex of sha256 of sorted extensions + sig algs
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# GREASE values (RFC 8701). These must be stripped before hashing, otherwise
# the fingerprint changes on every connection.
GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_ALPN = 0x0010
EXT_SIG_ALGS = 0x000D
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_ECH = 0xFE0D  # encrypted_client_hello


@dataclass
class ClientHelloInfo:
    """Everything JA4 needs, parsed out of an outer ClientHello."""
    tls_version: int = 0x0303
    ciphers: List[int] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)
    sig_algs: List[int] = field(default_factory=list)
    alpn: Optional[str] = None
    has_sni: bool = False
    has_ech: bool = False
    transport: str = "t"  # 't' TCP, 'q' QUIC

    @property
    def effective_version(self) -> int:
        return self.tls_version


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("!H", buf, off)[0]


def parse_client_hello(data: bytes) -> Optional[ClientHelloInfo]:
    """
    Parse a TLS record containing a ClientHello. Returns None if the bytes are
    not a ClientHello -- the sensor calls this speculatively on the first
    packets of every flow, so a clean None is the common case.
    """
    try:
        if len(data) < 45:
            return None
        # TLS record header: type=0x16 handshake
        if data[0] != 0x16:
            return None
        off = 5
        if data[off] != 0x01:  # handshake type: client_hello
            return None
        off += 4                      # handshake type + 3-byte length
        info = ClientHelloInfo()
        info.tls_version = _u16(data, off)
        off += 2
        off += 32                     # random
        sid_len = data[off]
        off += 1 + sid_len            # legacy session id

        cs_len = _u16(data, off)
        off += 2
        for i in range(0, cs_len, 2):
            c = _u16(data, off + i)
            if c not in GREASE:
                info.ciphers.append(c)
        off += cs_len

        comp_len = data[off]
        off += 1 + comp_len

        if off + 2 > len(data):
            return info
        ext_total = _u16(data, off)
        off += 2
        end = min(off + ext_total, len(data))

        while off + 4 <= end:
            etype = _u16(data, off)
            elen = _u16(data, off + 2)
            body = data[off + 4: off + 4 + elen]
            off += 4 + elen
            if etype in GREASE:
                continue
            info.extensions.append(etype)

            if etype == EXT_SERVER_NAME:
                info.has_sni = True
            elif etype == EXT_ECH:
                info.has_ech = True
            elif etype == EXT_SIG_ALGS and len(body) >= 2:
                n = _u16(body, 0)
                for i in range(0, min(n, len(body) - 2), 2):
                    s = _u16(body, 2 + i)
                    if s not in GREASE:
                        info.sig_algs.append(s)
            elif etype == EXT_ALPN and len(body) >= 3:
                plen = body[2]
                info.alpn = body[3:3 + plen].decode("ascii", "ignore") or None
            elif etype == EXT_SUPPORTED_VERSIONS and len(body) >= 1:
                n = body[0]
                best = 0
                for i in range(0, min(n, len(body) - 1), 2):
                    v = _u16(body, 1 + i)
                    if v not in GREASE:
                        best = max(best, v)
                if best:
                    info.tls_version = best
        return info
    except (struct.error, IndexError):
        return None


def _version_code(v: int) -> str:
    return {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}.get(v, "00")


def _alpn_code(alpn: Optional[str]) -> str:
    if not alpn:
        return "00"
    if len(alpn) == 1:
        return alpn + alpn
    return alpn[0] + alpn[-1]


def _trunc_sha256(items: List[int], width: int = 4) -> str:
    if not items:
        return "000000000000"
    joined = ",".join(f"{i:0{width}x}" for i in items)
    return hashlib.sha256(joined.encode()).hexdigest()[:12]


def compute_ja4(info: ClientHelloInfo) -> str:
    """Return the JA4 string: ja4_a_ja4_b_ja4_c."""
    sni_flag = "d" if info.has_sni else "i"
    nc = min(len(info.ciphers), 99)
    ne = min(len(info.extensions), 99)
    ja4_a = (f"{info.transport}{_version_code(info.effective_version)}"
             f"{sni_flag}{nc:02d}{ne:02d}{_alpn_code(info.alpn)}")
    ja4_b = _trunc_sha256(sorted(info.ciphers))
    ext_for_hash = sorted(e for e in info.extensions
                          if e not in (EXT_SERVER_NAME, EXT_ALPN))
    ja4_c = _trunc_sha256(ext_for_hash + sorted(info.sig_algs))
    return f"{ja4_a}_{ja4_b}_{ja4_c}"


# ---------------------------------------------------------------------------
# Reference browser profiles.
#
# These are the *declared classes*. A connection whose outer ClientHello is
# structurally close to one of these declares membership of that class, and the
# dissonance statistic then asks whether its physics is plausible for that
# class. In a production deployment you refresh these from a browser-farm
# capture on every browser release (see docs/ARCHITECTURE.md, "Recalibration").
# ---------------------------------------------------------------------------
BROWSER_PROFILES = {
    "chrome": {
        "ciphers": [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
                    0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F,
                    0x0035],
        "extensions": [0x0000, 0x0005, 0x000A, 0x000B, 0x000D, 0x0010, 0x0012,
                       0x0017, 0x001B, 0x0023, 0x002B, 0x002D, 0x0033, 0x4469,
                       0xFF01],
        "alpn": "h2",
    },
    "firefox": {
        "ciphers": [0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8,
                    0xC02C, 0xC030, 0xC00A, 0xC009, 0xC013, 0xC014, 0x002F,
                    0x0035, 0x000A],
        "extensions": [0x0000, 0x0005, 0x000A, 0x000B, 0x000D, 0x0010, 0x0015,
                       0x0017, 0x001C, 0x0022, 0x002B, 0x002D, 0x0033, 0xFF01],
        "alpn": "h2",
    },
    "safari": {
        "ciphers": [0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xC030, 0xC02F,
                    0xCCA9, 0xCCA8, 0xC00A, 0xC009, 0xC014, 0xC013, 0x009D,
                    0x009C, 0x0035, 0x002F],
        "extensions": [0x0000, 0x0005, 0x000A, 0x000B, 0x000D, 0x0010, 0x0012,
                       0x0017, 0x001B, 0x002B, 0x002D, 0x0033, 0xFF01],
        "alpn": "h2",
    },
    "mobile_app": {
        # Native iOS/Android networking stacks: shorter lists, no h2 in many
        # SDKs. A large benign population, and the one most easily mistaken
        # for automation -- which is why it gets its own behavioural model.
        "ciphers": [0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xC030, 0xC02F,
                    0x009D, 0x009C, 0x0035, 0x002F],
        "extensions": [0x0000, 0x000A, 0x000B, 0x000D, 0x0010, 0x0017, 0x002B,
                       0x002D, 0x0033],
        "alpn": "h1",
    },
}

DECLARED_CLASSES = sorted(BROWSER_PROFILES.keys())


def _jaccard(a: List[int], b: List[int]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / max(1, len(sa | sb))


def _order_similarity(a: List[int], b: List[int]) -> float:
    """
    Cipher *preference order* is part of a client's identity and is one of the
    things a hand-rolled TLS stack most often gets wrong. Compare rank of the
    shared items rather than membership alone.
    """
    common = [c for c in a if c in b]
    if len(common) < 2:
        return 0.0
    rank_b = {c: i for i, c in enumerate(b)}
    seq = [rank_b[c] for c in common]
    inversions = sum(1 for i in range(len(seq)) for j in range(i + 1, len(seq))
                     if seq[i] > seq[j])
    max_inv = len(seq) * (len(seq) - 1) / 2
    return 1.0 - (inversions / max_inv if max_inv else 0.0)


def profile_similarity(info: ClientHelloInfo, profile_name: str) -> float:
    """
    Structural similarity in [0, 1] of an observed ClientHello to a reference
    profile. This is feature 13.
    """
    p = BROWSER_PROFILES.get(profile_name)
    if p is None:
        return 0.0
    cipher_sim = _jaccard(info.ciphers, p["ciphers"])
    ext_sim = _jaccard(info.extensions, p["extensions"])
    order_sim = _order_similarity(info.ciphers, p["ciphers"])
    alpn_sim = 1.0 if (info.alpn or "").startswith(p["alpn"][:1]) else 0.0
    return round(
        0.35 * cipher_sim + 0.35 * ext_sim + 0.20 * order_sim + 0.10 * alpn_sim,
        6,
    )


def declared_class(info: ClientHelloInfo) -> Tuple[str, float]:
    """
    The class this connection claims to belong to, and how strongly.

    Note the asymmetry that makes the whole project work: this function is
    trivially fooled by uTLS, and we let it be fooled. The declared class is
    an *input to a consistency test*, not a verdict.
    """
    scores = {name: profile_similarity(info, name) for name in BROWSER_PROFILES}
    best = max(scores, key=scores.get)
    return best, scores[best]


def synth_client_hello(profile_name: str, *, ech: bool = True,
                       sni: bool = False) -> bytes:
    """
    Build a wire-format ClientHello for a named profile. Used by the dataset
    generator to produce PCAPs that the real parser above can read, so the
    sensor path is exercised end to end rather than fed pre-computed numbers.

    With ech=True and sni=False we emit the post-ECH shape: an outer hello
    carrying encrypted_client_hello and no cleartext SNI.
    """
    p = BROWSER_PROFILES[profile_name]
    body = b""
    body += struct.pack("!H", 0x0303)
    body += bytes(32)
    body += b"\x20" + bytes(32)                      # session id
    cs = b"".join(struct.pack("!H", c) for c in p["ciphers"])
    body += struct.pack("!H", len(cs)) + cs
    body += b"\x01\x00"                              # compression: null

    exts = b""
    for e in p["extensions"]:
        if e == EXT_SERVER_NAME and not sni:
            continue
        if e == EXT_ALPN:
            proto = p["alpn"].encode()
            inner = struct.pack("!H", len(proto) + 1) + bytes([len(proto)]) + proto
            exts += struct.pack("!HH", e, len(inner)) + inner
        elif e == EXT_SIG_ALGS:
            algs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
                    0x0601]
            inner = struct.pack("!H", len(algs) * 2) + b"".join(
                struct.pack("!H", a) for a in algs)
            exts += struct.pack("!HH", e, len(inner)) + inner
        elif e == EXT_SUPPORTED_VERSIONS:
            inner = b"\x02" + struct.pack("!H", 0x0304)
            exts += struct.pack("!HH", e, len(inner)) + inner
        else:
            exts += struct.pack("!HH", e, 0)
    if ech:
        exts += struct.pack("!HH", EXT_ECH, 8) + bytes(8)

    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
