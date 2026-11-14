"""
Module 2b -- feature extraction.

Turns an assembled Flow into the 14-D vector plus the declared-class label the
dissonance statistic needs.

Every quantity here is computed from packet sizes, arrival times and direction:
information that survives full encryption, and that ECH does not remove. No
payload byte is ever inspected beyond the handshake bytes needed for JA4, which
are transmitted in the clear by definition.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional

import numpy as np

from ..features import N_FEATURES, SPLT_PACKETS, INDEX_BY_NAME
from ..ja4 import (ClientHelloInfo, compute_ja4, declared_class,
                   parse_client_hello, profile_similarity, stack_key)
from .flow import Flow

# A gap longer than this ends a burst. Chosen to sit above typical intra-page
# sub-resource spacing and below human reading pauses.
BURST_GAP_MS = 120.0
# Sizes are quantised onto this lattice before entropy is taken. 64 bytes is
# the AES-GCM-ish record granularity that padding schemes tend to land on.
LATTICE_BYTES = 64


@dataclass
class FlowRecord:
    """
    What leaves the sensor. Note what is absent: no source IP in the part that
    reaches the ML plane. `src_ip` is carried in a separate field that only
    Module 5 reads, so the analytical path stays address-free.
    """
    features: np.ndarray                      # shape (14,)
    declared: str                             # class the connection claims
    declared_confidence: float
    ja4: Optional[str] = None
    stack: Optional[str] = None               # client TLS stack key (ja4.stack_key)
    has_ech: bool = False
    has_sni: bool = False
    src_ip: str = ""                          # enforcement-plane only
    src_port: int = 0                         # enforcement-plane only
    dst_ip: str = ""
    dst_port: int = 0
    start_ts: float = 0.0
    duration: float = 0.0
    n_packets: int = 0
    truth: Optional[dict] = field(default=None)

    def as_dict(self) -> dict:
        from ..features import FEATURE_NAMES
        return {name: float(self.features[i])
                for i, name in enumerate(FEATURE_NAMES)}


def _safe_log10(x: float, floor: float = 1e-6) -> float:
    return math.log10(max(x, floor))


def _lattice_entropy(sizes: List[int]) -> float:
    """
    Shannon entropy of the quantised size distribution.

    This is the padding detector. A beacon that pads every record to a constant
    block collapses the histogram to one bin and scores 0. Genuine browsing
    spreads across many bins. An attacker can raise the score by randomising
    pad length, but only by paying bandwidth for pad bytes that carry nothing --
    which is exactly the cost the evasion-cost theorem prices.
    """
    if not sizes:
        return 0.0
    bins: dict = {}
    for s in sizes:
        b = s // LATTICE_BYTES
        bins[b] = bins.get(b, 0) + 1
    total = sum(bins.values())
    return -sum((c / total) * math.log2(c / total) for c in bins.values())


def _periodicity(gaps: np.ndarray, tol: float = 0.15) -> float:
    """
    Fraction of gaps sitting within +/-tol of the flow's median gap.

    Preferred over a lag-1 autocorrelation of the gap sequence, which is close
    to zero for a constant-plus-iid-noise beacon and so fails at exactly the
    signal it was meant to catch. Measuring dispersion around the flow's own
    median is scale-invariant: lengthening the callback interval does not lower
    the score, so the attacker cannot evade by beaconing more slowly. The only
    way down is genuine irregularity, which costs latency.
    """
    if gaps.size < 2:
        return 0.0
    med = float(np.median(gaps))
    if med < 1e-6:
        return 1.0
    return float(np.mean(np.abs(gaps - med) <= tol * med))


def _relative_pauses(gaps: np.ndarray, factor: float = 3.0) -> float:
    """Gaps more than `factor` times the flow's median -- pauses in context."""
    if gaps.size < 2:
        return 0.0
    med = float(np.median(gaps))
    if med < 1e-6:
        return 0.0
    return float(np.sum(gaps > factor * med))


def extract(flow: Flow) -> Optional[FlowRecord]:
    """Extract the 14-D vector. Returns None if the flow is too short to score."""
    pkts = flow.packets[:SPLT_PACKETS]
    if len(pkts) < 4:
        return None

    sizes = np.array([p.size for p in pkts], dtype=float)
    times = np.array([p.ts for p in pkts], dtype=float)
    dirs = np.array([1 if p.forward else -1 for p in pkts])

    iats_ms = np.diff(times) * 1000.0
    iats_ms = np.clip(iats_ms, 0.0, None)

    v = np.zeros(N_FEATURES, dtype=np.float32)
    ix = INDEX_BY_NAME

    # --- f1-f3: size structure -------------------------------------------
    v[ix["mean_pkt_size"]] = float(sizes.mean())
    v[ix["std_pkt_size"]] = float(sizes.std())
    v[ix["size_lattice_entropy"]] = _lattice_entropy([int(s) for s in sizes])

    # --- f4-f7: timing structure -----------------------------------------
    mean_iat = float(iats_ms.mean()) if iats_ms.size else 0.0
    std_iat = float(iats_ms.std()) if iats_ms.size else 0.0
    v[ix["log_mean_iat"]] = _safe_log10(mean_iat)
    v[ix["log_std_iat"]] = _safe_log10(std_iat)
    v[ix["iat_cv"]] = float(std_iat / mean_iat) if mean_iat > 1e-6 else 0.0
    v[ix["periodicity_score"]] = _periodicity(iats_ms)

    # --- f8-f9: burst structure ------------------------------------------
    burst_sizes: List[int] = []
    current = 1
    for gap in iats_ms:
        if gap > BURST_GAP_MS:
            burst_sizes.append(current)
            current = 1
        else:
            current += 1
    burst_sizes.append(current)
    v[ix["burst_count"]] = float(len(burst_sizes))
    v[ix["mean_burst_size"]] = float(np.mean(burst_sizes))

    # --- f10-f11: directionality -----------------------------------------
    up_bytes = float(sizes[dirs > 0].sum())
    total_bytes = float(sizes.sum()) or 1.0
    up_pkts = int((dirs > 0).sum())
    down_pkts = int((dirs < 0).sum())
    v[ix["directionality_ratio"]] = up_bytes / total_bytes
    v[ix["up_down_pkt_ratio"]] = up_pkts / max(1, down_pkts)

    # --- f12: human think time -------------------------------------------
    v[ix["relative_pause_count"]] = _relative_pauses(iats_ms)

    # --- f13: the declared cryptographic identity -------------------------
    info: Optional[ClientHelloInfo] = (
        parse_client_hello(flow.client_hello) if flow.client_hello else None)
    if info is not None:
        cls, conf = declared_class(info)
        v[ix["ja4_similarity"]] = profile_similarity(info, cls)
        ja4, has_ech = compute_ja4(info), info.has_ech
        stack, has_sni = stack_key(info), info.has_sni
    else:
        # No handshake observed (mid-flow capture, or a resumed session).
        # "unknown" is its own class with its own behavioural model -- we do
        # not silently assume a browser, because that would hand the attacker a
        # free class by simply withholding the hello.
        cls, conf, ja4, has_ech = "unknown", 0.0, None, False
        stack, has_sni = None, False
        v[ix["ja4_similarity"]] = 0.0

    # --- f14: flow context -------------------------------------------------
    v[ix["log_flow_duration"]] = _safe_log10(flow.duration)

    return FlowRecord(
        features=v,
        declared=cls,
        declared_confidence=float(conf),
        ja4=ja4,
        stack=stack,
        has_ech=has_ech,
        has_sni=has_sni,
        src_ip=flow.src_ip,
        src_port=flow.src_port,
        dst_ip=flow.dst_ip,
        dst_port=flow.dst_port,
        start_ts=flow.start_ts,
        duration=flow.duration,
        n_packets=flow.total_packets,
        truth=flow.truth,
    )
