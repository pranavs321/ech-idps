"""
The 14-dimensional feature schema.

This module is the single source of truth for the feature vector. Module 2
produces it, Module 3 consumes it, Module 4 attributes over it and Module 5
reads the family labels off it. Nothing else in the codebase should hard-code
a feature index.

Layout (matches the project document, Section 6.1):
    f1  .. f12  SPLT physics   -- sizes / inter-arrival gaps / bursts / direction
    f13         cryptographic  -- structural similarity of observed JA4 to a
                                  genuine browser profile of the declared class
    f14         flow context   -- coarse flow-level context

Family labels exist for Pillar 3 (attribution-driven enforcement). Each
feature is either:

    ENDPOINT_INTRINSIC        a property of the attacker's own process. If the
                              verdict rests here, the evidence follows the
                              endpoint, so a persistent source-scoped block is
                              justified.

    INFRA_COINCIDENTAL        a property that co-tenants of a NAT, campus Wi-Fi
                              or CDN egress share. If the verdict rests here,
                              blocking the source IP punishes bystanders, so
                              mitigation must stay flow-scoped and short-lived.

    CRYPTO_DECLARED           the declared identity axis. Spoofable for free,
                              so on its own it never earns a persistent block;
                              it earns one only in coupling with intrinsic
                              physics (that coupling is what D(x) measures).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

ENDPOINT_INTRINSIC = "endpoint_intrinsic"
INFRA_COINCIDENTAL = "infra_coincidental"
CRYPTO_DECLARED = "crypto_declared"


@dataclass(frozen=True)
class FeatureSpec:
    index: int          # 0-based position in the vector
    name: str           # machine name
    label: str          # human-readable, used on the dashboard and in receipts
    family: str
    unit: str
    note: str


# ---------------------------------------------------------------------------
# The schema. Order here IS the vector order.
# ---------------------------------------------------------------------------
SCHEMA: List[FeatureSpec] = [
    FeatureSpec(
        0, "mean_pkt_size", "Mean payload size (first 15 packets)",
        INFRA_COINCIDENTAL, "bytes",
        "Shifts with MTU and middlebox segmentation, which co-tenants share.",
    ),
    FeatureSpec(
        1, "std_pkt_size", "Payload size spread",
        ENDPOINT_INTRINSIC, "bytes",
        "Human page loads mix tiny requests with full-MTU responses; a beacon "
        "emits near-constant records.",
    ),
    FeatureSpec(
        2, "size_lattice_entropy", "Size lattice entropy",
        ENDPOINT_INTRINSIC, "bits",
        "Shannon entropy of the quantised size histogram. Padding to a fixed "
        "block collapses this; genuine browsing keeps it high.",
    ),
    FeatureSpec(
        3, "log_mean_iat", "Mean inter-arrival gap (log ms)",
        INFRA_COINCIDENTAL, "log10(ms)",
        "Dominated by path RTT, which every host behind the same egress shares.",
    ),
    FeatureSpec(
        4, "log_std_iat", "Inter-arrival gap spread (log ms)",
        ENDPOINT_INTRINSIC, "log10(ms)",
        "Dispersion of the gaps, not their level -- a property of the sender's "
        "scheduler rather than the path.",
    ),
    FeatureSpec(
        5, "iat_cv", "Timing jitter coefficient of variation",
        ENDPOINT_INTRINSIC, "ratio",
        "std/mean of gaps. The headline roboticness signal: a sleep-loop "
        "beacon drives this toward 0, humans sit well above 1.",
    ),
    FeatureSpec(
        6, "periodicity_score", "Beacon periodicity",
        ENDPOINT_INTRINSIC, "ratio",
        "Fraction of gaps landing within +/-15% of the flow's own median gap. "
        "A sleep-loop beacon approaches 1.0 whatever its period, so unlike a "
        "raw timing threshold this cannot be dodged by choosing a slower "
        "callback interval.",
    ),
    FeatureSpec(
        7, "burst_count", "Burst count",
        ENDPOINT_INTRINSIC, "count",
        "Number of packet groups separated by an idle gap. Page loads burst; "
        "beacons trickle.",
    ),
    FeatureSpec(
        8, "mean_burst_size", "Mean packets per burst",
        ENDPOINT_INTRINSIC, "packets",
        "A browser fetching sub-resources produces fat bursts.",
    ),
    FeatureSpec(
        9, "directionality_ratio", "Upstream byte share",
        ENDPOINT_INTRINSIC, "ratio",
        "Browsing is download-heavy; C2 tasking and exfiltration invert this.",
    ),
    FeatureSpec(
        10, "up_down_pkt_ratio", "Upstream/downstream packet ratio",
        ENDPOINT_INTRINSIC, "ratio",
        "Separates request-response ping-pong from asymmetric content fetch.",
    ),
    FeatureSpec(
        11, "relative_pause_count", "Think-time pauses",
        ENDPOINT_INTRINSIC, "count",
        "Gaps exceeding three times the flow's own median gap, i.e. pauses "
        "relative to its established rhythm. Measured this way a slow beacon "
        "scores 0 the same as a fast one, because regularity rather than "
        "duration is what separates a reading human from a sleep loop.",
    ),
    FeatureSpec(
        12, "ja4_similarity", "JA4 similarity to declared browser profile",
        CRYPTO_DECLARED, "ratio",
        "Structural similarity of the observed outer-ClientHello fingerprint "
        "to the reference profile for the class it declares. Free to forge, "
        "which is exactly why it is only ever read alongside f1-f12.",
    ),
    FeatureSpec(
        13, "log_flow_duration", "Flow duration (log s)",
        INFRA_COINCIDENTAL, "log10(s)",
        "Coarse flow context. Long-lived flows are common on shared egress.",
    ),
]

N_FEATURES = len(SCHEMA)
assert N_FEATURES == 14, "The schema must stay 14-dimensional."

FEATURE_NAMES: List[str] = [f.name for f in SCHEMA]
FEATURE_LABELS: List[str] = [f.label for f in SCHEMA]
FEATURE_FAMILY: List[str] = [f.family for f in SCHEMA]
INDEX_BY_NAME: Dict[str, int] = {f.name: f.index for f in SCHEMA}

# Indices of the physics block (f1-f12) -- the axis the attacker cannot
# forge for free. Used by the dissonance statistic and by the f13 ablation.
PHYSICS_IDX: List[int] = [f.index for f in SCHEMA if f.family != CRYPTO_DECLARED
                          and f.index < 12]
CRYPTO_IDX: int = INDEX_BY_NAME["ja4_similarity"]

# Threshold for what counts as a human "think-time" gap, in milliseconds.
THINK_GAP_MS = 500.0

# The sensor observes at most this many packets of a flow before emitting.
SPLT_PACKETS = 15


def family_of(index: int) -> str:
    return SCHEMA[index].family


def describe(index: int) -> FeatureSpec:
    return SCHEMA[index]


def blank_vector() -> List[float]:
    return [0.0] * N_FEATURES
