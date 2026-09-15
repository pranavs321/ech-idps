"""
Module 3 -- the 3-tier detection engine.

Cascade order, and the reasoning behind it:

    Tier 1  JA4 blocklist        cheapest, deterministic, no FP risk beyond
                                 the quality of the list itself.
    Tier 2  XGBoost + D(x)       the main event. Catches mimicry by testing the
                                 declared identity against the physics.
    Tier 3  Isolation Forest     runs only on what Tier 2 cleared. Catches
                                 novelty, at the cost of a weaker verdict.

Each tier can terminate the cascade. That is not just a speed optimisation: it
also means the verdict carries *which* tier fired, and Module 5 uses that to
decide how much enforcement the evidence can bear. A Tier 1 exact hit and a
Tier 3 anomaly are both "malicious" and should absolutely not produce the same
response.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

from ..features import FEATURE_NAMES
from ..module2_sensor.extractor import FlowRecord
from .dissonance import DissonanceModel, evasion_cost_lower_bound
from .tier1_blocklist import JA4Blocklist
from .tier2_supervised import SupervisedTier
from .tier3_anomaly import AnomalyTier

BENIGN = "benign"
MALICIOUS = "malicious"


@dataclass
class Verdict:
    label: str                       # benign | malicious
    tier: str                        # tier1_blocklist | tier2_supervised | ...
    risk: float                      # [0, 1]
    confidence: float
    declared: str = ""
    best_fit: str = ""
    dissonance: float = 0.0
    dissonance_tau: float = 0.0
    supervised_score: float = 0.0
    anomaly_score: float = 0.0
    reason: str = ""
    evasion_cost: Dict[str, float] = field(default_factory=dict)
    record: Optional[FlowRecord] = None

    @property
    def is_malicious(self) -> bool:
        return self.label == MALICIOUS


class DetectionEngine:
    def __init__(self, blocklist: JA4Blocklist,
                 dissonance: DissonanceModel,
                 supervised: SupervisedTier,
                 anomaly: Optional[AnomalyTier] = None):
        self.blocklist = blocklist
        self.dissonance = dissonance
        self.supervised = supervised
        self.anomaly = anomaly

    # -- batch path (evaluation) -----------------------------------------
    def score_batch(self, X: np.ndarray, declared: List[str],
                    ja4: Optional[List[Optional[str]]] = None) -> Dict[str, np.ndarray]:
        """Vectorised scoring. Used by the evaluation harness."""
        d = self.dissonance.score(X, declared)
        sup = self.supervised.score(X, d)
        out = {
            "dissonance": d,
            "supervised": sup,
            "best_fit": np.array(self.dissonance.best_fit_class(X)),
        }
        if self.anomaly is not None:
            out["anomaly"] = self.anomaly.score(X)
        if ja4 is not None:
            out["blocklist"] = np.array(
                [self.blocklist.check(j) is not None for j in ja4])
        return out

    # -- single-flow path (live) -----------------------------------------
    def evaluate(self, rec: FlowRecord) -> Verdict:
        X = rec.features.reshape(1, -1)

        # ---- Tier 1 ------------------------------------------------------
        hit = self.blocklist.check(rec.ja4)
        if hit is not None:
            return Verdict(
                label=MALICIOUS, tier="tier1_blocklist",
                risk=hit.confidence, confidence=hit.confidence,
                declared=rec.declared,
                reason=(f"Outer ClientHello fingerprint matches a known "
                        f"malicious client ({hit.label}, {hit.mode} match)."),
                record=rec)

        # ---- shared statistics -------------------------------------------
        d = float(self.dissonance.score(X, [rec.declared])[0])
        best_fit = self.dissonance.best_fit_class(X)[0]
        sup = float(self.supervised.score(X, np.array([d]))[0])

        # ---- Tier 2 ------------------------------------------------------
        if sup >= self.supervised.threshold:
            cost = evasion_cost_lower_bound(d, self.dissonance.tau,
                                            n_packets=rec.n_packets or 15)
            if d > self.dissonance.tau:
                reason = (
                    f"Connection declares the {rec.declared} client stack, but "
                    f"its packet timing and size structure are far better "
                    f"explained by the {best_fit} behaviour model "
                    f"(D={d:.1f} nats against a calibrated threshold of "
                    f"{self.dissonance.tau:.1f}). The declared identity is "
                    f"inconsistent with the observed physics.")
            else:
                reason = (
                    f"Supervised model scored {sup:.3f} against a threshold of "
                    f"{self.supervised.threshold:.3f} on the physical feature "
                    f"structure, without a decisive identity contradiction.")
            return Verdict(
                label=MALICIOUS, tier="tier2_supervised",
                risk=sup, confidence=min(0.99, 0.5 + sup / 2),
                declared=rec.declared, best_fit=best_fit,
                dissonance=d, dissonance_tau=self.dissonance.tau,
                supervised_score=sup, reason=reason,
                evasion_cost=cost, record=rec)

        # ---- Tier 3 ------------------------------------------------------
        anom = 0.0
        if self.anomaly is not None:
            anom = float(self.anomaly.score(X)[0])
            if anom >= -self.anomaly.threshold:
                return Verdict(
                    label=MALICIOUS, tier="tier3_anomaly",
                    risk=min(0.95, 0.5 + anom / 4),
                    confidence=0.55,
                    declared=rec.declared, best_fit=best_fit,
                    dissonance=d, dissonance_tau=self.dissonance.tau,
                    supervised_score=sup, anomaly_score=anom,
                    reason=("Behaviour falls outside the clean-traffic baseline "
                            "without matching any known attack pattern. "
                            "Treated as novelty: low-confidence verdict, "
                            "minimum-scope response."),
                    record=rec)

        return Verdict(
            label=BENIGN, tier="clear", risk=sup, confidence=1.0 - sup,
            declared=rec.declared, best_fit=best_fit,
            dissonance=d, dissonance_tau=self.dissonance.tau,
            supervised_score=sup, anomaly_score=anom,
            reason="Declared identity is consistent with observed physics.",
            record=rec)
