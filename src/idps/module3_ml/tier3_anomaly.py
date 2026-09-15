"""
Tier 3 -- the zero-day novelty tier.

An Isolation Forest fitted on clean traffic only. It never sees a malicious
example, so it cannot learn "what malware looks like" -- it learns the shape of
the benign population and reports how far outside it a flow sits.

Why this tier exists when Tier 2 already scores well
----------------------------------------------------
Tier 2 can only recognise attack structure resembling something in its training
labels. Tier 3's job is the flow that is strange in a way nobody has labelled
yet. The two fail in different directions, which is the point of stacking them:
a supervised model is confidently wrong on novelty, a novelty detector is noisy
on the known. Running novelty *after* the supervised tier, on traffic the
supervised tier cleared, keeps its false-positive contribution bounded to the
residual.

It is also the tier most likely to misfire in production, so its verdicts are
deliberately weaker: Module 5 treats an anomaly-only verdict as grounds for a
short, flow-scoped action and an analyst alert, never a persistent ban.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@dataclass
class AnomalyConfig:
    n_estimators: int = 200
    contamination: float = 0.01
    max_samples: str = "auto"
    target_fpr: float = 0.01
    random_state: int = 7


class AnomalyTier:
    def __init__(self, config: Optional[AnomalyConfig] = None):
        self.config = config or AnomalyConfig()
        self.scaler: Optional[StandardScaler] = None
        self.model: Optional[IsolationForest] = None
        self.threshold: float = 0.0
        self.metrics: Dict[str, float] = {}

    def fit(self, X_clean: np.ndarray) -> "AnomalyTier":
        X_clean = np.asarray(X_clean, dtype=np.float64)
        self.scaler = StandardScaler().fit(X_clean)
        Z = self.scaler.transform(X_clean)
        self.model = IsolationForest(
            n_estimators=self.config.n_estimators,
            contamination=self.config.contamination,
            max_samples=self.config.max_samples,
            random_state=self.config.random_state,
            n_jobs=4,
        ).fit(Z)
        # score_samples: higher = more normal. Flag the lower tail.
        s = self.model.score_samples(Z)
        self.threshold = float(np.quantile(s, self.config.target_fpr))
        self.metrics = {
            "threshold": self.threshold,
            "target_fpr": self.config.target_fpr,
            "n_clean": int(len(X_clean)),
        }
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """Novelty score, higher = more anomalous (sign-flipped for sanity)."""
        Z = self.scaler.transform(np.asarray(X, dtype=np.float64))
        return -self.model.score_samples(Z)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.score(X) >= -self.threshold).astype(int)

    def save(self, path: str) -> None:
        import joblib
        joblib.dump(self, path)
        Path(path).with_suffix(".json").write_text(
            json.dumps(self.metrics, indent=2))

    @staticmethod
    def load(path: str) -> "AnomalyTier":
        import joblib
        return joblib.load(path)
