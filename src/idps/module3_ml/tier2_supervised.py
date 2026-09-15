"""
Tier 2 -- the supervised dissonance detector.

An XGBoost classifier over the 14-D sensor vector, optionally with D(x)
appended as a 15th derived input.

On that optional 15th input
---------------------------
The 14-D vector is the sensor's output contract and stays 14-D: that is what
crosses the boundary from the capture plane to the analytical plane, and it is
what the privacy argument is written against. D(x) is not a new measurement --
it is a function of features 1-13 computed inside the ML plane, using the
class-conditional densities. Appending it hands the tree ensemble a feature it
would otherwise have to approximate with axis-aligned splits, which it does
poorly: a likelihood ratio against a full-covariance mixture is not a shape
trees represent efficiently.

Set `use_dissonance_feature=False` to reproduce the plain 14-D configuration
described in the dossier. The evaluation harness reports both, and the gap
between them is a result worth putting in the paper.

Thresholding
------------
The decision threshold is not 0.5. It is chosen as the quantile of the benign
score distribution that hits a target false-positive rate, because in an IDS
the operational constraint is analyst workload, not balanced accuracy. A
detector at 99% accuracy that produces 4000 false alerts a day is not deployed
twice.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Sequence

import numpy as np

from ..features import FEATURE_NAMES


@dataclass
class SupervisedConfig:
    n_estimators: int = 400
    max_depth: int = 6
    learning_rate: float = 0.05
    subsample: float = 0.85
    colsample_bytree: float = 0.85
    min_child_weight: float = 2.0
    reg_lambda: float = 1.5
    target_fpr: float = 0.005
    use_dissonance_feature: bool = True
    random_state: int = 7


class SupervisedTier:
    def __init__(self, config: Optional[SupervisedConfig] = None):
        self.config = config or SupervisedConfig()
        self.model = None
        self.threshold: float = 0.5
        self.input_names: list = []
        self.metrics: Dict[str, float] = {}

    # -- input assembly ---------------------------------------------------
    def _inputs(self, X: np.ndarray,
                dissonance: Optional[np.ndarray]) -> np.ndarray:
        X = np.asarray(X, dtype=np.float32)
        if not self.config.use_dissonance_feature:
            return X
        if dissonance is None:
            raise ValueError(
                "use_dissonance_feature is on but no D(x) was supplied. "
                "Fit the DissonanceModel first and pass its scores through.")
        d = np.asarray(dissonance, dtype=np.float32).reshape(-1, 1)
        return np.hstack([X, d])

    @property
    def feature_names(self) -> list:
        names = list(FEATURE_NAMES)
        if self.config.use_dissonance_feature:
            names.append("dissonance_D")
        return names

    # -- training ---------------------------------------------------------
    def fit(self, X: np.ndarray, y: np.ndarray,
            dissonance: Optional[np.ndarray] = None,
            X_val: Optional[np.ndarray] = None,
            y_val: Optional[np.ndarray] = None,
            dissonance_val: Optional[np.ndarray] = None) -> "SupervisedTier":
        from xgboost import XGBClassifier

        y = np.asarray(y).astype(int)
        A = self._inputs(X, dissonance)
        self.input_names = self.feature_names

        # Class weighting rather than resampling: the operational prior really
        # is imbalanced, and resampling would distort the score distribution
        # the threshold is calibrated against.
        pos = max(1, int((y == 1).sum()))
        neg = max(1, int((y == 0).sum()))

        self.model = XGBClassifier(
            n_estimators=self.config.n_estimators,
            max_depth=self.config.max_depth,
            learning_rate=self.config.learning_rate,
            subsample=self.config.subsample,
            colsample_bytree=self.config.colsample_bytree,
            min_child_weight=self.config.min_child_weight,
            reg_lambda=self.config.reg_lambda,
            scale_pos_weight=neg / pos,
            objective="binary:logistic",
            eval_metric="aucpr",
            tree_method="hist",
            random_state=self.config.random_state,
            n_jobs=4,
        )
        self.model.fit(A, y, verbose=False)

        # Calibrate on validation benign if available, else training benign.
        if X_val is not None and y_val is not None:
            cal_scores = self.score(X_val, dissonance_val)
            cal_y = np.asarray(y_val).astype(int)
        else:
            cal_scores, cal_y = self.score(X, dissonance), y
        benign_scores = cal_scores[cal_y == 0]
        self.threshold = float(
            np.quantile(benign_scores, 1.0 - self.config.target_fpr))
        self.metrics = {
            "threshold": self.threshold,
            "target_fpr": self.config.target_fpr,
            "n_train": int(len(y)),
            "n_positive": pos,
        }
        return self

    # -- inference --------------------------------------------------------
    def score(self, X: np.ndarray,
              dissonance: Optional[np.ndarray] = None) -> np.ndarray:
        A = self._inputs(X, dissonance)
        return self.model.predict_proba(A)[:, 1]

    def predict(self, X: np.ndarray,
                dissonance: Optional[np.ndarray] = None) -> np.ndarray:
        return (self.score(X, dissonance) >= self.threshold).astype(int)

    # -- persistence ------------------------------------------------------
    def save(self, path: str) -> None:
        import joblib
        joblib.dump(self, path)
        Path(path).with_suffix(".json").write_text(json.dumps({
            "inputs": self.input_names, **self.metrics}, indent=2))

    @staticmethod
    def load(path: str) -> "SupervisedTier":
        import joblib
        return joblib.load(path)
