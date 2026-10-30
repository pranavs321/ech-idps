"""Models.

lookup   JA4 lookup table: score = share of malicious training rows with this exact JA4.
         Unseen JA4 -> training prevalence (and counted as 'abstained' in the coverage column).
         If XGBoost is not clearly better than this, the model is memorising fingerprints.
xgb      XGBoost (same family as the team baseline); scale_pos_weight from THIS training fold
rf       Random forest, balanced class weights
logreg   L2 logistic regression on standardised features
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

MODELS = ["lookup", "xgb", "rf", "logreg"]


class LookupBaseline:
    def fit(self, keys: pd.Series, y: np.ndarray):
        s = pd.Series(y, index=keys.astype(str).values)
        self.table = s.groupby(level=0).mean().to_dict()
        self.prior = float(np.mean(y))
        return self

    def predict_proba(self, keys: pd.Series) -> tuple[np.ndarray, np.ndarray]:
        k = keys.astype(str)
        seen = k.isin(self.table.keys()).to_numpy()
        p = k.map(self.table).fillna(self.prior).to_numpy(dtype=float)
        return p, seen


def make_model(name: str, y_train: np.ndarray, seed: int = 42):
    pos = max(int(y_train.sum()), 1)
    neg = max(int(len(y_train) - y_train.sum()), 1)
    if name == "xgb":
        from xgboost import XGBClassifier
        return XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.9,
                             colsample_bytree=0.8, tree_method="hist", n_jobs=1,
                             scale_pos_weight=neg / pos, random_state=seed, eval_metric="aucpr")
    if name == "rf":
        return RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=1,
                                      class_weight="balanced_subsample", random_state=seed)
    if name == "logreg":
        return make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, C=1.0,
                                                                  class_weight="balanced"))
    raise ValueError(f"unknown model {name}; choose from {MODELS}")
