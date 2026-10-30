import numpy as np
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score

from ja4bench.report import fast_ap, fast_f1, fast_roc_auc


def test_fast_metrics_match_sklearn():
    rng = np.random.default_rng(1)
    for _ in range(20):
        y = rng.integers(0, 2, 500)
        p = np.round(rng.random(500), 2)          # rounding forces ties
        assert abs(fast_roc_auc(y, p) - roc_auc_score(y, p)) < 1e-12
        assert abs(fast_ap(y, p) - average_precision_score(y, p)) < 1e-12
        assert abs(fast_f1(y, p) - f1_score(y, (p >= .5).astype(int))) < 1e-12
