import numpy as np
from typing import Dict, Sequence

def calibrate_thresholds(d_benign: np.ndarray, declared: Sequence[str], target_fpr: float) -> Dict[str, float]:
    """
    Calibrate dissonance thresholds on a per-class basis (Rate-Calibrated Thresholding).
    
    Instead of using a single global threshold, which disproportionately penalizes
    classes with lower cover rates or higher variance (like mobile_app), this computes
    a specific threshold for each declared class to enforce the target FPR *within*
    that class's own traffic.
    """
    declared = np.asarray(declared)
    thresholds = {}
    classes = sorted(set(declared))
    
    for cls in classes:
        sel = (declared == cls)
        if sel.sum() == 0:
            continue
        d_cls = d_benign[sel]
        tau = float(np.quantile(d_cls, 1.0 - target_fpr))
        thresholds[cls] = tau
        
    return thresholds
