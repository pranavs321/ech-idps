#!/usr/bin/env python3
import sys
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from idps.module3_ml.dissonance import DissonanceConfig, DissonanceModel

def main():
    data = np.load(ROOT / "artifacts" / "dataset.npz", allow_pickle=True)
    X, y = data["X"], data["y"].astype(int)
    declared = data["declared"]
    
    # Simple split (matching train.py seed 11)
    rng = np.random.default_rng(11)
    n = len(X)
    idx = rng.permutation(n)
    tr = idx[:int(0.6 * n)]
    te = idx[int(0.8 * n):]
    
    dm = DissonanceModel(DissonanceConfig(target_fpr=0.005))
    dm.fit(X[tr], declared[tr], benign_mask=(y[tr] == 0))
    
    global_tau = dm.tau
    per_class_tau = dm.tau_per_class.get("mobile_app", global_tau)
    
    # Filter test set for malware declaring 'mobile_app'
    sel_malware = (y[te] == 1) & (declared[te] == "mobile_app")
    X_malware = X[te][sel_malware]
    
    if len(X_malware) == 0:
        print("No mobile_app malware flows in test set!")
        return
        
    d_malware = dm.score(X_malware, np.array(["mobile_app"] * len(X_malware)))
    
    recall_global = (d_malware > global_tau).mean()
    recall_rate_calibrated = (d_malware > per_class_tau).mean()
    
    print(f"Global tau: {global_tau:.3f}")
    print(f"Rate-calibrated tau for mobile_app: {per_class_tau:.3f}")
    print(f"Recall with global tau: {recall_global:.4f}")
    print(f"Recall with rate-calibrated tau: {recall_rate_calibrated:.4f}")
    print(f"Delta: {recall_rate_calibrated - recall_global:+.4f}")

if __name__ == "__main__":
    main()
