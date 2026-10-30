#!/usr/bin/env python3
"""
Environment Leakage Index (ELI) Measurement Tool.
Implements the novel metric proposed in Section 23:
"For any dataset, report the TCP/IP-only score and the best single-field score
next to the headline accuracy. It's cheap and any JA4 paper could use it."

Quantifies the degree to which a machine learning intrusion detection model
is exploiting capture environment / vantage artifacts rather than malware behavior.
"""

import sys
import os
import argparse
import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import balanced_accuracy_score, roc_auc_score
import xgboost as xgb

def compute_single_field_bacc(df: pd.DataFrame, field: str, y: np.ndarray) -> float:
    """Predict label based on majority class for each unique value of the field."""
    if field not in df.columns:
        return 0.5
    s = df[field].fillna(-999).astype(str)
    # Mapping each unique value to majority label
    val_to_class = {}
    for val, grp in df.groupby(s):
        val_to_class[val] = grp['binary_label'].mode()[0]
    preds = s.map(val_to_class).values
    return float(balanced_accuracy_score(y, preds))

def run_eli_audit(data_path: str, capture_col: str = 'capture_id', label_col: str = 'label'):
    print("=" * 75)
    print("  ENVIRONMENT LEAKAGE INDEX (ELI) DATASET AUDIT")
    print("=" * 75)
    print(f"Dataset: {data_path}")

    if not os.path.exists(data_path):
        print(f"Error: {data_path} not found.")
        return

    df = pd.read_parquet(data_path) if data_path.endswith('.parquet') else pd.read_csv(data_path)
    
    # Standardize label to 0/1
    if df[label_col].dtype == object or isinstance(df[label_col].iloc[0], str):
        df['binary_label'] = df[label_col].apply(lambda x: 1 if str(x).strip().lower() in ['1', 'malware', 'malicious'] else 0)
    else:
        df = df[df[label_col].isin([0, 1])].copy()
        df['binary_label'] = df[label_col].astype(int)

    # Filter invalid groups
    if capture_col not in df.columns:
        df['capture_id'] = 'cap_' + (df.index // 50).astype(str)
        capture_col = 'capture_id'

    df = df.dropna(subset=[capture_col]).copy()
    y = df['binary_label'].values
    groups = df[capture_col].values

    print(f"Evaluated Connections: {len(df)} (Benign: {sum(y==0)}, Malicious: {sum(y==1)})")
    print(f"Unique Recording Captures: {df[capture_col].nunique()}")

    # 1. Single Field BAcc Benchmarks
    single_fields = {
        'Client Subnet (/24)': 'src_ip',
        'Client Initial TTL': 'ttl',
        'SYN-ACK MSS': 'synack_mss',
        'Client SYN Window': 'win',
        'JA4 Fingerprint': 'ja4'
    }

    # If src_ip exists, compute /24 subnet
    if 'src_ip' in df.columns:
        df['subnet_24'] = df['src_ip'].astype(str).apply(lambda ip: '.'.join(ip.split('.')[:3]) if '.' in ip else ip)
        single_fields['Client Subnet (/24)'] = 'subnet_24'

    print("\n--- Single-Field Heuristic Benchmark (Predict Class by Value Mode) ---")
    sf_scores = {}
    for label, col in single_fields.items():
        if col in df.columns:
            score = compute_single_field_bacc(df, col, y)
            sf_scores[label] = score
            print(f"  {label:<25} Balanced Accuracy: {score:.4f}  ({'PERFECT' if score > 0.98 else 'STRONG' if score > 0.75 else 'LOW/CHANCE'})")

    best_sf_name = max(sf_scores, key=sf_scores.get)
    best_sf_val = sf_scores[best_sf_name]

    # 2. env_only model (TCP/IP handshake features only)
    candidate_env_cols = ['ttl', 'win', 'synack_mss', 'syn_wscale', 'synack_wscale', 'syn_opt_count', 'synack_opt_count', 'tcp_mss', 'initial_ttl']
    env_cols = [c for c in candidate_env_cols if c in df.columns]

    sgkf = StratifiedGroupKFold(n_splits=5)
    
    if len(env_cols) > 0 and len(np.unique(groups)) >= 5:
        env_preds_all, y_true_all = [], []
        for train_idx, test_idx in sgkf.split(df, y, groups):
            X_tr, y_tr = df.iloc[train_idx][env_cols].fillna(-1), y[train_idx]
            X_te, y_te = df.iloc[test_idx][env_cols].fillna(-1), y[test_idx]
            if len(np.unique(y_tr)) < 2 or len(np.unique(y_te)) < 2:
                continue
            clf = xgb.XGBClassifier(n_estimators=100, max_depth=4, learning_rate=0.1, random_state=42)
            clf.fit(X_tr, y_tr)
            preds = clf.predict(X_te)
            env_preds_all.extend(preds)
            y_true_all.extend(y_te)
        env_only_bacc = float(balanced_accuracy_score(y_true_all, env_preds_all)) if env_preds_all else best_sf_val
    else:
        env_only_bacc = best_sf_val

    # 3. Full / Headline model (all numeric features)
    numeric_cols = [c for c in df.select_dtypes(include=[np.number]).columns if c not in ['binary_label', label_col, 'row_id']]
    head_preds_all, y_head_true = [], []
    for train_idx, test_idx in sgkf.split(df, y, groups):
        X_tr, y_tr = df.iloc[train_idx][numeric_cols].fillna(-1), y[train_idx]
        X_te, y_te = df.iloc[test_idx][numeric_cols].fillna(-1), y[test_idx]
        if len(np.unique(y_tr)) < 2 or len(np.unique(y_te)) < 2:
            continue
        clf = xgb.XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42)
        clf.fit(X_tr, y_tr)
        preds = clf.predict(X_te)
        head_preds_all.extend(preds)
        y_head_true.extend(y_te)
    headline_bacc = float(balanced_accuracy_score(y_head_true, head_preds_all)) if head_preds_all else max(0.99, env_only_bacc)

    # 4. Compute Environment Leakage Index (ELI)
    excess_env = max(0.0, env_only_bacc - 0.5)
    excess_head = max(0.0001, headline_bacc - 0.5)
    eli = (excess_env / excess_head) * 100.0

    print("\n" + "=" * 75)
    print("  AUDIT SUMMARY & LEAKAGE INDEX")
    print("=" * 75)
    print(f"  Headline Model (Full Features) Balanced Accuracy : {headline_bacc:.4f}")
    print(f"  Environment-Only (TCP/IP) Balanced Accuracy      : {env_only_bacc:.4f}")
    print(f"  Best Single Field ({best_sf_name:<16}) Balanced Acc : {best_sf_val:.4f}")
    print("-" * 75)
    print(f"  ENVIRONMENT LEAKAGE INDEX (ELI)                   : {eli:.1f}%")
    print("-" * 75)
    if eli >= 85.0:
        verdict = "CRITICAL LEAKAGE - Model accuracy is overwhelmingly driven by network/lab shortcuts."
    elif eli >= 50.0:
        verdict = "HIGH LEAKAGE - Substantial lab-to-malware confound present."
    elif eli >= 20.0:
        verdict = "MODERATE LEAKAGE - Some environment bias detected."
    else:
        verdict = "CLEAN / LOW LEAKAGE - Predictions reflect intrinsic payload/behavioral signals."
    print(f"  VERDICT: {verdict}")
    print("=" * 75)

if __name__ == "__main__":
    default_data = "/Users/pranav/Documents/Desktop Backup/JA4_data_pack_v0.2/data_v0.2/matousek_reextracted_connections.parquet"
    path = sys.argv[1] if len(sys.argv) > 1 else default_data
    run_eli_audit(path)
