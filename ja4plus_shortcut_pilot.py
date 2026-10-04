"""
Pilot script to reproduce ~98% F1 on the public JA4+ corpus using a random 5-fold split.
"""

import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score, matthews_corrcoef, precision_recall_curve, auc
from sklearn.preprocessing import OrdinalEncoder

RANDOM_SEED = 42
print(f"Random seed: {RANDOM_SEED}")

# Load dataset
dataset_path = "third_party/MalwareDet-JA4vsFlowStats/reproduce-research/nfstream-pipeline/data/nfs_all_datasets_clean_final.csv"
print(f"Loading dataset from {dataset_path}...")
df = pd.read_csv(dataset_path, sep=";", low_memory=False)

# Labels: malware = 1 (desktop-malware, mobile-malware), benign = 0 (desktop-apps, mobile-apps)
malware_folders = ["desktop-malware", "mobile-malware"]
df["label"] = np.where(df["SourceFolder"].isin(malware_folders), 1, 0)

# Class balance
class_counts = df["label"].value_counts().to_dict()
num_malware = class_counts.get(1, 0)
num_benign = class_counts.get(0, 0)
total_samples = len(df)
majority_class = df["label"].mode()[0]
majority_count = class_counts[majority_class]

# Trivial baseline (always predict majority class)
y_true = df["label"].values
y_trivial = np.full_like(y_true, majority_class)
trivial_f1 = f1_score(y_true, y_trivial, zero_division=0)

print("=== Class Balance ===")
print(f"Total samples: {total_samples}")
print(f"Malware (1): {num_malware} ({num_malware/total_samples*100:.2f}%)")
print(f"Benign (0): {num_benign} ({num_benign/total_samples*100:.2f}%)")
print(f"Trivial Baseline F1 (always predict {majority_class}): {trivial_f1:.4f}")

# Extract flow features
core_flow_cols = [
    'bidirectional_duration_ms', 'src2dst_duration_ms', 'dst2src_duration_ms',
    'bidirectional_bytes', 'src2dst_bytes', 'dst2src_bytes',
    'bidirectional_packets', 'src2dst_packets', 'dst2src_packets',
    'bidirectional_mean_ps', 'bidirectional_stddev_ps', 'bidirectional_min_ps', 'bidirectional_max_ps',
    'src2dst_mean_ps', 'src2dst_stddev_ps', 'src2dst_min_ps', 'src2dst_max_ps',
    'dst2src_mean_ps', 'dst2src_stddev_ps', 'dst2src_min_ps', 'dst2src_max_ps',
    'bidirectional_mean_piat_ms', 'bidirectional_stddev_piat_ms', 'bidirectional_min_piat_ms', 'bidirectional_max_piat_ms',
    'src2dst_mean_piat_ms', 'src2dst_stddev_piat_ms', 'src2dst_min_piat_ms', 'src2dst_max_piat_ms',
    'dst2src_mean_piat_ms', 'dst2src_stddev_piat_ms', 'dst2src_min_piat_ms', 'dst2src_max_piat_ms'
]

# Extract JA4 component features from udps.ja4
def parse_ja4(ja4_str):
    if not isinstance(ja4_str, str) or "_" not in ja4_str:
        return pd.Series([np.nan]*8, index=["ja4_proto", "ja4_ver", "ja4_sni", "ja4_ciphers_cnt", "ja4_exts_cnt", "ja4_alpn", "ja4_b", "ja4_c"])
    parts = ja4_str.split("_")
    ja4_a = parts[0]
    ja4_b = parts[1] if len(parts) > 1 else ""
    ja4_c = parts[2] if len(parts) > 2 else ""
    
    # ja4_a format e.g. t13d151600 or t12d1909h2
    proto = ja4_a[0] if len(ja4_a) > 0 else ""
    ver = ja4_a[1:3] if len(ja4_a) >= 3 else ""
    sni = ja4_a[3] if len(ja4_a) >= 4 else ""
    ciphers_cnt = int(ja4_a[4:6]) if len(ja4_a) >= 6 and ja4_a[4:6].isdigit() else np.nan
    exts_cnt = int(ja4_a[6:8]) if len(ja4_a) >= 8 and ja4_a[6:8].isdigit() else np.nan
    alpn = ja4_a[8:] if len(ja4_a) > 8 else ""
    
    return pd.Series([proto, ver, sni, ciphers_cnt, exts_cnt, alpn, ja4_b, ja4_c],
                     index=["ja4_proto", "ja4_ver", "ja4_sni", "ja4_ciphers_cnt", "ja4_exts_cnt", "ja4_alpn", "ja4_b", "ja4_c"])

ja4_features = df["udps.ja4"].apply(parse_ja4)

# Prepare combined dataframe
X_df = pd.concat([df[core_flow_cols], ja4_features], axis=1)

# Categorical columns to encode
cat_cols = ["ja4_proto", "ja4_ver", "ja4_sni", "ja4_alpn", "ja4_b", "ja4_c"]
for col in cat_cols:
    X_df[col] = X_df[col].astype(str)
    oe = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
    X_df[col] = oe.fit_transform(X_df[[col]])

# 5-fold Stratified K-Fold Random Split
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)

f1_scores = []
mcc_scores = []
pr_auc_scores = []

X = X_df.values
y = df["label"].values

print("\n=== Running 5-Fold Cross-Validation ===")
for fold, (train_idx, val_idx) in enumerate(skf.split(X, y)):
    X_train, X_val = X[train_idx], X[val_idx]
    y_train, y_val = y[train_idx], y[val_idx]
    
    clf = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        random_state=RANDOM_SEED,
        n_jobs=-1,
        eval_metric="logloss"
    )
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_val)
    y_proba = clf.predict_proba(X_val)[:, 1]
    
    f1 = f1_score(y_val, y_pred)
    mcc = matthews_corrcoef(y_val, y_pred)
    precision, recall, _ = precision_recall_curve(y_val, y_proba)
    pr_auc = auc(recall, precision)
    
    f1_scores.append(f1)
    mcc_scores.append(mcc)
    pr_auc_scores.append(pr_auc)
    print(f"Fold {fold+1}: F1 = {f1:.4f}, MCC = {mcc:.4f}, PR-AUC = {pr_auc:.4f}")

mean_f1 = np.mean(f1_scores)
mean_mcc = np.mean(mcc_scores)
mean_pr_auc = np.mean(pr_auc_scores)

print("\n=== Random-Split Combined XGBoost Results ===")
print(f"Mean F1:     {mean_f1:.4f}")
print(f"Mean MCC:    {mean_mcc:.4f}")
print(f"Mean PR-AUC: {mean_pr_auc:.4f}")
