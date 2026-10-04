"""
Protocol Evaluation Script for JA4+ Malware Detection Corpus.
Evaluates Random-Flow, Environment-Disjoint, Family-Disjoint, and JA4-Disjoint protocols
across Combined XGBoost, Packet-Size 3-Feature XGBoost, and JA4 Lookup Baseline.
"""

import os
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import StratifiedKFold, GroupKFold, KFold
from sklearn.metrics import f1_score, matthews_corrcoef, precision_recall_curve, auc, roc_curve
from sklearn.preprocessing import OrdinalEncoder

SEEDS = list(range(42, 52)) # 10 seeds: 42..51
DATASET_PATH = "third_party/MalwareDet-JA4vsFlowStats/reproduce-research/nfstream-pipeline/data/nfs_all_datasets_clean_final.csv"

def compute_recall_at_fpr_1e3(y_true, y_proba):
    fpr, tpr, thresholds = roc_curve(y_true, y_proba)
    valid_idx = np.where(fpr <= 1e-3)[0]
    if len(valid_idx) == 0:
        return 0.0
    return float(np.max(tpr[valid_idx]))

def parse_ja4(ja4_str):
    if not isinstance(ja4_str, str) or "_" not in ja4_str:
        return pd.Series([np.nan]*8, index=["ja4_proto", "ja4_ver", "ja4_sni", "ja4_ciphers_cnt", "ja4_exts_cnt", "ja4_alpn", "ja4_b", "ja4_c"])
    parts = ja4_str.split("_")
    ja4_a = parts[0]
    ja4_b = parts[1] if len(parts) > 1 else ""
    ja4_c = parts[2] if len(parts) > 2 else ""
    
    proto = ja4_a[0] if len(ja4_a) > 0 else ""
    ver = ja4_a[1:3] if len(ja4_a) >= 3 else ""
    sni = ja4_a[3] if len(ja4_a) >= 4 else ""
    ciphers_cnt = int(ja4_a[4:6]) if len(ja4_a) >= 6 and ja4_a[4:6].isdigit() else np.nan
    exts_cnt = int(ja4_a[6:8]) if len(ja4_a) >= 8 and ja4_a[6:8].isdigit() else np.nan
    alpn = ja4_a[8:] if len(ja4_a) > 8 else ""
    
    return pd.Series([proto, ver, sni, ciphers_cnt, exts_cnt, alpn, ja4_b, ja4_c],
                     index=["ja4_proto", "ja4_ver", "ja4_sni", "ja4_ciphers_cnt", "ja4_exts_cnt", "ja4_alpn", "ja4_b", "ja4_c"])

def load_data():
    print(f"Loading data from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH, sep=";", low_memory=False)
    
    # Class labels
    malware_folders = ["desktop-malware", "mobile-malware"]
    df["label"] = np.where(df["SourceFolder"].isin(malware_folders), 1, 0)
    
    # Environment platform
    df["platform"] = df["SourceFolder"].apply(lambda x: "desktop" if "desktop" in str(x) else "mobile")
    
    # Core flow features
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
    
    # 3 Packet size features
    ps3_cols = ['bidirectional_mean_ps', 'src2dst_mean_ps', 'dst2src_mean_ps']
    
    # JA4 features
    ja4_features = df["udps.ja4"].apply(parse_ja4)
    
    # Pre-encode categoricals
    cat_cols = ["ja4_proto", "ja4_ver", "ja4_sni", "ja4_alpn", "ja4_b", "ja4_c"]
    for col in cat_cols:
        ja4_features[col] = ja4_features[col].astype(str)
        oe = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
        ja4_features[col] = oe.fit_transform(ja4_features[[col]])
        
    X_combined = pd.concat([df[core_flow_cols], ja4_features], axis=1).values
    X_ps3 = df[ps3_cols].values
    
    return df, X_combined, X_ps3

def evaluate_ja4_lookup(y_train, ja4_train, y_test, ja4_test):
    train_df = pd.DataFrame({'ja4': ja4_train, 'label': y_train})
    overall_majority = int(train_df['label'].mode()[0])
    overall_prob = float(train_df['label'].mean())
    
    group_stats = train_df.groupby('ja4')['label'].agg(['count', 'mean']).reset_index()
    group_stats['majority'] = (group_stats['mean'] >= 0.5).astype(int)
    lookup_map = dict(zip(group_stats['ja4'], group_stats['majority']))
    prob_map = dict(zip(group_stats['ja4'], group_stats['mean']))
    
    y_pred = []
    y_proba = []
    covered_cnt = 0
    for ja in ja4_test:
        if ja in lookup_map:
            y_pred.append(lookup_map[ja])
            y_proba.append(prob_map[ja])
            covered_cnt += 1
        else:
            y_pred.append(overall_majority)
            y_proba.append(overall_prob)
            
    coverage = covered_cnt / len(ja4_test) if len(ja4_test) > 0 else 0.0
    return np.array(y_pred), np.array(y_proba), coverage

def run_evaluation():
    df, X_combined, X_ps3 = load_data()
    y = df["label"].values
    ja4_series = df["udps.ja4"].fillna("").values
    families = df["StandardizedAppName"].fillna("").values
    platforms = df["platform"].values
    
    protocols = ["random-flow", "environment-disjoint", "family-disjoint", "ja4-disjoint"]
    models = ["combined", "packet_size_3feat", "ja4_lookup"]
    
    results_store = { (p, m): {"mcc": [], "pr_auc": [], "rec_fpr": [], "f1": [], "trivial_f1": [], "coverage": []}
                     for p in protocols for m in models }
    
    for seed in SEEDS:
        print(f"--- Running Seed {seed} ---")
        
        # Protocol 1: Random Flow (5-fold)
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
        splits_random = list(skf.split(X_combined, y))
        
        # Protocol 3: Family Disjoint (5-fold)
        # Using KFold on unique families to assign families to folds
        unique_fams = pd.Series(families).unique()
        kf_fam = KFold(n_splits=5, shuffle=True, random_state=seed)
        fam_fold_map = {}
        for fold_i, (_, val_fam_idx) in enumerate(kf_fam.split(unique_fams)):
            for fam in unique_fams[val_fam_idx]:
                fam_fold_map[fam] = fold_i
        splits_family = []
        df_fam_series = pd.Series(families)
        for fold_i in range(5):
            val_idx = df_fam_series[df_fam_series.map(fam_fold_map) == fold_i].index.values
            train_idx = df_fam_series[df_fam_series.map(fam_fold_map) != fold_i].index.values
            splits_family.append((train_idx, val_idx))
            
        # Protocol 4: JA4 Disjoint (5-fold)
        unique_ja4s = pd.Series(ja4_series).unique()
        kf_ja4 = KFold(n_splits=5, shuffle=True, random_state=seed)
        ja4_fold_map = {}
        for fold_i, (_, val_ja4_idx) in enumerate(kf_ja4.split(unique_ja4s)):
            for ja in unique_ja4s[val_ja4_idx]:
                ja4_fold_map[ja] = fold_i
        splits_ja4 = []
        df_ja4_series = pd.Series(ja4_series)
        for fold_i in range(5):
            val_idx = df_ja4_series[df_ja4_series.map(ja4_fold_map) == fold_i].index.values
            train_idx = df_ja4_series[df_ja4_series.map(ja4_fold_map) != fold_i].index.values
            splits_ja4.append((train_idx, val_idx))

        # Helper to execute 5-fold evaluation for a protocol
        def eval_kfold(protocol_name, splits):
            for model_name in models:
                y_true_all, y_pred_all, y_proba_all = [], [], []
                triv_pred_all = []
                coverages = []
                
                for train_idx, val_idx in splits:
                    y_tr, y_va = y[train_idx], y[val_idx]
                    maj_tr = int(pd.Series(y_tr).mode()[0])
                    triv_pred_all.extend([maj_tr]*len(y_va))
                    y_true_all.extend(y_va)
                    
                    if model_name == "combined":
                        clf = xgb.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, random_state=seed, n_jobs=-1, eval_metric="logloss")
                        clf.fit(X_combined[train_idx], y_tr)
                        pred = clf.predict(X_combined[val_idx])
                        prob = clf.predict_proba(X_combined[val_idx])[:, 1]
                        coverages.append(1.0)
                    elif model_name == "packet_size_3feat":
                        clf = xgb.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, random_state=seed, n_jobs=-1, eval_metric="logloss")
                        clf.fit(X_ps3[train_idx], y_tr)
                        pred = clf.predict(X_ps3[val_idx])
                        prob = clf.predict_proba(X_ps3[val_idx])[:, 1]
                        coverages.append(1.0)
                    elif model_name == "ja4_lookup":
                        pred, prob, cov = evaluate_ja4_lookup(y_tr, ja4_series[train_idx], y_va, ja4_series[val_idx])
                        coverages.append(cov)
                        
                    y_pred_all.extend(pred)
                    y_proba_all.extend(prob)
                    
                y_true_all = np.array(y_true_all)
                y_pred_all = np.array(y_pred_all)
                y_proba_all = np.array(y_proba_all)
                triv_pred_all = np.array(triv_pred_all)
                
                mcc = matthews_corrcoef(y_true_all, y_pred_all)
                prec, rec, _ = precision_recall_curve(y_true_all, y_proba_all)
                pr_auc_val = auc(rec, prec)
                rec_fpr = compute_recall_at_fpr_1e3(y_true_all, y_proba_all)
                f1_val = f1_score(y_true_all, y_pred_all, zero_division=0)
                triv_f1_val = f1_score(y_true_all, triv_pred_all, zero_division=0)
                avg_cov = float(np.mean(coverages))
                
                results_store[(protocol_name, model_name)]["mcc"].append(mcc)
                results_store[(protocol_name, model_name)]["pr_auc"].append(pr_auc_val)
                results_store[(protocol_name, model_name)]["rec_fpr"].append(rec_fpr)
                results_store[(protocol_name, model_name)]["f1"].append(f1_val)
                results_store[(protocol_name, model_name)]["trivial_f1"].append(triv_f1_val)
                results_store[(protocol_name, model_name)]["coverage"].append(avg_cov)

        eval_kfold("random-flow", splits_random)
        eval_kfold("family-disjoint", splits_family)
        eval_kfold("ja4-disjoint", splits_ja4)
        
        # Protocol 2: Environment Disjoint (Desktop <-> Mobile)
        desk_idx = np.where(platforms == "desktop")[0]
        mob_idx = np.where(platforms == "mobile")[0]
        
        def eval_env_disjoint():
            # Direction A: Train Desktop, Test Mobile
            # Direction B: Train Mobile, Test Desktop
            dirs = [(desk_idx, mob_idx), (mob_idx, desk_idx)]
            for model_name in models:
                y_true_all, y_pred_all, y_proba_all = [], [], []
                triv_pred_all = []
                coverages = []
                
                for train_idx, val_idx in dirs:
                    y_tr, y_va = y[train_idx], y[val_idx]
                    maj_tr = int(pd.Series(y_tr).mode()[0])
                    triv_pred_all.extend([maj_tr]*len(y_va))
                    y_true_all.extend(y_va)
                    
                    if model_name == "combined":
                        clf = xgb.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, random_state=seed, n_jobs=-1, eval_metric="logloss")
                        clf.fit(X_combined[train_idx], y_tr)
                        pred = clf.predict(X_combined[val_idx])
                        prob = clf.predict_proba(X_combined[val_idx])[:, 1]
                        coverages.append(1.0)
                    elif model_name == "packet_size_3feat":
                        clf = xgb.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, random_state=seed, n_jobs=-1, eval_metric="logloss")
                        clf.fit(X_ps3[train_idx], y_tr)
                        pred = clf.predict(X_ps3[val_idx])
                        prob = clf.predict_proba(X_ps3[val_idx])[:, 1]
                        coverages.append(1.0)
                    elif model_name == "ja4_lookup":
                        pred, prob, cov = evaluate_ja4_lookup(y_tr, ja4_series[train_idx], y_va, ja4_series[val_idx])
                        coverages.append(cov)
                        
                    y_pred_all.extend(pred)
                    y_proba_all.extend(prob)
                    
                y_true_all = np.array(y_true_all)
                y_pred_all = np.array(y_pred_all)
                y_proba_all = np.array(y_proba_all)
                triv_pred_all = np.array(triv_pred_all)
                
                mcc = matthews_corrcoef(y_true_all, y_pred_all)
                prec, rec, _ = precision_recall_curve(y_true_all, y_proba_all)
                pr_auc_val = auc(rec, prec)
                rec_fpr = compute_recall_at_fpr_1e3(y_true_all, y_proba_all)
                f1_val = f1_score(y_true_all, y_pred_all, zero_division=0)
                triv_f1_val = f1_score(y_true_all, triv_pred_all, zero_division=0)
                avg_cov = float(np.mean(coverages))
                
                results_store[("environment-disjoint", model_name)]["mcc"].append(mcc)
                results_store[("environment-disjoint", model_name)]["pr_auc"].append(pr_auc_val)
                results_store[("environment-disjoint", model_name)]["rec_fpr"].append(rec_fpr)
                results_store[("environment-disjoint", model_name)]["f1"].append(f1_val)
                results_store[("environment-disjoint", model_name)]["trivial_f1"].append(triv_f1_val)
                results_store[("environment-disjoint", model_name)]["coverage"].append(avg_cov)
                
        eval_env_disjoint()
        
    # Build final summary table
    os.makedirs("results", exist_ok=True)
    summary_rows = []
    
    print("\n============================================ PROTOCOL GRID RESULTS ============================================")
    for (protocol, model), m_dict in results_store.items():
        mcc_med, mcc_min, mcc_max = np.median(m_dict["mcc"]), np.min(m_dict["mcc"]), np.max(m_dict["mcc"])
        pr_med, pr_min, pr_max = np.median(m_dict["pr_auc"]), np.min(m_dict["pr_auc"]), np.max(m_dict["pr_auc"])
        rec_med, rec_min, rec_max = np.median(m_dict["rec_fpr"]), np.min(m_dict["rec_fpr"]), np.max(m_dict["rec_fpr"])
        f1_med, f1_min, f1_max = np.median(m_dict["f1"]), np.min(m_dict["f1"]), np.max(m_dict["f1"])
        triv_med = np.median(m_dict["trivial_f1"])
        cov_med = np.median(m_dict["coverage"])
        
        row = {
            "protocol": protocol,
            "model": model,
            "mcc_median": round(mcc_med, 4),
            "mcc_range": f"[{round(mcc_min, 4)}, {round(mcc_max, 4)}]",
            "pr_auc_median": round(pr_med, 4),
            "pr_auc_range": f"[{round(pr_min, 4)}, {round(pr_max, 4)}]",
            "rec_fpr_1e3_median": round(rec_med, 4),
            "rec_fpr_1e3_range": f"[{round(rec_min, 4)}, {round(rec_max, 4)}]",
            "f1_median": round(f1_med, 4),
            "f1_range": f"[{round(f1_min, 4)}, {round(f1_max, 4)}]",
            "trivial_f1": round(triv_med, 4),
            "coverage": round(cov_med, 4)
        }
        summary_rows.append(row)

    out_df = pd.DataFrame(summary_rows)
    out_df.to_csv("results/protocol_grid.csv", index=False)
    
    print(out_df.to_string(index=False))
    print("===============================================================================================================\n")

if __name__ == "__main__":
    run_evaluation()
