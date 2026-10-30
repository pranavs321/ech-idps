# Protocol results (generated; do not edit by hand)

```json
{
  "utc": "2026-10-07T10:05:37+00:00",
  "ja4bench": "0.3.0",
  "python": "3.12.3",
  "pandas": "3.0.2",
  "numpy": "2.4.4",
  "args": {
    "inp": [
      "data/canonical/matousek2024.csv.gz"
    ],
    "out": "results_reference/leak_test",
    "protocols": "P2_capture,P3_ja4",
    "combos": "xgb:ja4_components,xgbLEAK:ja4_components",
    "domain_col": "platform",
    "k": 5,
    "seed": 42,
    "boot": 1000,
    "tcp_only": true,
    "exclude_flag": [
      "flag_no_capture_id"
    ],
    "only_env": []
  },
  "input_sha256": {
    "data/canonical/matousek2024.csv.gz": "1888415bff4645b7d02e06bb0d8a7902fdf7af0f47ec3448e825eea7d41283c7"
  },
  "filters": [
    "label in {0,1}: 30664 -> 21127",
    "tcp-only: 21127 -> 20148",
    "exclude flag_no_capture_id: 20148 -> 18704"
  ],
  "rows_used": 18704,
  "captures_used": 1421,
  "train_runtime_s": 44,
  "sklearn": "1.8.0",
  "xgboost": "3.4.1",
  "summarised_from": "oof.csv.gz"
}
```

Flow-level metrics pooled over out-of-fold predictions; [95% CI] = bootstrap over captures.
cap_alert_benign = share of BENIGN captures with >=1 flow scored >= 0.5 (host-level false alarms).
seen_ja4 = share of test rows whose exact JA4 occurred in training.
fold ROC-AUC = mean (min) of per-fold ROC-AUC. When it differs from the pooled value, trust the
per-fold value: pooling mixes folds with different score scales. For P5/P6/P7 read folds.csv.

| protocol | combo | ROC-AUC pooled | fold ROC-AUC | PR-AUC | F1 | recall | FPR | cap ROC-AUC | cap_alert_benign | seen_ja4 | n_test | captures |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P2_capture | xgb:ja4_components | 0.908 [0.882, 0.931] | 0.911 (0.885) | 0.967 [0.955, 0.976] | 0.886 [0.863, 0.903] | 0.835 | 0.177 | 0.939 | 0.306 | 0.99 | 18704 | 1421 |
| P2_capture | xgbLEAK:ja4_components | 0.912 [0.885, 0.935] | 0.916 (0.893) | 0.969 [0.959, 0.978] | 0.888 [0.866, 0.906] | 0.839 | 0.176 | 0.942 | 0.302 | 0.99 | 18704 | 1421 |
| P3_ja4 | xgb:ja4_components | 0.857 [0.827, 0.881] | 0.808 (0.604) | 0.943 [0.922, 0.960] | 0.847 [0.825, 0.867] | 0.785 | 0.239 | 0.918 | 0.367 | 0.00 | 18704 | 1421 |
| P3_ja4 | xgbLEAK:ja4_components | 0.918 [0.895, 0.936] | 0.849 (0.643) | 0.968 [0.957, 0.977] | 0.889 [0.867, 0.907] | 0.837 | 0.162 | 0.948 | 0.290 | 0.00 | 18704 | 1421 |

## Skipped folds

none
