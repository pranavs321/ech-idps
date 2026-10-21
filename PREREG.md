# Pre-registration (committed BEFORE training on real data)

**Project:** Detecting the Lab, Not the Malware: a leakage-controlled, cross-environment and counterfactual evaluation of JA4-based malware detection.  
**Date committed:** 2026-10-04  

---

## Data and labels
- **Sources and roles:** Configured in `config/sources.yaml` at this commit. Labels are flow-level (see README "How labels work").
- **Exclusions (fixed now):**
  - Gray flows
  - Scan/probe and phishing captures
  - QUIC (TCP/TLS only)
  - Captures that fail the extractor gate
  - Duplicate PCAPs (identical SHA-256: keep exactly one copy)
- **Unit of analysis:** The capture.
- **Confidence intervals:** Bootstrap over captures (1,000 resamples).

---

## Protocols
- **P1:** Random flow split (reference only)
- **P2:** Capture-disjoint
- **P3:** JA4-disjoint
- **P4:** Family-disjoint
- **P5:** Temporal (train $\le 2023 \to$ test 2024; train $\le 2024 \to$ test 2025–2026)
- **P6:** Leave-one-env_group-out
- **P7:** Matched captures only
- **P8:** Frozen models on the grid  
*Settings:* 5 folds, 10 seeds; median and range reported.

---

## Models (fixed hyperparameters, no tuning)
- `always_malicious`, `ja4_lookup`, `env_only`, `xgb_behaviour`, `xgb_ja4`, `xgb_combined`, `xgb_combined_no_server`, `rbg` (proposed), `rbg_no_dst`
- Sanity checks: `logreg` and `rf`
- **XGBoost Hyperparameters:** 300 trees, depth 6, learning rate 0.1, subsample 0.8, colsample 0.8, `scale_pos_weight` from the training fold.
- **Thresholds:** Chosen to maximize MCC on an inner capture-grouped validation split of the training fold only.

---

## Metrics
- **Lead Metrics:** MCC, PR-AUC, recall at FPR $10^{-3}$ (with resolution $1/n_{\text{neg}}$).
- **F1 Score:** Always shown alongside its trivial baseline value.
- **Capture-Level Metrics:** Per-capture recall/FPR and number of single-class test captures reported.

---

## Hypotheses
- **H1:** P1 MCC of `xgb_combined` exceeds its P3, P4, and P6 MCC by more than the bootstrap interval.
- **H2:** `env_only` reaches $\text{MCC} \ge 0.5$ under P1 on at least one public corpus.
- **H3:** Under P6, every learned model falls to $\text{MCC} \le 0.2$.
- **H4:** On the grid, the `xgb_ja4` score varies more across clients than across behaviours ($\eta^2$).
- **H5:** `rbg` loses less MCC from P1 to $\text{mean}(P6, P7)$ than `xgb_combined`.

---

## Controls
- **Deliberate leakage self-test:** Vocabulary fit on all rows + threshold tuned on test must inflate P1.
- **Label-rule check:** `xgb_combined_no_server` and `rbg_no_dst` reported beside their full versions.
- **Reporting:** Negative results are reported as results.

---

## Amendments (Exploratory Findings Follow-Up)

**Date committed:** 2026-10-21  
**No model is trained or scored on confirmatory data before this file is committed.**

### A1. Environment Baseline Requirement
Report an `env_only` baseline (TCP/IP fields only: JA4T and JA4TS parts and initial TTLs) beside every JA4 result.

### A2. Combined Disjoint Protocol
Add a combined split with no shared capture AND no shared JA4 value.

### A3. Transport Artifact Ablation
Report every result with and without JA4T/JA4TS fields.

