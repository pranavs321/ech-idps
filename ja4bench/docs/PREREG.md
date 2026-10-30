# Pre-registration — commit and tag `prereg-v1` BEFORE training on any confirmatory dataset

Project: *Detecting the Lab, Not the Malware: a leakage-controlled, environment-matched and
counterfactual evaluation of JA4-based malware detection*
Authors: ______________________   Date committed: ____________   Commit: ____________
Tranco list ID (pinned): ____________   ja4lab commit: ____________   ja4bench version: 0.3.0

## 0. Exploratory vs confirmatory (honesty clause)

The public Matoušek corpus was analysed **before** this document was written
(`results_reference/`, 2026-10-06). Results on it are reported as **exploratory**. The hypotheses
below are **confirmatory** only for data not yet modelled at the time of the commit:
MTA 2024 flow-level labels, Dataset A rebuilt from public sources, CTU-SME-11, Stratosphere mixed
captures, Tria.ge/ANY.RUN sandbox-matched sets, MTA 2025–2026.

## 1. Data, units and exclusions (fixed now)

- Unit of analysis: the **capture**. Splits are by capture or coarser; CIs are bootstrap over captures
  (1,000 resamples, percentile 95%, seed 42).
- Scope: TCP/TLS only (`--tcp-only`). QUIC rows are excluded and their count reported.
- Excluded rows: label −1 (gray, ads, unknown); rows without a capture id (`flag_no_capture_id`);
  scan/probe and phishing captures; captures failing the extractor gate; duplicate pcaps (same
  SHA-256, keep one).
- Pre-registered variant: also exclude OS/browser background flows (`flag_os_background`), reported
  beside the main run, never instead of it.
- Labels are never overwritten; every analysis states its `label_basis` mix.

## 2. Protocols

P1 random flow split (reference only) · P2 capture-disjoint · P3 JA4-disjoint · P4 family-disjoint ·
P5 temporal (train ≤ year y, test > y) · P6 leave-one-domain-out (desktop/mobile, or env family) ·
P7 leave-one-source-out (cross-corpus) · P8 environment-matched (only environments containing both
classes, capture-disjoint inside them). 5 folds where applicable, seed 42. Folds lacking a class are
skipped and listed, never filled with constant predictions.

## 3. Models and feature sets (fixed now)

`lookup:ja4` (memorisation baseline) · `xgb:ja4_components` · `rf:ja4_components` ·
`xgb:ja4_plus_sni` (ECH ablation) · `xgb:env_only` (diagnostic: environment fields only) ·
`xgb:ja4_flow` / `xgb:flow` when flow features exist. XGBoost 3.4.1: 300 trees, depth 6, lr 0.1,
`scale_pos_weight` from each training fold. No hyper-parameter tuning on test folds.

## 4. Metrics

Primary: capture-bootstrap ROC-AUC and PR-AUC; host-level alert rate on benign captures (share of
benign captures with ≥1 flow scored ≥ 0.5). Secondary: F1, recall, FPR, balanced accuracy, MCC at
0.5; seen-JA4 rate; label-conflict floor; environment-only ROC-AUC under P2 ("Environment Leakage
Index", ELI).

## 5. Hypotheses (confirmatory datasets only)

- **H1 memorisation.** Under P2, `xgb:ja4_components` ROC-AUC exceeds `lookup:ja4` by < 0.02.
- **H2 confound.** On any corpus whose classes come from different environments, ELI ≥ 0.80.
- **H3 unseen fingerprints.** Under P3, `xgb:ja4_components` ROC-AUC ≤ 0.75 on every corpus.
- **H4 environment-matched collapse.** For each corpus with an environment-matched subset,
  `xgb:ja4_components` ROC-AUC under P8 is lower than under P2 on the full corpus, and its F1 is
  bounded by the subset's label-conflict floor.
- **H5 environment-relative features** (mixed-capture data only: MTA flow-level, CTU-SME-11): features
  expressed relative to the same host's baseline beat absolute features under P6/P7 by ≥ 0.05 ROC-AUC.
- **H6 ECH.** Removing SNI (`ja4_plus_sni` → `ja4_components`) lowers P2 ROC-AUC; the size of the drop
  is reported per corpus (no direction-free claim beyond that).
- **H7 temporal.** Models trained ≤ 2024 lose ≥ 0.10 ROC-AUC on 2025–2026 MTA captures relative to
  P2 on ≤ 2024 data.

A hypothesis is supported only if the bound holds for the point estimate AND the 95% CI does not
cross it. Unsupported hypotheses are reported as results.

## 6. Deliberate leakage test

Run combo `xgbLEAK:ja4_components`, which adds a JA4 target-mean feature computed on ALL rows (test
rows included), next to the clean `xgb:ja4_components`, under P2 and P3. Report the inflation. Under
P3 (unseen fingerprints) the clean model cannot know test fingerprints, so a large gain proves the
harness detects leakage; no gain means the harness is wrong.

## 7. Stopping rules

No new feature sets, models or exclusions after `prereg-v1` except via the deviations log.
Negative results are reported.

## Deviations log

| date | what changed | why | effect on results |
|---|---|---|---|
| | | | |
