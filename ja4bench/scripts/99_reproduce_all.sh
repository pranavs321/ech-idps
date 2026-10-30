#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo "JA4Bench Full End-to-End Reproducibility Script"
echo "=========================================="

PYTHON=".venv/bin/python"

# 1. Run core unit tests
echo "[Step 1] Running Unit Tests..."
$PYTHON tests/run_tests.py

# 2. Build Matousek canonical & diagnose
echo "[Step 2] Building Matoušek canonical table..."
$PYTHON scripts/10_build_canonical.py --adapter matousek --in data/external/matousek/datasets --out data/canonical/matousek2024.csv.gz
$PYTHON scripts/20_diagnose.py --in data/canonical/matousek2024.csv.gz --out results/audit_all

# 3. Main protocols run
echo "[Step 3] Running main protocols..."
$PYTHON scripts/30_run_protocols.py --in data/canonical/matousek2024.csv.gz --tcp-only --exclude-flag flag_no_capture_id --combos lookup:ja4,xgb:ja4_components,rf:ja4_components,xgb:ja4_plus_sni,xgb:env_only --boot 1000 --out results/protocols_main

# 4. MTA 2024 pipeline (T05-T09)
echo "[Step 4] Running MTA 2024 pipeline..."
$PYTHON scripts/build_t05_mta2024_meta.py
$PYTHON scripts/prepare_and_run_t06.py
$PYTHON scripts/10_build_canonical.py --adapter generic --in data/interim/mta2024_flows_labelled.csv --mapping config/mappings/ja4lab_mta2024.yaml --out data/canonical/mta2024_flow.csv.gz
$PYTHON scripts/20_diagnose.py --in data/canonical/mta2024_flow.csv.gz --tcp-only --out results/audit_mta2024
$PYTHON scripts/30_run_protocols.py --in data/canonical/mta2024_flow.csv.gz --tcp-only --protocols P2_capture,P3_ja4,P4_family --combos lookup:ja4,xgb:ja4_components,xgb:ja4_plus_sni,xgb:env_only --out results/e4_mta_within
$PYTHON scripts/30_run_protocols.py --in data/canonical/matousek2024.csv.gz data/canonical/mta2024_flow.csv.gz --tcp-only --exclude-flag flag_no_capture_id --protocols P7_source --combos lookup:ja4,xgb:ja4_components,xgb:env_only --out results/e5_cross_corpus

# 5. Dataset A pipeline (T10-T11)
echo "[Step 5] Running Dataset A pipeline..."
$PYTHON scripts/build_t10_datasetA.py
$PYTHON scripts/30_run_protocols.py --in data/canonical/datasetA_rebuild.csv.gz --tcp-only --protocols P2_capture,P3_ja4,P8_env_matched --combos lookup:ja4,xgb:ja4_components,xgb:env_only --out results/t11_break_9998

# 6. Tier 2 & Figures (T12-T20)
echo "[Step 6] Running Tier 2 & Figure generation..."
$PYTHON scripts/build_tier2_all.py
$PYTHON scripts/40_make_figures.py --run results/protocols_main --out results/figures

echo "=========================================="
echo "All JA4Bench tasks and evaluations completed successfully!"
echo "=========================================="
