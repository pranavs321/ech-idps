#!/usr/bin/env bash
# Verifies the installation. Numbers produced here are SYNTHETIC - never report them.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d third_party/ja4-main ] || bash scripts/get_foxio_reference.sh
python tests/test_reassembly.py
python tests/validate_against_foxio.py
python scripts/make_smoke_data.py --out data/processed/SMOKE_instances.csv
python -m ja4lab.experiments --instances data/processed/SMOKE_instances.csv --out results_SMOKE --quick
echo "SMOKE TEST PASSED (results_SMOKE/ is synthetic, do not use)"
