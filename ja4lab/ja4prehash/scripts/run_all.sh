#!/usr/bin/env bash
# Full pipeline on YOUR data in data/raw/<benign|malicious>/<source>/<family>/*.pcap
set -euo pipefail
cd "$(dirname "$0")/.."
python -m ja4lab.extract --pcap-root data/raw --out data/interim/connections.csv
ARGS=""
[ -f data/meta/infected_hosts.csv ] && ARGS="$ARGS --infected data/meta/infected_hosts.csv"
[ -f data/meta/tranco.csv ] && ARGS="$ARGS --tranco data/meta/tranco.csv --tranco-top 10000"
python -m ja4lab.label --in data/interim/connections.csv --out data/processed/instances.csv $ARGS
python -m ja4lab.experiments --instances data/processed/instances.csv --out results
python -m ja4lab.threatintel coverage --instances data/processed/instances.csv --out results || true
python -m ja4lab.threatintel benchmark --out results || true
python scripts/measure_extraction_gap.py --pcap-root data/raw --out results/extraction_gap.csv
echo "Done. Open results/SUMMARY.md"
