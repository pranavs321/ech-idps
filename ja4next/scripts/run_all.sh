#!/usr/bin/env bash
# Full exploratory pipeline. Idempotent: every stage skips work already done.
# Logs go to logs/<stage>.log. Never touches the 2022-2026 holdout.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src
mkdir -p logs data/manifests data/labels results

YEARS="${YEARS:-2013-2021}"

echo "[0/7] environment check"
python3 -I scripts/check_env.py | tee logs/00_env.log

echo "[1/7] label feeds (Maltrail trails, SSLBL, Feodo)"
bash scripts/fetch_labels.sh 2>&1 | tee logs/01_labels.log

echo "[2/7] crawl MTA manifest 2013-2026 (2022-2026 listed as holdout, not downloaded)"
[ -f data/manifests/mta_manifest.csv ] || python3 -u -m ja4next.crawl_mta --years 2013-2026 \
    --out data/manifests/mta_manifest.csv 2>&1 | tee logs/02_crawl.log

echo "[3/7] download pcap + IOC zips for $YEARS"
python3 -u -m ja4next.download --manifest data/manifests/mta_manifest.csv --years "$YEARS" \
    2>&1 | tee logs/03_download.log

echo "[4/7] extract + label"
python3 -u -m ja4next.process --workers "${WORKERS:-6}" 2>&1 | tee logs/04_process.log

echo "[5/7] evaluate: all labels, then hostname-only, then gold-only"
python3 -u -m ja4next.evaluate --out results/all 2>&1 | tee logs/05_eval_all.log
python3 -u -m ja4next.evaluate --hostname-only --out results/hostname_only 2>&1 | tee logs/05_eval_hostname.log
python3 -u -m ja4next.evaluate --tiers gold_mal,benign --out results/gold_only 2>&1 | tee logs/05_eval_gold.log

echo "[6/7] second lab (Stratosphere), clean-benign test, incidents, data audit, figures"
bash scripts/run_stratosphere.sh

echo "[7/7] checksums"
find results -type f \( -name '*.csv' -o -name '*.json' \) | sort | xargs sha256sum > results/SHA256SUMS
echo "done"
