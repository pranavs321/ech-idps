#!/usr/bin/env bash
# Second-lab stage: Stratosphere MCFP botnet + Mixed + Normal captures. Idempotent (fetch scripts resume).
# Downloads one pcap at a time, extracts TLS rows, deletes the pcap. ~45 GB transferred, ~10 GB peak disk.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src
mkdir -p logs results data/manifests
echo "[s1] manifests + READMEs"
[ -f data/manifests/mcfp_pcaps.csv ] || python3 -m ja4next.crawl_mcfp
echo "[s2] fetch + extract (resume-safe)"
python3 -I -u scripts/fetch_mcfp.py  --max-mb 120  2>&1 | tee logs/fetch_mcfp.log
python3 -I -u scripts/fetch_mcfp2.py --max-mb 9000 2>&1 | tee logs/fetch_mcfp2.log
python3 -I -u scripts/fetch_mcfp3.py --max-mb 1300 2>&1 | tee logs/fetch_mcfp3.log
echo "[s3] labels"
python3 -I scripts/label_mcfp.py 2>&1 | tee logs/label_mcfp.log
echo "[s4] experiments: second lab (strict, weak), clean foreign benign, incident grouping"
python3 -u -m ja4next.second_lab 2>&1 | tee logs/second_lab.log
MCFP_LABELS=weak python3 -u -m ja4next.second_lab 2>&1 | tee logs/second_lab_weak.log
python3 -u -m ja4next.foreign_benign 2>&1 | tee logs/foreign_benign.log
python3 -u -m ja4next.incidents 2>&1 | tee logs/incidents.log
python3 -u -m ja4next.feature_direction 2>&1 | tee logs/feature_direction.log
echo "[s5] audit + figures"
python3 -I scripts/data_quality.py > logs/data_quality.log
python3 -I scripts/make_figures.py
echo "stratosphere stage done"
