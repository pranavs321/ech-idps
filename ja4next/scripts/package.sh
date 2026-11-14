#!/usr/bin/env bash
# Build ja4next.zip for the team: code, docs, Antigravity config, manifests, processed features, results.
# Leaves out raw pcaps, the HTML cache and third-party label dumps (fetch them again with scripts/fetch_labels.sh).
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-../ja4next.zip}"
rm -f "$out"
zip -qr "$out" . \
  -x "data/raw/*" "data/interim/*" "data/interim_holdout/*" "data/manifests/mta_html_cache/*" \
     "data/labels/maltrail/*" "data/labels/*.gz" "data/labels/*.csv" ".venv/*" "*/__pycache__/*" \
     "*.pyc" ".git/*" "logs/*.pid" "trash/*" ".pytest_cache/*"
ls -la "$out"
