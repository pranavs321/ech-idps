#!/usr/bin/env bash
# JA4DB frozen community snapshot (public API closed in 2026) + FoxIO mapping file
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data/ti
curl -sL -o data/ti/ja4db_all_records.csv https://raw.githubusercontent.com/Niicolaa/ja4db-export/main/csv/all_records.csv
curl -sL -o data/ti/ja4plus-mapping.csv https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv
wc -l data/ti/*.csv
