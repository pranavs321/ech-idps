#!/usr/bin/env bash
# Label feeds. Re-run to refresh; each file is dated in labels/FETCHED.txt.
set -euo pipefail
cd "$(dirname "$0")/../data/labels"
[ -d maltrail ] || git clone -q --depth 1 https://github.com/stamparm/maltrail.git
curl -sfL -o trails.csv.gz https://github.com/stamparm/trails/releases/latest/download/trails.csv.gz
curl -sf -o sslbl.abuse.ch_blacklist_sslblacklist.csv https://sslbl.abuse.ch/blacklist/sslblacklist.csv
curl -sf -o sslbl.abuse.ch_blacklist_ja3_fingerprints.csv https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
curl -sf -o feodotracker.abuse.ch_downloads_ipblocklist_aggressive.csv https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv
# ThreatFox / URLhaus full exports now need a free abuse.ch Auth-Key (the old URLs return 410).
# Put your key in ABUSECH_AUTH_KEY to fetch them:
if [ -n "${ABUSECH_AUTH_KEY:-}" ]; then
  curl -sf -H "Auth-Key: $ABUSECH_AUTH_KEY" -o threatfox_full.csv.zip "https://threatfox.abuse.ch/export/csv/full/" || echo "ThreatFox export failed"
fi
date -u +"%Y-%m-%dT%H:%MZ fetched" > FETCHED.txt
ls -la
