#!/usr/bin/env bash
# Run ONE pipeline stage for an agent (Antigravity) or a human.
#   - idempotent: state/<stage>.done marks success (use --force to redo)
#   - single instance: logs/<stage>.pid
#   - non-interactive: stdin from /dev/null
#   - output: logs/<stage>.log ; exit code: logs/<stage>.exitcode (the source of truth)
# Works with macOS bash 3.2.
# Usage: scripts/run_stage.sh <env|labels|crawl|download|process|evaluate|confirm> [--force]
set -o pipefail
stage="${1:?usage: scripts/run_stage.sh <stage> [--force]}"
cd "$(dirname "$0")/.." || exit 2
mkdir -p logs state
log="logs/$stage.log"; pidf="logs/$stage.pid"; rcf="logs/$stage.exitcode"; donef="state/$stage.done"
if [ -f "$donef" ] && [ "${2:-}" != "--force" ]; then
  echo "SKIP $stage: done at $(cat "$donef") (use --force to redo)"; exit 0; fi
if [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then
  echo "BUSY $stage: pid $(cat "$pidf"); watch: tail -n 20 $log"; exit 0; fi
echo $$ > "$pidf"; rm -f "$rcf"
PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
export PYTHONPATH=src PYTHONUNBUFFERED=1
YEARS="${YEARS:-2013-2021}"
echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) START $stage" >> "$log"
case "$stage" in
  env)      "$PY" scripts/check_env.py ;;
  labels)   bash scripts/fetch_labels.sh ;;
  crawl)    "$PY" -m ja4next.crawl_mta --years 2013-2026 --out data/manifests/mta_manifest.csv ;;
  download) "$PY" -m ja4next.download --manifest data/manifests/mta_manifest.csv --years "$YEARS" ;;
  process)  "$PY" -m ja4next.process --workers "${WORKERS:-6}" ;;
  evaluate) "$PY" -m ja4next.evaluate --out results/all &&
            "$PY" -m ja4next.evaluate --hostname-only --out results/hostname_only &&
            "$PY" -m ja4next.evaluate --tiers gold_mal,benign --out results/gold_only ;;
  confirm)  if [ ! -f docs/PREREG_FROZEN.sha256 ]; then
              echo "REFUSED: freeze the pre-registration first (docs/PREREG_ADDENDUM.md + its sha256 signed off by the guide)"; false
            else
              "$PY" -m ja4next.download --manifest data/manifests/mta_manifest.csv --years 2022-2026 \
                    --allow-holdout --index data/manifests/mta_files_holdout.csv --root data/raw/mta_holdout &&
              "$PY" -m ja4next.confirm --frozen docs/PREREG_FROZEN.sha256
            fi ;;
  *) echo "unknown stage $stage"; false ;;
esac < /dev/null >> "$log" 2>&1
rc=$?
echo "$rc" > "$rcf"; rm -f "$pidf"
echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) END $stage rc=$rc" >> "$log"
[ "$rc" -eq 0 ] && date -u +%Y-%m-%dT%H:%M:%SZ > "$donef"
tail -n 15 "$log"
exit "$rc"
