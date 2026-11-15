---
trigger: always_on
description: "Safety, holdout and long-running-job rules for the ja4next PCAP -> JA4 -> XGBoost pipeline."
---

# Pipeline guardrails

## Files and safety
- Work only inside this workspace. Never touch ~/.ssh, ~/.gemini or any .env file.
- `data/raw/` and `results/` are append-only: never delete, move or overwrite files there. To discard output, move it to `trash/<YYYYMMDD-HHMM>/`.
- Never run: rm -rf, sudo, git push, git reset --hard, git clean, find ... -delete, brew install, or pip install outside .venv. If one seems needed, stop and ask me.
- Never use the browser to download data. All downloads go through `scripts/run_stage.sh`.
- Never download, unzip or open any file whose name contains "malware". Never execute files from `data/raw/`.
- HOLDOUT: never fetch or read malware-traffic-analysis.net posts from 2022-2026 and never pass `--allow-holdout`. The `confirm` stage is run by a human only.

## Running stages (long jobs)
- Run stages ONLY with `scripts/run_stage.sh <stage>`. One stage at a time. The runner skips finished stages (`state/<stage>.done`) and refuses a second copy (`logs/<stage>.pid`). Never delete those files to "unstick" a run; ask me.
- If a run goes to the background, do not sleep-loop. Use /schedule to check every 10 minutes with `tail -n 20 logs/<stage>.log; cat logs/<stage>.exitcode`. The exit-code file is the source of truth.
- Commands must be non-interactive. Never print whole logs, pcaps, CSV or Parquet files; use tail, head -n 20, wc -l, du -sh or a short Python summary.
- If a stage fails twice with the same error, stop, write the diagnosis to `logs/BLOCKERS.md` and ask me.

## Code
- Use `.venv/bin/python`. Run `.venv/bin/python -m pytest -q tests` after every code change.
- Do not change seeds, splits, XGBoost settings or feature lists without writing the change and its reason to `logs/CHANGES.md`.
- Never add SNI text, server IP, client IP, capture id or allowlist membership as model features.

## Reporting
- Every number in `docs/` or `reports/` must cite the `results/` file it came from.
- After each stage append 3-5 lines to `logs/PROGRESS.md`: what ran, outputs, row counts, wall time, exit code.
