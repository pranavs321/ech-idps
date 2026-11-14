---
name: fetch-data
description: Stages 1-3. Fetches label feeds, crawls the malware-traffic-analysis.net manifest (2022-2026 listed as holdout only) and downloads pcap + IOC zips for 2013-2021. Use when asked to get or update data.
---

# Stages 1-3: labels, manifest, downloads

Follow the always-on pipeline guardrails rule. Never pass --allow-holdout.

1. `scripts/run_stage.sh labels`. Then `ls -la data/labels | head -n 20`. ThreatFox/URLhaus need an abuse.ch Auth-Key (ABUSECH_AUTH_KEY); skip them if not set.
2. `scripts/run_stage.sh crawl` (about 45-60 minutes at 1 request per second; polite on purpose, do not speed it up). Check every 10 minutes with /schedule: `tail -n 5 logs/crawl.log; cat logs/crawl.exitcode`.
3. Show the plan: `.venv/bin/python -c "import pandas as pd; m=pd.read_csv('data/manifests/mta_manifest.csv'); print(m.groupby(['year','kind','holdout']).size())"`. Confirm that every 2022-2026 row has holdout=1.
4. `YEARS=2013-2021 scripts/run_stage.sh download` (several GB; hours). Monitor the same way: `tail -n 5 logs/download.log; wc -l data/manifests/mta_files.csv; du -sh data/raw`.
5. When done, protect the raw data: `chmod -R a-w data/raw`. Append counts to logs/PROGRESS.md.
