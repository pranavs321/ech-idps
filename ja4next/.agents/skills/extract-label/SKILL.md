---
name: extract-label
description: Stage 4. Extracts every downloaded pcap to TLS connections with tshark, attaches analyst IOCs and abuse.ch/Maltrail labels, writes data/processed/connections.parquet. Use after fetch-data.
---

# Stage 4: extract and label

Follow the always-on pipeline guardrails rule.

1. Confirm `state/download.done` exists; otherwise stop and tell me to run /fetch-data.
2. `WORKERS=6 scripts/run_stage.sh process`. Monitor every 10 minutes with /schedule: `tail -n 5 logs/process.log; cat logs/process.exitcode`.
3. Summarise in one command: `.venv/bin/python -c "import pandas as pd; d=pd.read_parquet('data/processed/connections.parquet'); print(len(d), d.capture_id.nunique()); print(d.groupby(['source','label_tier']).size().unstack(fill_value=0)); print('ja4==tshark', round((d.ja4==d.ja4_tshark).mean(),4))"`.
4. Sanity checks, each written to logs/BLOCKERS.md if it fails: gold_mal > 300 rows; benign > 1000 rows; ja4==tshark agreement > 0.95; no source with 0 malicious rows.
5. Append the table to logs/PROGRESS.md.
