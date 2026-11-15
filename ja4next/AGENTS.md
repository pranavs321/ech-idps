# ja4next — project brief for coding agents (Antigravity, Claude Code, Codex)

## What this project is
Research code for the paper "Detecting the Lab, Not the Malware". It measures whether JA4/TLS-fingerprint
malware detectors detect malware or the capture environment, and tests a new detector that describes each
TLS connection **relative to the same host's own traffic** (host-relative features, family `HR`).

Pipeline: public infection pcaps (malware-traffic-analysis.net, one infected Windows host + its normal
traffic per capture) -> tshark -> one row per TLS connection (JA4, JA4S, JA4T/TS, certificate, behaviour)
-> labels from independent evidence (analyst IOC files, abuse.ch SSLBL/Feodo, Maltrail, vendor allowlist)
-> feature families ENV / TLS / BEH / SRV / HR -> XGBoost -> split ladder (capture, JA4, source, time).

## Layout
- `src/ja4next/extract.py`  pcap -> connections (JA4 validated 150/151 vs FoxIO reference; run tests/validate_foxio.py)
- `src/ja4next/crawl_mta.py`, `download.py`  manifest + downloads (pcap and IOC zips only, never "malware" zips)
- `src/ja4next/labels.py`  label tiers: gold_mal, weak_mal, benign, conflict, unknown
- `src/ja4next/features.py`  feature families; `host_relative()` is the new method
- `src/ja4next/evaluate.py`  split ladder, ELI, low-FPR points, per-host triage, bootstrap CIs, source identifiability
- `scripts/run_stage.sh <stage>`  the ONLY way to run a stage (env, labels, crawl, download, process, evaluate)
- `results/`  every number in the paper comes from a file here; `logs/` stage logs; `state/` done markers

## Non-negotiable rules
1. **Holdout:** malware-traffic-analysis.net posts from 2022-2026 are the pre-registered confirmatory set.
   Never download, open, extract or evaluate them. The `confirm` stage refuses to run until
   `docs/PREREG_FROZEN.sha256` exists, and only a human creates that file.
2. Never download or open zips whose name contains "malware" (they hold live samples). Never execute anything
   from `data/raw/`. Run Python that reads downloaded files with `python -I`.
3. Labels must never use handshake fields. Never add SNI strings, server IPs or allowlist membership as model
   features (the labels are derived from them).
4. Every reported number must come from a file in `results/` produced by a stage. Never type metrics by hand.
5. Report results as exploratory. Quote each number with its split and interval.
