---
name: add-source
description: Adds a new public pcap dataset (e.g. Stratosphere CTU-Mixed, TQH-C2, Unit 42 Wireshark quizzes, Malware of the Day) as a new source with its own manifest, labels and source name. Use when asked to add a dataset.
---

# Add a data source

Follow the always-on pipeline guardrails rule.

1. Read docs/DATASETS.md for the source's URL, licence and label notes. If the licence forbids ML training or the source needs a login, STOP and ask me.
2. Write `src/ja4next/sources/<name>.py` with a `manifest()` that lists pcap URLs and a per-capture IOC or label file, mirroring crawl_mta.py. Only pcap files; never samples.
3. Give the source its own name in `process.source_of` (e.g. `ctu_mixed`) so leave-one-source-out treats it separately.
4. Same-host check: report, per capture, how many internal client IPs carry both a malicious and a benign-labelled connection. Sources where no host has both classes go into a separate "cross-host" bucket and are not used for same-host claims.
5. Add a unit test in tests/ for the manifest parser, run pytest, then rerun /extract-label and /evaluate.
