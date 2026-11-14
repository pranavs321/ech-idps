---
name: evaluate
description: Stage 5. Runs the split ladder (capture, JA4, source, time), ELI, low-FPR points, per-host triage, bootstrap CIs and source identifiability for every feature family including the host-relative (HR) family. Use after extract-label.
---

# Stage 5: evaluate

Follow the always-on pipeline guardrails rule.

1. Confirm `state/process.done` exists.
2. `scripts/run_stage.sh evaluate` (three runs: all labels, hostname-only, gold-only; about 30-60 min each on an M4; set `XGB_THREADS` to the number of performance cores). Monitor with /schedule every 10 minutes.
3. Print only the summaries: `for r in all hostname_only gold_only; do echo == $r; cat results/$r/summary.csv | head -n 40; done` and `cat results/hostname_only/extra.json | head -n 80`.
4. Red flags, each to logs/BLOCKERS.md: any test AUC of exactly 1.0; ENV beating HR+TLS+BEH on the source split; a source split with fewer than 30 malicious rows in a held-out source.
5. Write a walkthrough: one table per results folder (set x split: balanced accuracy, AUC, TPR at 1% FPR), the bootstrap intervals for HR+TLS+BEH minus TLS+BEH, the ELI values and source identifiability. Cite the file for every number.
