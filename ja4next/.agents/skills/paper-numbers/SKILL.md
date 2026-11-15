---
name: paper-numbers
description: Turns results/ files into paper-ready tables and sentences (markdown and LaTeX) for the new sections on host-relative detection, citing the source file of every number. Use after evaluate.
---

# Paper numbers

1. Read results/*/summary.csv, results/*/extra.json and results/*/split_ladder.csv only.
2. Write reports/new_sections.md with: (a) a table of feature set x split (balanced accuracy, AUC, TPR at 1% FPR); (b) the HR minus TLS+BEH bootstrap intervals; (c) ELI and source identifiability per family; (d) per-host triage hit@1 and precision@5. Each table caption names its file.
3. Also write reports/new_sections.tex with the same tables in booktabs format.
4. Never round differently from the CSV (3 decimals) and never state a gain whose interval crosses zero as an improvement.
