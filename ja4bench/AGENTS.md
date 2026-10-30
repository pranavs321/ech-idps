# AGENTS.md — rules for any coding agent working in this repository

Paste this whole file as the first message of every new Antigravity session (or add it to the
workspace rules). Then give the agent ONE task card from `docs/TASKS.md` at a time.

## Why these rules exist

Earlier in this project, agent summaries reported numbers that no command had produced
(a "1,120 / 834 / 142" instance count, a "39 agreements" cross-check, a fabricated metadata file,
an "exact match" that compared ja4lab with itself). All were caught and retracted. The rules below
make that impossible to repeat.

## The rules

1. **Raw output or it did not happen.** Every number, count, file name or result you report must
   come from a command whose full output you paste. Never summarise without the output above it.
2. **Do not make a failing check pass by editing code or data.** If a CHECK fails, stop and paste
   the output. Do not "fix" thresholds, filters, seeds or expected values.
3. **Labels are append-only.** Never overwrite `label`, `victim_ip` or any label column. Add a new
   column with a new name and a `*_basis` column saying why.
4. **Never delete or rewrite** `data/meta/*.csv`, `data/external/**/MANIFEST.sha256`,
   `results_reference/**` or `docs/PREREG.md` after it is tagged `prereg-v1`. Deviations go in the
   "Deviations log" at the bottom of PREREG.md, with a date and a reason.
5. **No live malware, ever.** Download packet captures and published reports only. Never download,
   unzip-and-run, or open malware samples or executables. Never extract files carved from PCAPs
   (`--export-objects` etc.). Sandbox reports are fetched as PCAP/JSON only.
6. **One Python.** Use `.venv/bin/python` only. If an import fails, stop and report it.
7. **Commit after every task card**: `git commit -m "T<nn>: <what>"`. Never commit anything under
   `data/` except `data/meta/` and manifests (see `.gitignore`).
8. **Do not invent paths, columns or counts.** If you do not know a column name, print the columns
   (`head -1 file.csv`) and use what is there.
9. **Determinism.** Seeds are fixed at 42. If two runs of the same command differ, report it.
10. **Every model result needs its baselines next to it**: the JA4 lookup table (`lookup:ja4`) and
    the environment-only diagnostic (`xgb:env_only`). A result without them is not reported.

11. **Never edit shared code, lists or tolerances to make a check pass** (adapters, OS_BACKGROUND_SUFFIXES,
    compare tolerances, schema). A needed change goes in its own commit with a stated reason, and the
    check is then rerun from scratch.
12. **Never generate a labels/IOC file from the data you are labelling.** IOC C2 lists come only from the
    published IOC files (data/meta/iocs/...) mapped to each capture. Labels derived from other labels,
    or from "everything that is not background", are not IOC labels.
13. **"Unknown" is never "benign" and never "malicious".** Honest flow labelling always leaves unknown
    flows; zero unknown flows means something is wrong.
14. **Every pcap, hash and count must point to a file on disk.** If a file is missing, write `MISSING`,
    never a computed placeholder, never a hash of a name. A task is "done" only when its CHECK passed
    in pasted output; never write "100% complete". Do not run more than one task card per message.
15. **No `git add -f` on data or results.** If git ignores it, ask first.
16. **Environment = `requirements-lock.txt`, verified by `scripts/check_env.py`.** If it cannot be installed,
    stop and report the pip error. NEVER edit pins to match what installed, NEVER modify or delete anything
    outside this repository (system Python, Homebrew, pip), NEVER run `rsync --delete` or `rm -rf` on a
    directory containing work without first showing `git status` and getting a yes.

## Report template (use for every card)

```
TASK: T<nn> <title>
COMMANDS RUN: <exact commands>
RAW OUTPUT: <pasted, untrimmed for anything that contains a number you cite>
CHECK: PASS | FAIL  — <which line of the output shows it>
FILES CHANGED: <git status --short>
COMMIT: <hash>
OPEN QUESTIONS: <anything you were unsure about; never guess>
```

## Repository map

```
ja4bench/            library: schema, adapters, ja4parse, features, protocols, models, metrics, diagnostics
scripts/00_*.sh      data fetching (CSV / PCAP / reports only)
scripts/10_*.py      any source -> canonical table (validated, hashed)
scripts/20_*.py      dataset audit (before any model)
scripts/30_*.py      protocols P1–P8 x model/feature-set combos, capture-bootstrap CIs
scripts/40_*.py      figures for the report
config/sources.yaml  every dataset: role, environment, access, status
config/mappings/     YAML mappings for the generic adapter (ja4lab, Dataset A, ...)
docs/                ROADMAP, DATASETS, LITERATURE, PREREG, TASKS, FINDINGS
results_reference/   outputs produced on the public Matousek corpus; your rerun must match them
tests/               run with: .venv/bin/python tests/run_tests.py
```
