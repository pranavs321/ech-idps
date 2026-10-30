# ja4bench — is your JA4 malware detector detecting malware, or the lab?

Code and plan for the final-year project *Detecting the Lab, Not the Malware: A Leakage-Controlled,
Environment-Matched Evaluation of JA4-Based Malware Detection*.

Published JA4 malware detectors report ~95–99%. In most public datasets malware and benign traffic
are recorded in different places, so a model can score highly by recognising the recording setup.
ja4bench converts every dataset into one table where **the capture environment is recorded per
capture**, then evaluates detectors under protocols that remove the shortcuts one at a time.

## Read in this order

1. `docs/FINDINGS.md` — what is already verified, with exact numbers and the command behind each.
2. `docs/ROADMAP.md` — thesis, gaps, contributions, experiment map, phases, report outline, viva prep.
3. `docs/DATASETS.md` + `config/sources.yaml` — every data source, its role and how to get it.
4. `docs/LITERATURE.md` — related work, what each paper leaves open, reading log.
5. `docs/PREREG.md` — hypotheses and rules; commit and tag before confirmatory runs.
6. `AGENTS.md` + `docs/TASKS.md` — how to drive the coding agent, one card at a time.

## Quick start (reproduces `results_reference/` from public data, ~10 minutes)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python tests/run_tests.py                       # 10 passed, 0 failed
bash scripts/00_fetch_matousek.sh                         # CSVs only (~25 MB)
.venv/bin/python scripts/10_build_canonical.py --adapter matousek \
    --in data/external/matousek/datasets --out data/canonical/matousek2024.csv.gz
.venv/bin/python scripts/20_diagnose.py --in data/canonical/matousek2024.csv.gz --out results/audit_all
.venv/bin/python scripts/30_run_protocols.py --in data/canonical/matousek2024.csv.gz --tcp-only \
    --exclude-flag flag_no_capture_id \
    --combos lookup:ja4,xgb:ja4_components,rf:ja4_components,xgb:ja4_plus_sni,xgb:env_only \
    --boot 1000 --out results/protocols_main
.venv/bin/python scripts/36_compare_runs.py results/protocols_main results_reference/protocols_main
.venv/bin/python scripts/40_make_figures.py --run results/protocols_main --out results/figures
```

## Pipeline

```
sources ──adapters──▶ canonical table ──20_diagnose──▶ AUDIT.md (confound, conflict floor, coverage)
 (Matoušek, ja4lab/MTA,   (schema.py validates;          │
  Dataset A, CTU-SME-11,   env + label_basis per row)     └──30_run_protocols──▶ P1–P8 × combos
  Tria.ge, ANY.RUN, …)                                         lookup / XGBoost / RF / env-only / +SNI
                                                               capture-bootstrap CIs, host-level alerts
```

| Protocol | Holds out | | Combo | Purpose |
|---|---|---|---|---|
| P1 | random flows (reference only) | | `lookup:ja4` | memorisation baseline |
| P2 | captures | | `xgb:ja4_components` | the literature's "JA4 model" |
| P3 | JA4 fingerprints | | `rf:ja4_components` | second learner |
| P4 | malware families / apps | | `xgb:ja4_plus_sni` | ECH ablation (what SNI adds) |
| P5 | later years | | `xgb:env_only` | diagnostic: environment without TLS |
| P6 | a platform/domain | | `xgbLEAK:…` | deliberate-leak test (harness check) |
| P7 | a whole source | | | |
| P8 | only environments with both classes | | | |

## Layout

`ja4bench/` library · `scripts/` numbered steps · `config/` sources and mappings · `docs/` plan ·
`results_reference/` reference outputs · `tests/` unit tests · `data/` (git-ignored except `data/meta/`).

## Safety

PCAPs and published reports only. No malware samples are downloaded or executed, nothing is extracted
from captures, nothing is submitted to public sandboxes. See `AGENTS.md` rule 5.

## Data credits

Public corpus: P. Matoušek, O. Ryšavý, I. Burgetová, "Experience Report: Using JA4+ Fingerprints for
Malware Detection in Encrypted Traffic", CNSM 2024 — https://github.com/matousp/malware-analysis.
JA4+ by FoxIO (https://github.com/FoxIO-LLC/ja4; check FoxIO's license terms for JA4+ components other
than JA4 before redistribution).
