# Task cards for the coding agent

Give ONE card per message, after pasting `AGENTS.md`. Accept a card only when its CHECK passes in
raw output pasted back. If a CHECK fails, the agent stops and reports; it does not "fix" the check.

Paths: `JA4LAB=` your ja4lab/ja4prehash project root. All commands run from the ja4bench root.

---

## Tier 1 — complete project

### T00 Setup
```
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
git init && git add -A && git commit -m "T00: import ja4bench 0.3.0"
.venv/bin/python tests/run_tests.py
```
CHECK: last line `10 passed, 0 failed`.

### T01 Reproduce the reference results (public Matoušek corpus)
```
bash scripts/00_fetch_matousek.sh
.venv/bin/python scripts/10_build_canonical.py --adapter matousek --in data/external/matousek/datasets --out data/canonical/matousek2024.csv.gz
.venv/bin/python scripts/20_diagnose.py --in data/canonical/matousek2024.csv.gz --out results/audit_all
.venv/bin/python scripts/30_run_protocols.py --in data/canonical/matousek2024.csv.gz --tcp-only --exclude-flag flag_no_capture_id --combos lookup:ja4,xgb:ja4_components,rf:ja4_components,xgb:ja4_plus_sni,xgb:env_only --boot 1000 --out results/protocols_main
.venv/bin/python scripts/36_compare_runs.py results/protocols_main results_reference/protocols_main
```
CHECK: the four CSV hashes printed by the fetch script equal those in
`data/external/matousek/MANIFEST.sha256` of the reference (see `docs/FINDINGS.md`); canonical `content_sha256` equals
`ce17be19d5f23368…` (hash of the DECOMPRESSED csv; never compare .gz file hashes); compare script prints `PASS`. If upstream changed the CSVs, stop and report the new hashes.

### T02 Commit the pre-registration
Fill the blanks at the top of `docs/PREREG.md` (names, date, ja4lab commit). Then
`git add docs/PREREG.md && git commit -m "T02: pre-registration" && git tag prereg-v1`.
CHECK: `git tag` shows `prereg-v1`; `git show prereg-v1 --stat` lists PREREG.md.

### T03 Pin the Tranco list (in ja4lab)
Download the list by its permanent ID from tranco-list.eu, record ID + date + SHA-256 in ja4lab's
README, git-ignore `data/meta/tranco.csv`, delete `tranco.csv.zip` and `tranco.zip` from the root.
CHECK: README diff shows ID, date, hash; `git status --short` no longer lists the zips.

### T04 Matoušek pcaps → TCP environment fields
```
rm -rf data/external/matousek && bash scripts/00_fetch_matousek.sh --with-pcaps     # ~5 GB
# run the ja4lab extractor on every pcap under data/external/matousek/datasets/ (use ja4lab's own CLI;
# print its --help first, do not guess flags) -> data/interim/matousek_ja4lab.csv
```
Then join ja4lab rows to the canonical table on (capture file basename, src_port, dst_ip, dst_port),
adding `ttl, win, mss, wscale, ja4t` as NEW columns → `data/canonical/matousek2024_tcp.csv.gz`.
Rerun T01's protocol command on it with `--combos lookup:ja4,xgb:ja4_components,xgb:env_only`.
CHECK: printed join rate (joined / canonical rows) for each of the 4 files; env_only row in the new
SUMMARY.md. Join rate < 90% → stop and report examples of unjoined rows.

### T04b Spot-check the "background-only" sandbox captures (FINDINGS F3)
List the 437 Tria.ge captures whose labelled TCP flows are all `flag_os_background=1`
(group the canonical table by capture_id). Pick 20 at random (seed 42), open each task's PUBLIC report
page on tria.ge (report only; never download the sample) and record: family, any C2 listed in the
report, whether that C2 is a Google/Microsoft service. Save `results/spotcheck_bg_only.csv`.
CHECK: 20 rows; count of captures where the report lists a non-background C2 that ja4lab missed.

### T05 Per-capture environment metadata for MTA 2024
Create `data/meta/capture_meta_mta2024.csv` from `data/meta/capture_meta.TEMPLATE.csv`, one row per
capture in ja4lab's corpus (malicious + benign). Fill only what is known from the MTA post or capture
(OS from TTL/JA4T is NOT allowed as a source; write `unknown`).
CHECK: `wc -l` = captures + 1; `cut -d, -f3 | sort | uniq -c` printed.

### T06 Flow-level IOC labels
```
head -1 $JA4LAB/data/interim/connections.csv
head -1 $JA4LAB/data/meta/infected_hosts.csv
.venv/bin/python scripts/15_flow_labels_from_iocs.py --flows $JA4LAB/data/interim/connections.csv \
   --capture-col <real> --src-col <real> --dst-col <real> --sni-col <real> \
   --hosts $JA4LAB/data/meta/infected_hosts.csv --hosts-capture-col <real> \
   --victim-col ioc_victim_ip --c2-col ioc_c2_matched --out data/interim/mta2024_flows_labelled.csv
```
CHECK: the per-capture table and the line "captures with BOTH ioc_c2 and os_background flows". If it
is < 20, stop and report; do not widen the background list without a commit message saying why.

### T07 MTA 2024 canonical table
Copy `config/mappings/ja4lab_mta2024.TEMPLATE.yaml` → `ja4lab_mta2024.yaml`, replace every FILL_ME
with real column names from T06's header.
```
.venv/bin/python scripts/10_build_canonical.py --adapter generic --in data/interim/mta2024_flows_labelled.csv --mapping config/mappings/ja4lab_mta2024.yaml --out data/canonical/mta2024_flow.csv.gz
.venv/bin/python scripts/20_diagnose.py --in data/canonical/mta2024_flow.csv.gz --tcp-only --out results/audit_mta2024
```
CHECK: no SCHEMA PROBLEMS; AUDIT.md shows `captures_mixed_class` > 0.

### T08 E4 within-capture contrast (environment-matched by construction)
```
.venv/bin/python scripts/30_run_protocols.py --in data/canonical/mta2024_flow.csv.gz --tcp-only --protocols P2_capture,P3_ja4,P4_family --combos lookup:ja4,xgb:ja4_components,xgb:ja4_plus_sni,xgb:env_only --out results/e4_mta_within
```
CHECK: SUMMARY.md with all four combos; skipped folds listed.

### T09 E5 cross-corpus (frozen-style transfer)
```
.venv/bin/python scripts/30_run_protocols.py --in data/canonical/matousek2024.csv.gz data/canonical/mta2024_flow.csv.gz --tcp-only --exclude-flag flag_no_capture_id --protocols P7_source --combos lookup:ja4,xgb:ja4_components,xgb:env_only --out results/e5_cross_corpus
```
CHECK: two folds (`test=matousek2024`, `test=mta2024`) or a logged skip reason.

### T10 Rebuild Dataset A from public sources
Use the PCAP list in the 29 Sep record (section 9.6). Download CTU-13 scenarios and USTC-TFC2016 /
Stratosphere files by name into `data/raw/datasetA/`, write `MANIFEST.sha256`, extract with ja4lab,
map with a new `config/mappings/datasetA.yaml` (source per file; env_group per original dataset),
build `data/canonical/datasetA_rebuild.csv.gz`. Unresolvable names (e.g. ctu13-n-2) → list them, do
not guess.
CHECK: table of the 18 PCAPs: found / not found, sha256, rows extracted.

### T11 Break the 99.98%
Recreate the team split (train/val/test PCAP lists from the record) as a `split` column, train
`xgb:ja4_components` on train, report test metrics (expect ≈ 0.99). Then run P1–P8 on the same table.
CHECK: team-split numbers next to P2/P3/P4/P8 numbers in one table with lookup and env_only rows.

## Tier 2 — environment-matched and temporal evidence

### T12 Tria.ge sandbox-matched set
Researcher account → API key. Search existing public tasks only (never submit). Select ≥ 30 malicious
tasks across ≥ 10 families (2023–2026) and ≥ 30 low-score tasks of well-known benign software, all
on the SAME analysis profile/OS. Download pcaps + report JSON via the documented API. Record task id,
profile, score, family, date in `data/meta/capture_meta_triage.csv`.
CHECK: manifest with sha256 per pcap; count table profile × label.

### T13 ANY.RUN sandbox-matched set
Manual: public submissions, filter "No threats detected" for common installers/updaters, plus
malicious tasks on the same OS image; download pcaps. Record task URLs.
CHECK: same as T12.

### T14 CTU-SME-11 subset
Download only the Windows-VM and two benign desktop device folders from Zenodo 7958259. Extract with
ja4lab; join expert labels from the Zeek logs on (5-tuple, start time ± 1 s).
CHECK: join rate; label × device table.

### T15 Stratosphere mixed captures — same procedure as T14.

### T16 MTA 2025–2026 temporal set
Download ≥ 20 captures per year with an indicators file in `malware-traffic/indicators`; run the IOC
victim pipeline and T06. Run P5 on mta2024 + mta2025 + mta2026.
CHECK: P5 folds not skipped; year × label table.

### T17 ECH ablation table
From every SUMMARY.md: `xgb:ja4_plus_sni` minus `xgb:ja4_components` per protocol and corpus.
CHECK: one table, every cell traceable to a summary.csv row.

### T18 Environment-relative features (H5)
Implement feature set `ja4_envrel` in `ja4bench/features.py` (per-host rarity of the JA4 within the
capture, per-host z-scores of flow features), unit-test it, run P6/P7 on mixed-capture tables only.
CHECK: tests pass; H5 table vs `ja4_components`.

## Tier 3 — stand-out

### T19 Counterfactual grid (optional; harmless traffic to your own server only)
Windows 11 VM × {Chrome (QUIC off), Python requests, PowerShell} × {browse own site, fixed beacon,
jittered beacon} × 3 sessions. Metadata per session. Score with models frozen before the grid.
CHECK: ≥ 18 sessions; per-session flagged share table.

### T20 Figures
`.venv/bin/python scripts/40_make_figures.py --run results/protocols_main --out results/figures`
CHECK: PNGs exist; each figure's numbers equal summary.csv.

### T21 Freeze and reproduce-all
A single `scripts/99_reproduce_all.sh` that runs every command above from raw downloads; run it on a
clean clone.
CHECK: every summary.csv identical to the committed one.


---

## REDO CARDS (after the 2026-10-07 audit) — run strictly in this order, one per message

### R0 Environment
Run in YOUR OWN Terminal app, not the agent's sandbox: `python3.12 -m venv .venv`,
`.venv/bin/pip install -r requirements-lock.txt`. Never patch system Python, never edit pins.
CHECK: `.venv/bin/python scripts/check_env.py` prints `RESULT: PASS`. Nothing else counts.

### R1 Rerun T01 on R0, then T04 with a real join
`36_compare_runs.py` must print PASS. For T04 print the join rate PER source file and per label; if any
file is below 90%, stop and list 10 unjoined rows with their capture ids. Never leave NaN TCP fields
unreported: missingness that differs by class is itself a shortcut (report it).

### R2 Quarantine
`mkdir -p results/_quarantine && git mv` the outputs of T08, T09, T11, T12-T18 and the mta2024 /
mta_temporal / datasetA canonical tables there; delete capture_meta_{triage,anyrun,datasetA,temporal}.csv
from data/meta (they hold computed placeholder hashes and mislabelled rows). Commit "R2: quarantine".

### R3 Real IOC labels for the IOC-verified MTA 2024 captures
(a) `head -3` of the IOC manifest and `ls` of the IOC folder; paste. (b) Build data/meta/ioc_map.csv
(capture,ioc_file) from the manifest ONLY. (c) Build the infected-hosts table from the IOC-verified list
in ja4lab (not from flow labels). (d) Run scripts/15_flow_labels_from_iocs.py, then
scripts/16_audit_flow_labels.py. CHECK: audit prints PASS (100% of ioc_c2 flows matched to a line in
their own capture's IOC file, and unknown flows > 0). Report the number of captures having both
ioc_c2 and os_background flows, whatever it is. The background list in matousek.py stays untouched; any
MTA-specific additions go in config/os_background_mta.txt with one reason per line and no CDNs.

### R4 Rerun T07-T09 on the R3 table only
### R5 T10 properly
Only the 18 PCAPs in section 9.6 of the 29 Sep record, by name; per file: found/not found + real sha256.
Reproduce the team split first. Anything not found is listed as MISSING. CTU-SME-11 is a different
dataset and goes under T14.
### R6 T12-T15 only after you hold real downloads
Tria.ge / ANY.RUN tasks: record task id, URL, profile, score, family, sha256 of the downloaded pcap.
No task from the MTA collection may appear in them.
### R7 T18 only on tables with mixed captures (R3 output), with the env_only baseline next to it.
