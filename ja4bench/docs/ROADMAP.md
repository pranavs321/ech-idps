# ROADMAP — from where we are to a finished, defensible project

## 0. The thesis in one paragraph

Papers report 95–99% for JA4-based malware detection. In most public datasets malware is recorded in
one place (a sandbox, a lab VM) and benign traffic in another (a lab PC, a simulator), so a model can
score highly by recognising *where* traffic was recorded. This project measures how much of the score
is that shortcut, re-tests detectors where both classes come from the same environment, checks them
on newer IOC-verified malware, measures what ECH will remove, and proposes evaluation rules (and a
detector design) that survive these tests.

**Title:** *Detecting the Lab, Not the Malware: A Leakage-Controlled, Environment-Matched Evaluation
of JA4-Based Malware Detection*

## 1. Where we stand (only verified items; numbers in `docs/FINDINGS.md`)

- ja4lab extractor validated against FoxIO (JA4 150/151, JA4S 85/85, JA4H 69/71, JA4T 39/39).
- 35 of 39 MTA 2024 victims IOC-verified; IOC files archived with hashes.
- ja4bench harness: canonical schema, adapters, P1–P8, lookup + env-only baselines, capture
  bootstrap, deliberate-leak test, 10 unit tests passing.
- Public Matoušek corpus audited and evaluated end to end (`results_reference/`).

## 2. What is lagging, and the fix

| Gap | Why it matters | Fix | Task |
|---|---|---|---|
| Waiting for Vighnesh's files | Blocks the "break the 99.98%" result | Rebuild Dataset A from its public sources with ja4lab; use his files later as a cross-check | T10–T11 |
| ja4lab labels are host-level | Victim's own browsing lands in the malicious class | Flow-level labels from IOC C2 endpoints (`scripts/15_flow_labels_from_iocs.py`) | T06 |
| No per-capture environment metadata | The confound cannot be measured or controlled | `data/meta/capture_meta*.csv` for every source | T05 |
| No environment-matched benign data | Every benign/malicious split so far is also an environment split | Within-capture contrast; Tria.ge/ANY.RUN sandbox-matched benign; CTU-SME-11 | T08, T12–T14 |
| Only one capture year | Temporal decay untested | MTA 2025–26 + indicators repo | T16 |
| Pre-registration not committed | Results could be accused of p-hacking | Commit `docs/PREREG.md`, tag `prereg-v1` | T02 |
| Tranco list not pinned | Gray-flow filter not reproducible | Pin list ID, record date and hash | T03 |
| Env-only baseline uses CSV fields only | TTL/window/MSS are the real environment signal | Re-extract Matoušek pcaps with ja4lab, join TCP fields | T04 |
| Agent claims without output | Earlier retractions | `AGENTS.md`, report template, raw output only | always |

## 3. Contributions (what the report/paper claims)

- **C1. A provenance-tracked JA4 benchmark** where every capture carries environment metadata and
  every label carries its basis (`ioc_verified`, `source_asserted`, `sandbox_verdict`, `inferred`).
- **C2. Shortcut diagnostics for JA4 detectors:** Environment Leakage Index (env-only ROC-AUC under
  capture-disjoint splits), JA4 label-conflict floor, seen-JA4 rate, lookup-table baseline beside
  every result, and a deliberate-leak test that proves the harness catches leakage.
- **C3. A protocol suite (P1–P8)** applied to every corpus, with skip-and-log and capture-level CIs.
- **C4. Environment-matched evaluation** three ways: within-capture IOC contrast, sandbox-matched
  benign, same-network datasets.
- **C5. Temporal and cross-corpus re-evaluation** on IOC-verified MTA 2024 → 2025–26 malware.
- **C6. ECH ablation** quantifying how much detection relies on SNI.
- **C7 (optional). Counterfactual grid** on harmless real traffic (OS × TLS library × behaviour).

## 4. Experiment map

| ID | Question | Data | Protocol / combos | If the model is memorising… |
|---|---|---|---|---|
| E0 | Is the harness sound? | Matoušek | P2, P3 with `xgbLEAK` vs `xgb` | (leak must inflate scores) |
| E1 | Is XGBoost better than a lookup table? | every corpus | P1, P2: `lookup` vs `xgb:ja4_components` | lookup ≈ XGBoost |
| E2 | How much is environment? | every corpus | P2: `xgb:env_only` (ELI) | ELI high |
| E3 | Unseen fingerprints / families | every corpus | P3, P4 | near chance |
| E4 | Environment-matched | Matoušek mobile, MTA flow-level, Tria.ge/ANY.RUN, CTU-SME-11 | P8 (+ P2 inside mixed captures) | collapse toward the label-conflict floor |
| E5 | Cross-domain / cross-corpus | Matoušek desktop↔mobile; Dataset A → MTA | P6, P7 | collapse |
| E6 | Temporal | MTA 2024 → 2025–26; Triage 2023 → 2026 | P5 | decay |
| E7 | What does ECH remove? | every corpus with SNI | `ja4_plus_sni` vs `ja4_components` | big drop = SNI did the work |
| E8 | What drives the score? (optional) | Windows VM grid, harmless | frozen models | score follows client/OS, not behaviour |

## 5. Phases, gates and tiers

Each phase ends with a **gate**: the CHECK in `docs/TASKS.md` passes in raw output. Tier 1 alone is a
complete project; Tier 2 makes it strong; Tier 3 makes it stand out.

| Week | Phase | Tasks | Gate | Tier |
|---|---|---|---|---|
| 1 | Setup, reproduce reference, pre-register, pin Tranco | T00–T03 | your rerun matches `results_reference/` exactly | 1 |
| 1–2 | Matoušek pcaps → TCP environment fields; env-only with TTL/window | T04 | join rate ≥ 90% printed | 1 |
| 2 | MTA 2024 metadata + flow-level IOC labels + canonical + within-capture test | T05–T08 | ≥ 20 captures with both ioc_c2 and os_background flows | 1 |
| 3 | Dataset A rebuilt from public sources; reproduce ~99.98% under the team split; then P1–P8 | T10–T11 | team-split number reproduced within 0.01, or the difference explained | 1 |
| 4 | Cross-corpus: Dataset A / Matoušek → MTA (P7) | T09 | summary table with lookup + env-only rows | 1 |
| 4–5 | CTU-SME-11 subset + Stratosphere mixed | T14–T15 | labels joined to ja4lab flows, join rate printed | 2 |
| 5 | MTA 2025–26 temporal | T16 | P5 runs without skips | 2 |
| 5–6 | Tria.ge + ANY.RUN sandbox-matched sets | T12–T13 | ≥ 30 benign + ≥ 30 malicious tasks from the same sandbox profile | 2 |
| 6 | ECH ablation table, environment-relative detector (H5) | T17–T18 | H5 tested on mixed-capture data only | 2 |
| 6–7 | Optional grid | T19 | ≥ 18 sessions with metadata | 3 |
| 7–8 | Figures, freeze, reproduce-all, write | T20–T21 | `make reproduce` regenerates every number | 1 |

Shift weeks to your real deadline; never reorder Tier 1 behind Tier 2.

## 6. The proposed detector (stated as a hypothesis, tested honestly)

A JA4 string identifies a TLS *library*, not intent. The design therefore separates three signals and
is only ever claimed for what the tests show:

1. **Library identity** (JA4 components, mapped to library families via JA4DB as enrichment).
2. **Behaviour** (timing regularity, sizes, connection pattern) — from ja4lab flow features.
3. **Environment-relative context** — each flow compared with *its own host's* baseline in the same
   capture (e.g. is this JA4 rare for this host? does this flow's timing differ from the host's other
   flows?). Relative features cancel per-environment artefacts such as TTL or window size.

Pre-registered limits: environment-relative features are only meaningful where a capture contains both
benign and malicious activity (MTA flow-level, CTU-SME-11, Stratosphere mixed). On single-class captures
(sandbox runs, lab captures) they would encode capture composition — itself a shortcut — so they are
not used there. If H5 fails, report it; the evaluation contribution stands on its own.

## 7. Report / paper outline

1. Introduction — 99% claims; the shortcut; contributions C1–C7.
2. Background — JA4/JA4+, TLS libraries vs apps, ECH (RFC 9849), shortcut learning.
3. Related work — `docs/LITERATURE.md` sections A, B, D; position against the Multi-View Fusion paper.
4. Data — sources table with environment and label basis; label policy; exclusions.
5. Method — canonical schema, protocols P1–P8, baselines, diagnostics, bootstrap, pre-registration.
6. Results — audit (Table 1), E0–E7 (Figure 1: ROC-AUC per protocol with CIs; Figure 2: P2 vs P8;
   Table 2: lookup vs XGBoost vs env-only; Table 3: ECH ablation; Table 4: temporal).
7. Proposed detector and its limits.
8. Discussion — what JA4 is good for (identifying libraries, hunting known infrastructure) and what it
   is not (generic malware detection); recommendations checklist for future papers.
9. Threats to validity — label noise, sandbox artefacts, QUIC excluded, small benign desktop sets.
10. Ethics and safety — PCAPs only, no live malware, public data, terms of service.
Appendix — reproduction commands, hashes, full tables.

## 8. Risks and fallbacks

| Risk | Fallback |
|---|---|
| Dataset A rebuild cannot reproduce 99.98% | Report the discrepancy; audit with Vighnesh's files if they arrive |
| Few MTA captures have both C2 and OS-background flows | Widen background list (documented), add MTA 2025–26, lean on CTU-SME-11 |
| Tria.ge researcher account not granted | ANY.RUN manual downloads; Stratosphere mixed captures |
| CTU-SME-11 too large | Download only Windows-VM device folders; state it |
| Time runs out | Stop after Tier 1: Matoušek + MTA + Dataset A rebuild is already a complete measurement study |

## 9. Viva questions to prepare (write a 3-sentence answer for each)

1. Why is a random flow split wrong for this problem?
2. What is the Environment Leakage Index and why is it not "cheating"?
3. Why does a lookup table matter as a baseline?
4. What is the label-conflict floor and what does it prove?
5. Why are your labels better than the public datasets' labels?
6. Isn't the grid synthetic data? (No: real clients, real traffic, used only as a stress test.)
7. What happens to your conclusions under ECH?
8. What would you tell a SOC that wants to deploy a JA4 detector tomorrow?

## 10. Where to submit (check current deadlines yourself)

University report first. Then an arXiv preprint and a workshop or conference on network/ML security
(e.g. AISec at CCS, TMA, CNSM, DIMVA, IEEE ICC/Globecom workshops). Measurement papers with negative
results and released code are welcome at these venues; the closest related paper went to a regional
conference (ASIANComNet), which is a realistic first target.
