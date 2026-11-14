# Adaptive, Explainable, ECH-Aware Split-Plane IDPS

Detecting fingerprint-spoofing malware in fully encrypted (TLS 1.3 + ECH)
traffic by testing whether a connection's **declared cryptographic identity**
is consistent with its **involuntary physical behaviour** — without decrypting
anything.

This repository is the working implementation of the S7 project described in
`docs/` (your `id-PROJECT.pdf` and the novelty dossier). All five modules run,
the three novelty pillars are implemented and measured, and the whole thing
executes on a laptop with no special privileges.

> **Status, 14 Nov 2026 (read this first).** Every number further down this page comes
> from the simulated corpus. The first measurements on real captures are in
> [`docs/REAL_TRAFFIC_RESULTS.md`](docs/REAL_TRAFFIC_RESULTS.md). In short, on 894 public
> same-host infection captures (2013-2021, exploratory):
> - the sensor had six bugs that only real pcaps expose; fixed, and it now reproduces
>   148 of 148 FoxIO reference JA4 values and agrees 100% with an independent extractor;
> - Tier 2 on the 14-D vector reaches AUC 0.990 within a source and 0.877 on an unseen one;
> - D(x) with the hand-written browser profiles does not work on real traffic
>   (AUC 0.262 on an unseen source); malware there uses the operating system's TLS
>   library, it does not impersonate a browser;
> - the new **host context** input (`src/idps/module2_sensor/host_context.py`), which
>   describes each connection against its own host and needs no SNI, lifts detection at
>   1% false alarms on an unseen source from 0.550 to 0.813 (causal form: 0.669).
>
> The pipeline that downloads, labels and evaluates the real captures is in
> [`ja4next/`](ja4next/README.md), with Antigravity skills and a pre-registration
> addendum for the held-back 2022-2026 captures.

---

## TL;DR — run everything with one command

```bash
cd ech-idps
pip install -r requirements.txt      # first time only
python3 run_all.py
```

That generates the dataset, trains every model, runs the full evaluation, and
prints a live demo of one attack being caught, explained and mitigated. First
run is about a minute. When it finishes:

- `results/evaluation.png` — your four result figures
- `results/evaluation.json` — the numbers behind them
- `artifacts/` — trained models and the dataset

If you only have time to look at one thing before your review, run
`python3 scripts/04_demo.py` and read the receipt it prints.

---

## What problem this solves, in one paragraph

TLS 1.3 already hides payloads. **Encrypted ClientHello (ECH)** hides the last
useful thing: the destination (SNI). Every deployed defence that keys on the
destination domain goes blind. The one signal still visible — the outer
ClientHello's JA4 fingerprint — is exactly the thing an attacker forges *for
free* with tools like uTLS, so their malware's handshake looks byte-for-byte
like Chrome. This project replaces **identity** with **consistency**: it asks
whether the connection's packet timing and sizes are physically plausible for
the client it *claims* to be. A beacon can fake Chrome's fingerprint for free,
but faking Chrome's *physics* — irregular human timing, bursty page loads —
forces it to add delay and padding that wreck its own command-and-control
channel. That trap is made precise by an **evasion-cost bound**, and every
block the system issues comes with a **mathematical receipt** and a
**collateral-aware mitigation** decision.

---

## The three novelty claims, and where each one lives in the code

| Pillar | Claim | Code | Result |
|--------|-------|------|--------|
| **1. Cryptographic–Physical Dissonance** | A single calibrated statistic `D(x)` scoring how improbable the physics is under the *declared* identity class | `src/idps/module3_ml/dissonance.py` | Result C (ablation) |
| **2. Evasion-Cost bound** | Any adversary who suppresses `D(x)` below threshold pays a provable minimum in latency + padding | `evasion_cost_lower_bound()` + `docs/EVASION_COST_THEOREM.md` | Result B (the cost curve) |
| **3. Attribution-driven enforcement** | The TreeSHAP vector *selects* the mitigation scope/mechanism/TTL, instead of just being a report | `src/idps/module4_xai/treeshap.py` → `src/idps/module5_soar/policy.py` | Result D (collateral damage) |

The supporting deliverable (Gap 4 in the dossier) — the first ECH-era mimicry
dataset — is `datasets/generator.py`.

---

## The five modules (matches your project document exactly)

```
 packet
   │
   ▼
┌─────────────────────┐   Module 1  eBPF/XDP data plane
│ kernel filter (XDP) │   src/idps/module1_dataplane/
│ drop known-bad in   │   real C program: xdp_filter.c
│ nanoseconds         │   portable Python twin: dataplane.py
└─────────┬───────────┘
          │ pass
          ▼
┌─────────────────────┐   Module 2  Flow sensor + feature extraction
│ assemble flows,     │   src/idps/module2_sensor/
│ compute JA4 + 14-D  │   real JA4 off wire bytes (ja4.py)
│ vector, strip IPs   │   14-D schema: src/idps/features.py
└─────────┬───────────┘
          │ 14-D vector + declared class
          ▼
┌─────────────────────┐   Module 3  3-tier ML engine
│ Tier 1 JA4 blocklist│   src/idps/module3_ml/
│ Tier 2 XGBoost+D(x) │   dissonance.py, tier1/2/3_*.py
│ Tier 3 IsolationFor.│   engine.py orchestrates the cascade
└─────────┬───────────┘
          │ malicious verdict
          ▼
┌─────────────────────┐   Module 4  Explainability (TreeSHAP)
│ exact attributions, │   src/idps/module4_xai/treeshap.py
│ family-mass split   │   endpoint-intrinsic vs infra-coincidental
└─────────┬───────────┘
          │ φ vector
          ▼
┌─────────────────────┐   Module 5  SOAR (attribution-driven)
│ scope/mechanism/TTL │   src/idps/module5_soar/
│ from φ + IP context │   policy.py, ip_context.py, soar.py
└─────────┬───────────┘
          │ verdict fed back
          ▼   into Module 1's kernel map
```

The loop closing back into Module 1 is the point of the split-plane design:
analysis can take milliseconds because enforcement, once decided, is free.

---

## Running each stage on its own

```bash
python3 scripts/01_generate_dataset.py   # build the ECH-era corpus + a demo PCAP
python3 scripts/02_train.py              # fit dissonance model + all 3 tiers
python3 scripts/03_evaluate.py           # baselines, cost curve, ablation, collateral
python3 scripts/04_demo.py               # live end-to-end walkthrough
```

Useful flags:

```bash
python3 scripts/01_generate_dataset.py --benign 24000 --mimicry 10800   # bigger corpus
python3 scripts/02_train.py --no-dissonance-feature                     # 14-D ablation
python3 scripts/03_evaluate.py --no-plots                               # skip matplotlib
python3 scripts/04_demo.py --show 5                                     # walk 5 flows
```

---

## Deploying the real kernel filter (optional, needs Linux + root)

Everything above uses a pure-Python data-plane twin so it runs anywhere. To run
the *actual* XDP program on a real interface:

```bash
sudo apt install clang llvm libbpf-dev linux-tools-$(uname -r)
make -C src/idps/module1_dataplane
sudo python3 -m idps.module1_dataplane.loader --iface eth0
```

See `docs/ARCHITECTURE.md` for attach modes (native vs generic XDP) and why the
mode matters for any latency number you quote.

---

## Current measured results

From `python3 run_all.py` on the bundled corpus (~19k flows):

- **Tier 2 detector:** AUC ≈ 0.985, **recall ≈ 0.91 at a held false-positive
  rate of 0.5%**
- **Dissonance `D(x)` alone:** AUC ≈ 0.75 — a weak standalone signal that
  becomes strong *in coupling*, which is the whole thesis
- **Collateral damage:** attribution-driven mitigation reduced innocent-flow
  disruption on shared infrastructure to **zero**, versus hundreds under a
  naive "ban every flagged source" policy, by vetoing ~90% of would-be
  escalations
- **Evasion-cost curve:** the attacker can drive recall down, but only by
  paying an order-of-magnitude increase in cover-traffic bandwidth — the cost
  is *measured off the generated traffic*, not assumed

Your exact numbers will vary slightly run to run (the corpus is randomly
generated); the shapes are stable.

---

## Honesty notes you should carry into the review

These are real limitations. Stating them yourself is worth marks; being caught
not knowing them is not.

1. **The dataset is simulated, not captured.** The flows are drawn from
   parametric behavioural models, not a real ECH testbed. That is adequate to
   exercise the pipeline, demonstrate the cost curve's *shape*, and fix the
   calibration procedure — it is **not** adequate for a headline accuracy claim
   in a paper. The path to real captures is in `docs/DATASET.md`.
2. **A patient attacker can still pay the cost.** The evasion-cost bound prices
   evasion; it does not make it impossible. A low-and-slow implant with an
   enormous latency budget can shape its way under threshold. The claim is
   *cost*, not *impossibility* — say it that way.
3. **A sign fix vs the dossier.** The dossier writes `D(x) = log[P(x|c)/P(x|c*)]`
   but also says "large D(x) means lying." Because `c*` is the best-fit class,
   that ratio is ≤ 0 and gets *more negative* with dissonance. The code
   implements the negation so that `D(x) ≥ 0` and larger means more dissonant.
   Fix the sign in the paper.
4. **Behavioural models need periodic recalibration** as browsers evolve; a
   stale class model raises false positives. See `docs/ARCHITECTURE.md`.

---

## Repository layout

```
ech-idps/
├── run_all.py                     one-command full pipeline
├── requirements.txt
├── README.md                      you are here
├── src/idps/
│   ├── features.py                the 14-D schema (single source of truth)
│   ├── ja4.py                     JA4 fingerprinting + browser profiles
│   ├── pipeline.py                wires all five modules together
│   ├── module1_dataplane/         XDP program + portable twin
│   ├── module2_sensor/            flow assembly + feature extraction
│   ├── module3_ml/                dissonance + 3-tier engine
│   ├── module4_xai/               TreeSHAP receipts
│   └── module5_soar/              attribution-driven mitigation
├── datasets/generator.py          the ECH-era mimicry corpus
├── scripts/                       01→04, run in order
├── docs/                          architecture, theorem, dataset plan
├── artifacts/                     (generated) models + dataset
└── results/                       (generated) figures + evaluation.json
```

---

## What to read next

- `docs/ARCHITECTURE.md` — how the split plane works and why, deployment notes
- `docs/EVASION_COST_THEOREM.md` — Pillar 2 stated properly, with the proof sketch
- `docs/DATASET.md` — what the generator models, and how to replace it with real captures
- `docs/REVIEW_CHEATSHEET.md` — one page: likely examiner questions and honest answers
