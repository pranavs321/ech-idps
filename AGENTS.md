# AGENTS.md — Standing Instructions

Every agent spawned in this workspace reads this file before starting work.
This is an S7 academic research project with a submission deadline. Optimise for
**correctness and defensibility in review**, not for feature count.

---

## What this project is

An Intrusion Detection and Prevention System that catches malware hiding inside
fully encrypted (TLS 1.3 + ECH) traffic, without decrypting anything. It works by
testing whether a connection's **declared cryptographic identity** (its JA4
fingerprint, which attackers forge for free with uTLS) is consistent with its
**involuntary physical behaviour** (packet timing and sizes, which they cannot
forge cheaply).

Read `README.md` first, then `docs/RESEARCH_AND_NOVELTY.md`. The second file
tells you which claims are defensible and which have been narrowed after a
literature check — **do not restore broadened claims.**

---

## Environment

- Python 3.12+
- Install with `pip install -r requirements.txt`
- Full pipeline: `python3 run_all.py` (about 60 seconds)
- Never commit anything in `artifacts/` or `results/` — both are generated

---

## Code style

- PEP 8, 4-space indent, 88-column soft limit
- Type hints on all public function signatures
- Docstrings on every module and public function
- **Comments explain *why*, never *what*.** This codebase's comments carry the
  research reasoning — they are read by examiners. Preserve that voice.
- No emoji in code or output
- Prefer `numpy` vectorised operations over Python loops in hot paths

---

## Hard architectural rules — do not violate these

1. **The feature vector is exactly 14-dimensional.** `src/idps/features.py` is
   the single source of truth. Never hard-code a feature index anywhere else;
   import `INDEX_BY_NAME`. If you add a feature you break the sensor's output
   contract and the privacy argument built on it.

2. **The 5-tuple never crosses into the ML plane.** Module 2 strips IPs and
   ports before emitting a `FlowRecord`'s features. Module 5 re-attaches an
   address from its own store. This boundary is a stated privacy property of the
   project — do not route addresses through the analytical path for convenience.

3. **The dissonance model fits on benign traffic ONLY.** Contaminating it with
   malware teaches the model to excuse the attack it is supposed to catch.

4. **Thresholds are calibrated on validation data, never on training data.**
   Calibrating on train gives an optimistically low FPR and is the single most
   common reason IDS papers fail to reproduce.

5. **Infrastructure-coincidental evidence can never escalate to a source-wide
   ban**, regardless of model confidence. This is Pillar 3's whole guarantee
   ("bounded by construction"). See `src/idps/module5_soar/policy.py`.

6. **Attacker cost must be measured, never assumed.** In
   `datasets/generator.py`, latency and padding overhead are *consequences* of
   the shaping schedule. If you make them free parameters, the evasion-cost
   curve becomes circular and the central result is worthless.

7. **Do not use scapy's layer dispatch for packet parsing.** Importing
   xgboost/shap after scapy clobbers its link-layer registration and
   `getlayer(IP)` silently returns `None`. `src/idps/module2_sensor/sources.py`
   parses bytes directly. Keep it that way.

---

## Testing

Before claiming any task complete:

```bash
python3 run_all.py          # must finish with exit 0
```

Then sanity-check that results have not silently degraded:
- Tier 2 test AUC should stay above ~0.97
- Recall at 0.5% FPR should stay above ~0.85
- Collateral-damage reduction should stay at or near 100%

If a change moves these, say so explicitly. **Never quietly retune a threshold
to make a number look better.**

---

## Research integrity — this matters more than the code

- If a result is weaker than hoped, **report it honestly**. The docs already
  concede that `D(x)` alone is a weak standalone signal (AUC ~0.75) and that
  the dataset is simulated. These concessions are deliberate and earn marks.
- Never invent citations, metrics, or dataset properties.
- The dataset is **simulated, not captured**. Any text describing it must say so.
- If you find prior art that weakens a novelty claim, add it to
  `docs/RESEARCH_AND_NOVELTY.md` and narrow the claim. Do not hide it.

---

## Useful task prompts for this repo

Good tasks to hand an agent here:

- "Add unit tests under `tests/` for the JA4 parser and the 14-D extractor."
- "Build the FastAPI dashboard in `src/idps/dashboard/` serving SOAR incidents."
- "Add IPv6 support to `_parse_frame` in `module2_sensor/sources.py`."
- "Write a LaTeX paper skeleton in `paper/` using the structure in the dossier
  and the narrowed claims from `docs/RESEARCH_AND_NOVELTY.md`."
- "Add a `--real-pcap` mode so `01_generate_dataset.py` can ingest captured
  traffic instead of generated flows."

Tasks to **refuse or flag**:
- Anything that widens a novelty claim without new evidence
- Anything that expands the feature vector beyond 14 dimensions
- Anything that makes attacker cost a tunable parameter
