#!/usr/bin/env python3
"""
run_all.py -- the single button.

This runs the entire project end to end: generate the corpus, train every
tier, evaluate, and print a live end-to-end demo of one flow being caught,
explained and mitigated. If you run nothing else, run this.

    python3 run_all.py

It calls the four numbered scripts in order and then the demo. Each numbered
script also works on its own if you want to run a single stage -- see README.md.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable


STAGES = [
    ("Generate the ECH-era mimicry corpus",
     [PY, "scripts/01_generate_dataset.py"]),
    ("Train the detection stack (dissonance + 3 tiers)",
     [PY, "scripts/02_train.py"]),
    ("Evaluate: baselines, evasion-cost curve, ablation, collateral damage",
     [PY, "scripts/03_evaluate.py"]),
    ("Live end-to-end demo: catch, explain, mitigate one flow",
     [PY, "scripts/04_demo.py"]),
]


def banner(text: str, n: int, total: int) -> None:
    line = "=" * 74
    print(f"\n{line}\n  STAGE {n}/{total}: {text}\n{line}", flush=True)


def main() -> None:
    t0 = time.time()
    print("Adaptive, Explainable, ECH-Aware Split-Plane IDPS")
    print("Running the full pipeline. First run takes about a minute.\n")

    for i, (label, cmd) in enumerate(STAGES, 1):
        banner(label, i, len(STAGES))
        result = subprocess.run(cmd, cwd=ROOT)
        if result.returncode != 0:
            print(f"\nStage {i} failed (exit {result.returncode}).")
            print("Fix the error above and re-run. Earlier stages are cached, "
                  "so you won't lose work.")
            sys.exit(result.returncode)

    print(f"\n{'=' * 74}")
    print(f"  DONE in {time.time() - t0:.0f}s.")
    print(f"{'=' * 74}")
    print("\nWhat you now have:")
    print("  artifacts/   trained models, the dataset, a demo PCAP")
    print("  results/     evaluation.json and evaluation.png (your figures)")
    print("\nNext: open results/evaluation.png, and read README.md for how to")
    print("talk about each piece in your review.")


if __name__ == "__main__":
    main()
