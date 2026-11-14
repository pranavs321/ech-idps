---
name: confirmatory-run
description: The pre-registered confirmatory test on the 2022-2026 holdout. Only for use after the human has frozen docs/PREREG_ADDENDUM.md and created docs/PREREG_FROZEN.sha256. Never run on the agent's own initiative.
---

# Confirmatory run (human-gated)

1. If `docs/PREREG_FROZEN.sha256` does not exist, STOP: say that the guide must approve docs/PREREG_ADDENDUM.md and a human must run `shasum -a 256 docs/PREREG_ADDENDUM.md src/ja4next/*.py > docs/PREREG_FROZEN.sha256`.
2. Verify nothing changed since freezing: `shasum -a 256 -c docs/PREREG_FROZEN.sha256`. Any mismatch: STOP and report.
3. Ask me for explicit approval in this conversation before step 4.
4. `scripts/run_stage.sh confirm`. Do not modify code, features, seeds or thresholds afterwards. Report every pre-registered hypothesis as supported or not supported, including failures.
