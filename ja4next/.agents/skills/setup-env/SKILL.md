---
name: setup-env
description: Stage 0. Checks tshark, creates .venv, installs requirements, validates the JA4 extractor against FoxIO reference pcaps. Use first, or when imports or tshark fail.
---

# Stage 0: environment

Follow the always-on pipeline guardrails rule.

1. Run `tshark --version | head -n 1`. If missing, STOP and tell me to run `brew install --cask wireshark` and then `sudo ln -s /Applications/Wireshark.app/Contents/MacOS/tshark /usr/local/bin/tshark` myself.
2. If `.venv/` does not exist: `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`.
3. Run `scripts/run_stage.sh env`. It must print every library version and exit 0.
4. Validate the extractor: `git clone --depth 1 https://github.com/FoxIO-LLC/ja4.git ../foxio-ja4` (once), then `.venv/bin/python -I tests/validate_foxio.py ../foxio-ja4`. Expected: `JA4 ours : 150/151` and `JA4S ours : 85/85` (the one miss is a non-ASCII ALPN that tshark cannot expose). If lower, write the mismatches to logs/BLOCKERS.md and stop.
5. Append the result to logs/PROGRESS.md.
