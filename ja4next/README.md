# ja4next

Code, data manifests and results for the next stage of **"Detecting the Lab, Not the Malware"**: a same-host
benchmark built from every public malware-traffic-analysis.net infection capture from 2013-2021, labels from
independent evidence, and the new **stack-conditioned host-relative** feature family.

Start here:
1. `docs/ANTIGRAVITY_SETUP.md` - set up the Mac and run everything with Antigravity skills (or by hand below).
2. `docs/RESULTS_EXPLORATORY.md` - what today's run found (exploratory; numbers come from `results/`).
3. `docs/NOVELTY.md` - what we can claim and the prior work to cite.
4. `docs/DATASETS.md` - ranked sources to add next, with licence notes.
5. `docs/PREREG_ADDENDUM.md` - hypotheses for the confirmatory run on the 2022-2026 holdout (needs the guide's sign-off).
6. `docs/THREAT_MODEL.md` - the threat model section the paper was missing.

## By hand
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
scripts/run_stage.sh env
scripts/run_stage.sh labels
scripts/run_stage.sh crawl          # ~1 h, 1 request/s; 2022-2026 listed as holdout only
YEARS=2013-2021 scripts/run_stage.sh download
WORKERS=6 scripts/run_stage.sh process
scripts/run_stage.sh evaluate
.venv/bin/python -m pytest -q tests
```

## What is validated
* JA4 matches FoxIO's reference output on 150 of 151 TCP TLS connections in FoxIO's own test pcaps (tshark's
  built-in JA4 gets 145); JA4S 85 of 85. The one miss is a non-ASCII ALPN that tshark does not expose as bytes.
  Re-run: `python -I tests/validate_foxio.py <path to FoxIO-LLC/ja4 clone>`.
* Unit tests (`tests/test_core.py`): GREASE, JA4/JA4S/JA4T, signature-algorithm list selection, IOC parsing,
  allowlist, crawler never listing sample zips, host-relative invariance to a host-constant shift.

## Safety
* Never downloads zips with "malware" in the name; unpacks only .pcap/.pcapng/.txt; executes nothing from data/.
* 2022-2026 is the pre-registered holdout: listed in the manifest, refused by the downloader without
  `--allow-holdout`, blocked by the Antigravity guard hook, and the `confirm` stage refuses to run until
  `docs/PREREG_FROZEN.sha256` exists.
* Raw pcaps and Maltrail-derived labels are not redistributed; manifests list URL + SHA-256 only.
