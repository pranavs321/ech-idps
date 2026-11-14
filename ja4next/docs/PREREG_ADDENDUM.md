# Pre-registration addendum: host-relative detection (draft for the guide to approve)

Status: DRAFT. Freezing = the guide approves this file, then a team member runs
`shasum -a 256 docs/PREREG_ADDENDUM.md src/ja4next/*.py > docs/PREREG_FROZEN.sha256` and commits it.
After that, no code, feature, label rule, seed or threshold may change before the confirmatory run.
Deviations go into `docs/DEVIATIONS.md` with date and reason (a practice adopted from a concurrent student project, credited in the paper).

## Data
- **Exploratory (training) data:** malware-traffic-analysis.net (MTA) posts 2013-2021, plus any other source
  already processed before freezing. Hashes in `data/manifests/mta_files.csv`.
- **Confirmatory (test) data:** every MTA post dated 2022-01-01 to 2026-12-31 that has a `*.pcap.zip`, as
  listed in `data/manifests/mta_manifest.csv` rows with `holdout=1` (frozen list; file hashes recorded at
  download). Nothing from these posts has been downloaded, opened or evaluated before freezing.
- **Unit of analysis:** TLS-over-TCP connection from a private client address to a public server address with
  a ClientHello. Hosts = (capture, client IP).

## Labels (frozen)
`src/ja4next/labels.py` as hashed. Malicious = analyst IOC file or post page of the same post, abuse.ch SSLBL
certificate SHA1, Feodo IP (gold), or Maltrail static trail (weak). Benign = vendor allowlist, on no IOC list.
Primary analysis: gold + weak vs benign, **hostname-only** (bare-IP connections excluded, because the
allowlist needs a hostname). Secondary: gold-only; all connections.

## Models (frozen)
XGBoost, 200 trees, depth 4, learning rate 0.1, subsample 0.9, colsample 0.8, capture-balanced weights, seed 0.
Features are computed on every connection of a host; then at most 100 labelled connections per (capture, class)
are kept (uniform, seed 0) for training and for scoring, so beacon-heavy captures cannot dominate.
Feature sets: `TLS+BEH` (previous best), `HR+TLS+BEH` (new), `HRb+TLS+BEH` (relative behaviour only), `ENV`.
Threshold-free primary metrics; the 1% FPR point is taken on the holdout ROC curve.

## Hypotheses
| ID | Hypothesis | Test | Supported if |
|---|---|---|---|
| H1 | Host-relative features (HR = HRb + HRd) raise detection at a low false-alarm rate | TPR at 1% FPR, HR+TLS+BEH minus TLS+BEH, 1,000 capture-cluster bootstrap resamples | 95% CI lower bound > 0 |
| H2 | Host-relative features raise ranking quality | ROC-AUC difference, same bootstrap | 95% CI lower bound > 0 |
| H3 | Environment fields do not transfer to new years | ENV-only ROC-AUC on holdout | < 0.60 |
| H4 | Natural JA4 mimicry persists on 2022-2026 hosts | on hosts with both classes (hostname-only), the capture-weighted share of malicious connections whose exact JA4 also appears on a benign connection of the same host | >= 0.50 |
| H5 | Host-level triage improves | hit@1 (top-ranked connection per infected host is malicious), HR+TLS+BEH vs TLS+BEH, paired bootstrap over hosts | 95% CI lower bound > 0 |
| H6 | A no-training host-relative volume rule works on new years | ROC-AUC of `hr_dest_share` (share of the host's TLS connections to this destination) used directly as the score | >= 0.85 |

All six are reported whatever the outcome. No other comparison on the holdout is confirmatory.

## Exploratory evidence that motivated these hypotheses
Filled from `results/` before freezing (see docs/RESULTS_EXPLORATORY.md). These numbers are not tests.

Evidence so far, hostname-only, from `results/hostname_only/` and a dry run of the confirmatory code on a fake split
(train 2013-2020, test 2021; `results/dryrun_confirm_NOT_CONFIRMATORY/`, not a confirmatory result):
- H1/H2: large gains on the leave-one-source-out and train<=2018/test-2019-2021 splits (see RESULTS_EXPLORATORY.md);
  the fake split also supports both.
- H3 is genuinely open: ENV-only AUC was 0.46-0.53 on the source and time splits but 0.75 on the fake 2021 split
  (MTA's own lab set-up is fairly stable from 2020 to 2021).
- H4: capture-weighted mimicry on hosts with both classes is 0.67 over 2013-2021 (row share 0.55).
- H5: no difference on the fake split (0.91 vs 0.92).
- H6: the rule scored AUC 0.950 on the unseen-source split and 0.936 on train<=2018/test-2019-2021 (`results/hostname_only/hrd_dissect.csv`).
