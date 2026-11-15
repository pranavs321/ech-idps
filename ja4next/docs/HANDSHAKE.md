# TLS handshake profile and shortcut checks (exploratory, 15 Nov 2026)

Script: `scripts/handshake_profile.py`. Numbers: `results/handshake/` (`summary.json`, `tier_summary.csv`,
`version_by_tier.csv`, `version_by_year.csv`, `top_ja4.csv`, `shortcut_checks.csv`).
Data: MTA 2013-2021, 88,085 connections from 1,052 captures (61,605 labelled).

## What the handshake shows
| | benign | gold malware | weak malware |
|---|---|---|---|
| connections | 8,074 | 38,888 | 14,643 |
| server name (SNI) present | 100% | 60% | 64% |
| TLS 1.0 | 1.2% | 21.3% | 25.6% |
| TLS 1.2 | 82.9% | 76.7% | 71.6% |
| TLS 1.3 | 15.0% | 2.0% | 0.4% |

* **Malicious connections share a fingerprint with benign ones.** 60.7% of labelled malicious connections use a JA4 that also
  appears on benign connections, and 64.7% of captures have a malicious connection sharing one. This is the same mimicry
  effect measured in the same-host benchmark.
* **Two shortcuts exist in the labels.** Benign connections always have a server name (their labels require an allowlisted name),
  while 39% of malicious connections have none. Malware also uses TLS 1.0 far more often.
* **How much each shortcut is worth** (decision tree on one feature, capture-disjoint AUC): missing server name alone **0.64**,
  TLS version alone **0.62**. Both are weak on their own.
* The main model is hostname-only, which removes the server-name shortcut. The TLS version stays as a feature, so the
  version shortcut is still possible; it is smaller than the environment shortcuts measured elsewhere, but it should be
  reported alongside the main results.

## What this means for the model
1. Keep the hostname-only rule as the primary analysis and report the missing-name rate as a label-artefact check.
2. Report a TLS-version-only baseline next to every TLS result (the same check the earlier audit recommended).
3. The overlap of malicious and benign fingerprints is large, so detection must come from behaviour and destination context
   (the host-relative features), not from the fingerprint alone.
