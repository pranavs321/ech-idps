# FINDINGS — verified results so far (exploratory: public Matoušek corpus)

Every number below comes from files in `results_reference/`, produced on 2026-10-06 by the commands
in the README. Input: upstream CSVs (sha256 in `data/external/matousek/MANIFEST.sha256` at fetch time:
desktop-apps `b2c1f454…`, desktop-malware `3e4e2967…`, mobile-apps `2023f1a7…`, mobile-malware
`ba115fc8…`), canonical table `sha256=1888415bff46…`. XGBoost 3.4.1, scikit-learn 1.8.0, seed 42,
1,000 capture-bootstrap resamples. Model runs use TCP only and exclude rows without a capture id:
**18,704 flows, 1,421 captures**. These results are *exploratory*: this corpus was analysed before the
pre-registration (see PREREG section 0).

## F0. The harness catches a planted leak  (`results_reference/leak_test/`)

Adding a JA4 target-mean computed on all rows (test included) under P3 (unseen fingerprints) raises
ROC-AUC from **0.857 [0.827, 0.881] to 0.918 [0.895, 0.936]** (non-overlapping; per-fold mean 0.808 →
0.849). Under P2 the same leak adds only 0.004, because 99% of test fingerprints were already in
training. 10/10 unit tests pass, including exact agreement of the fast bootstrap metrics with
scikit-learn.

## F1. Desktop: the class is the machine  (`results_reference/audit_all`, `audit_tcp`)

All 255 benign desktop rows (24 captures) come from one lab Windows machine; all 11,491 malicious
desktop rows (866 captures) from the Tria.ge sandbox. No desktop environment holds both classes.
Cramér's V(environment, label) = 0.585 (all rows) / 0.566 (model filter); 55.6% / 52.4% of labelled rows
sit in single-class environments.

## F2. Provenance gap

1,713 published rows have no pcap filename (1,515 desktop-malware, 94 mobile-apps, 104 mobile-malware),
so they cannot be split by capture. The schema validator caught this; they are flagged, not deleted.

## F3. Host-level labels: sandbox background is labelled malware

- 3,663 Tria.ge "malicious" rows (31.9%) go to OS/browser background domains (Bing, Microsoft, Office,
  Google; list in `ja4bench/adapters/matousek.py`). Model filter: 3,465 rows, 23.8% of malicious rows.
- **437 of 865 sandbox malware captures (50.5%) contain no labelled TLS flow except background
  traffic.** Upper bound: some malware abuses Google/Microsoft services, so spot-check 20 of these
  captures' sandbox reports by hand before quoting the number (task in TASKS.md, T04 note).

## F4. The top "malware" fingerprint is a browser

`t13d1516h2_8daaf6152771_e5627efa2ab1` is the most frequent malicious JA4 (2,900 rows) and the second
most frequent benign JA4 (501 rows). The same string is documented for Playwright-driven Chromium
(webdecoy.com JA4 guide, 2026) — i.e. the sandbox's Chromium/Edge, not malware.

## F5. XGBoost = a lookup table  (`results_reference/protocols_main/`)

| | P1 random | P2 capture-disjoint |
|---|---|---|
| JA4 lookup table | 0.920 [0.900, 0.937] | 0.910 [0.883, 0.933] |
| XGBoost, JA4 components | 0.920 [0.900, 0.937] | 0.908 [0.882, 0.931] |
| Random forest, JA4 components | 0.920 [0.900, 0.937] | 0.909 [0.880, 0.933] |

ROC-AUC with 95% capture-bootstrap CI. The learned models add nothing over memorising fingerprints.

## F6. Environment alone (no TLS field at all) nearly matches

`xgb:env_only` (client /24 subnet, destination port, transport) reaches **ROC-AUC 0.857 [0.818,
0.892] under P2** — the Environment Leakage Index — while alerting on only 2.5% of benign captures.
Under P3 its per-fold mean (0.859) exceeds the JA4 model's (0.808).

## F7. Unseen fingerprints (P3)

XGBoost per-fold mean ROC-AUC **0.808** (worst fold 0.604); 36.7% of benign captures get at least one
alert. The lookup table is 0.5 by construction (its pooled 0.326 is a pooling artefact; see SUMMARY
notes).

## F8. Cross-platform (P6, per fold)

- Train desktop → test mobile: XGBoost ROC-AUC **0.227** (worse than random), flags 93.9% of benign
  mobile flows.
- Train mobile → test desktop: ROC-AUC 0.883, but recall **11.3%** at the default threshold.
- Only 17.6% of mobile rows have a JA4 ever seen on desktop (34.9% the other way).

## F9. Environment-matched subset (P8: mobile half, HashApp emulator, 8,910 flows, 532 captures)

- The environment-only model drops to **0.578 [0.506, 0.652]**, confirming the environment is matched.
- The JA4 model keeps ranking ability: **0.906 [0.887, 0.923]**, again identical to the lookup table
  (0.906).
- At the operating threshold it degrades: F1 0.823, and **54.3% of benign app captures** get an alert
  (30.6% under P2).
- 89.2% of malicious rows use a JA4 also seen on benign apps in the same environment. The JA4
  label-conflict floor is 17.1%: no JA4-only classifier can be wrong on fewer rows, even in-sample.
- Label caveat: many mobile "malware" flows are ad-SDK traffic from adware-like apps (e.g.
  `cdn.iads.unity3d.com` labelled M).

**Correction (2026-10-06):** an earlier chat summary said JA4 "barely works" where the environment is
held constant. The model run does not support that wording. Ranking (ROC-AUC) survives at 0.906; what
fails is the operating point (half of benign captures alerted) and the conflict floor caps accuracy.
State it that way.

## F10. ECH ablation: SNI does the heavy lifting

| Protocol | JA4 components | JA4 + SNI | Δ |
|---|---|---|---|
| P2 | 0.908 | 0.982 | +0.074 |
| P4 family-disjoint | 0.855 | 0.920 (FPR 0.259 → 0.397) | +0.065 |
| P8 env-matched | 0.906 | 0.993 | +0.087 |
| P6 cross-platform (fold mean) | 0.555 | 0.485 | −0.070 |

SNI identifies destinations (app back-ends, ad networks, sandbox background), which is memorisation of
infrastructure. ECH (RFC 9849) removes exactly this, and it does not transfer across platforms anyway.

## F11. Pre-registered variant: drop OS-background flows  (`results_reference/protocols_no_osbg/`)

15,133 flows, 980 captures remain. P2: JA4 model 0.900 [0.876, 0.924], lookup 0.899, env-only 0.812.
P3 per-fold mean falls **0.808 → 0.708**; P4 pooled 0.855 → 0.817. Part of what looked like
generalisation to unseen fingerprints was background traffic.

## F12. Not testable on this corpus

P5 temporal skipped (training years ≤ 2022 / ≤ 2023 contain only malware); P7 needs a second source.
Both come from MTA 2024–26 and the Dataset A rebuild.

## Exploratory check against the pre-registered hypotheses

| H | Bound | Here | Status |
|---|---|---|---|
| H1 memorisation | XGBoost − lookup < 0.02 (P2) | −0.002 | consistent |
| H2 confound | ELI ≥ 0.80 | 0.857 [0.818, 0.892] | consistent |
| H3 unseen JA4 | ≤ 0.75 | 0.808 per-fold (0.708 without background) | **not met** on main run |
| H4 env-matched collapse | P8 < P2 ROC-AUC | 0.906 vs 0.908 | **not met** on ROC-AUC; host alerts 54.3% vs 30.6% |
| H6 ECH | report drop | +0.074 from SNI (P2) | reported |

Unmet hypotheses are results. H3/H4 bounds stay as pre-registered for the confirmatory datasets.

## One paragraph you can say in the viva

On the public JA4+ benchmark, a learned JA4 detector is indistinguishable from a lookup table of
fingerprints. A model given no TLS information at all — just the client subnet, port and transport —
reaches 0.86 ROC-AUC because benign and malicious desktop traffic were recorded on different machines.
Half of the sandbox "malware" captures contain only Windows background traffic. Trained on one platform
and tested on the other, the detector ranks worse than chance. Where the environment is genuinely
matched, ranking survives but more than half of benign app captures raise an alert. And most of what
SNI adds is destination memorisation that ECH will remove.
