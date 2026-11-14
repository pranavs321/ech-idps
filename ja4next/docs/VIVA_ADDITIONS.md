# Viva questions for the new work (answer in your own words; quote numbers from results/ with their split)

| Question | Short answer (fill the numbers from docs/RESULTS_EXPLORATORY.md) |
|---|---|
| What is a host-relative feature? | A connection's behaviour described against the same host's other connections in the same capture (robust z-score and rank), overall and within the host's own JA4 stack. Anything constant within the host (OS, path MTU, latency, VPN) cancels. |
| Why not just per-source normalisation? | That is the domain-generalisation strawman (`TLS+BEHsrc`); it needs the whole target source in advance and does not remove host-level differences. We report it beside ours. |
| Which part actually helps across sources? | The destination-context part (HRd), not the relative behaviour part (HRb). See the HRd dissection table: we tested each group alone and left out. |
| Is HRd just learning how you labelled? | That is the key threat. Benign labels come from a vendor allowlist and malicious ones from IOC lists, so features that identify big-vendor infrastructure (e.g. many hostnames on one server IP) could be a labelling proxy. We report each HRd group separately and the gold-only run; we claim only what survives. |
| Why did the label-free host x JA4 outlier score fail? | In an infected capture the malware's connections are many and alike, so they ARE the norm of their stack; benign connections look unusual by comparison (AUC below 0.5). Same-capture baselines are contaminated. |
| Why cap 200 connections per capture and class? | A few beacon-heavy captures hold thousands of near-identical rows. Features are computed on all connections first; the cap only limits which labelled rows train/test, and capture weighting already gives every capture equal weight. |
| What is the nuisance-injection test? | We multiply every host's packet sizes by a random factor (0.75-1.35) and its timing by 0.5-2.5, then score with models trained on clean data. Absolute-feature models should drop; host-relative ranks should not. |
| What are environment-matched negative bags? | Each infected host vs the same host with its labelled malicious connections removed (features rebuilt). Same OS, path and benign software, so a bag-level AUC above 0.5 cannot come from recognising the environment. |
| What did the 2022-2026 holdout show? | Not run yet: it is reserved for the pre-registered confirmatory test (docs/PREREG_ADDENDUM.md) after the guide signs off. |
| Why is natural mimicry lower than the 89.5% you reported before? | Different label sources (analyst IOC files now included) and many beacon-heavy 2021 captures. Capture-weighted on hosts with both classes it is the number in results/dataset_summary.json; report both definitions. |
| Can TLS version alone separate the classes? | Partly: on 2019-2021 Windows 10 hosts browsers use TLS 1.3 and SChannel malware TLS 1.2 (TLS 1.0 appears only in malware). We report results by version. |
