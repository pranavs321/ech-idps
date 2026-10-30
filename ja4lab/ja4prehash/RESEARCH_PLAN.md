# Research plan

**Working title:** *Beyond the Hash: Generalising JA4+ TLS Fingerprints to Unseen Malicious Clients
through Pre-Hash Component Learning*

## 1. Problem (one paragraph for the abstract)

JA3/JA4 fingerprints are hashes, so they only support exact lookup. A fingerprint absent from a
database carries no information, and databases are sparse. In our JA3 study, 1.15 M TLS connections
produced 708 unique JA3 values, of which only ~30 were known to threat intelligence. The frozen
JA4DB snapshot holds 74,540 records, but only 14 are labelled as malware. We study whether the
*inputs* to the hash (the pre-hash components of JA4, JA4S, JA4T and JA4H) let a model detect and
attribute clients **whose exact fingerprint was never seen**.

## 2. Contributions (what you claim; each backed by one result file)

1. **An evaluation protocol for fingerprint generalisation.** Random splits are compared with
   leave-fingerprint-out, leave-family-out and leave-dataset-out splits. We show how much random
   splits overstate performance (`rq2_detection.csv`).
2. **A collision ceiling.** We report the fraction of malicious clients whose pre-hash parameters
   are identical to those of a benign client, both for JA4 alone and for the JA4+JA4S+JA4T
   combinations. This is the upper bound for any TLS-metadata detector (`rq1_collisions.csv`).
   It extends Matoušek et al. (CNSM 2024), who measured collisions on hashes rather than raw components.
3. **What the hash discards matters (or not).** An ablation compares CH_STRICT (exactly the JA4
   input) against CH_EXT (extension order, GREASE, groups, key shares), then adds JA4S and then JA4T
   (`rq3_ablation.csv`).
4. **Open-set family/stack attribution** of unseen fingerprints with abstention (`rq5_attribution.csv`),
   plus a **public reproducible benchmark** built from JA4DB raw strings (`ja4db_attribution.csv`).
5. **A validated open extractor** with TCP reassembly and retransmission deduplication, verified
   against FoxIO's reference implementation, together with a measured naive-vs-reassembled extraction
   gap (`extraction_gap.csv`).

Do not claim "zero-day detection" or "novel IDS". Claim **generalisation beyond exact lookup,
measured honestly**. That is defensible.

## 3. Positioning against related work (read these five first)

- Althouse et al., JA3 (Salesforce, 2017) and the JA4+ technical details (FoxIO, 2023).
- Anderson & McGrew, *Identifying encrypted malware traffic with contextual flow data*, AISec 2016;
  *Accurate TLS fingerprinting using destination context and knowledge bases*, 2020. This is fuzzy
  matching, which our kNN-Jaccard baseline represents.
- Matoušek, Ryšavý, Burgetová, *Experience Report: Using JA4+ Fingerprints for Malware Detection in
  Encrypted Traffic*, CNSM 2024 (DOI 10.23919/CNSM62983.2024.10814358). It covers hash uniqueness and collisions.
- *Towards identification of network applications in encrypted traffic*, Annals of Telecommunications 2025.
  Its JA3-vs-JA4 point is that high JA3 uniqueness creates many unseen fingerprints.
- *Detecting Malware in Encrypted Network Traffic Using ML and TLS Fingerprints* (Springer, 2025).
  It compares JA4+ with MalDIST-style flow features.

**Our gap:** these works use the fingerprint *as a token*. None evaluates generalisation to
*unseen* fingerprints from pre-hash components under group-disjoint splits.

## 4. Experimental protocol

- **Unit of analysis:** the client instance = (pcap, client IP, full raw fingerprint set). This
  prevents 10,000 identical beacons from counting as 10,000 correct predictions. Report
  connection-level numbers only as a secondary view.
- **Labels:** malicious means the connection comes from the infected host and its SNI is not a
  well-known benign domain. Popular-domain traffic from a victim goes to a *gray* set, which is
  excluded and reported.
- **Baselines:** (i) exact JA4 lookup built from the same training data; (ii) external DB lookup
  (JA4DB, FoxIO); (iii) kNN with Jaccard distance over component sets (fuzzy matching).
- **Models:** HistGradientBoosting (main), Random Forest, Logistic Regression.
- **Metrics:** PR-AUC (main, robust to imbalance), TPR at 1% FPR (operational), precision, recall,
  F1 and FPR at a threshold chosen on an inner validation split (never on test), plus lookup
  coverage. Report mean ± std over folds.
- **Must-have sanity checks:**
  - A leave-dataset-out drop exposes shortcuts where the model learns the dataset instead of the malware.
  - For the time split, train on older captures and test on newer ones (add it if your sources span years).
  - Confirm that the unseen-JA4 subset of the random split behaves like leave-fingerprint-out.

## 5. Data plan (target sizes)

| | Minimum for a credible paper |
|---|---|
| Malicious families | ≥ 15, each with ≥ 2 distinct JA4 (needed for leave-fingerprint-out within a family) |
| Malicious PCAPs | ≥ 150 (MTA 2023–2026 + Stratosphere) |
| Benign sources | ≥ 3 datasets **plus** your own lab captures (browsers, curl, Python, Go, Java, Office, updaters) |
| Distinct JA4 overall | ≥ 1,000 |

Your own lab captures are the most valuable benign data: exact labels, current software, and no
"benign from 2016 vs malware from 2025" shortcut.

## 6. Paper outline (IEEE conference / Elsevier *Computers & Security* style)

1. Introduction: lookup sparsity statistics, research questions, contributions
2. Background: JA4+ construction and what each hash discards
3. Related work: the table above
4. Methodology: extraction and reassembly, label hygiene, feature groups, splits
5. Datasets: table of sources, families and counts after cleaning (from `.report.csv`)
6. Results: RQ1 collisions → RQ2 protocols → RQ3 ablation → RQ4 attribution + JA4DB benchmark → importance
7. Discussion: inseparable cases, spoofing (uTLS/curl-impersonate), ECH, deployment cost
8. Limitations and ethics
9. Conclusion, plus release of code and cleaned instance-level dataset (not raw PCAPs)

Candidate venues: IEEE CNSM, IFIP Networking, ACSAC workshops, and the journals *Computers & Security*,
*Journal of Information Security and Applications*, *IEEE Access*.

## 7. Timeline (10 weeks)

| Week | Work | Deliverable |
|---|---|---|
| 1 | Smoke test; collect PCAPs into the folder layout; write infected_hosts.csv | `connections.csv` for the first 50 PCAPs |
| 2 | Lab captures of benign software (script the browsers and tools) | benign set ≥ 3 sources |
| 3 | Cleaning; dataset table; RQ1 collisions | Table 1 + collision figure |
| 4–5 | RQ2/RQ3 on the full data; check the leave-dataset-out drop | main results table |
| 6 | RQ5 attribution + JA4DB benchmark + TI coverage | attribution table |
| 7 | Error analysis: inspect 20 false negatives and 20 false positives in Wireshark | discussion section |
| 8 | Robustness: time split; spoofing test with curl-impersonate / uTLS if time allows | robustness paragraph |
| 9–10 | Writing, figures, internal review with Arjun chetta | submission draft |

## 8. Preliminary result (real, public data)

JA4DB snapshot benchmark, stack attribution on **unseen fingerprints only**, 5-fold group-disjoint:
901 unambiguous raw strings in 7 stack families.

| | Accuracy | Coverage |
|---|---|---|
| Exact lookup | 0% (no test JA4 is known) | 0% |
| Majority class | 55.5% | 100% |
| Model (τ = 0) | 72.5% ± 4.1 | 100% |
| Model (τ = 0.9, abstain otherwise) | 79.1% ± 3.7 | 82.6% |

Also, 401 raw strings (31%) were claimed by more than one User-Agent family, which is evidence of
UA spoofing or shared TLS stacks. Macro-F1 is modest (0.52) because minority stacks are small;
more data will change these numbers.
