# Literature map

Status: **[read-abstract]** = abstract/landing page checked 2026-10-06; **[memory]** = from memory,
verify venue/year/claims before citing. Nothing here is "read in full" yet — the reading log at the
bottom is how you turn each entry into something you can defend in a viva.

## A. JA4 / TLS-fingerprint malware detection (the work you are re-evaluating)

| Paper | What it shows | What it leaves open (your angle) |
|---|---|---|
| Matoušek, Ryšavý, Burgetová, "Experience Report: Using JA4+ Fingerprints for Malware Detection in Encrypted Traffic", CNSM 2024 (IEEE Xplore 10814358) [read-abstract] | Uniqueness and overlap of JA4/JA4S/JA4X across malware families and benign apps; public corpus | Desktop malware (Tria.ge sandbox) and desktop apps (one lab machine) never share an environment; sandbox background labelled malware (our audit, `docs/FINDINGS.md`) |
| Lipcsey-Magyar, Madarász, Pekar, "Beyond JA4+: Flow Statistics vs. TLS Fingerprinting for Encrypted Malware Detection", Infocommunications Journal 18(1), 2026, DOI 10.36244/ICJ.2026.1.4 [read-abstract] | Only 64.9% of families have unique fingerprints; flow statistics + packet lengths reach 98.11% F1; motivated by ECH | Are flow statistics also environment proxies (FIN counts, durations depend on capture window)? Needs environment-disjoint tests |
| "Detecting Malware in Encrypted Network Traffic Using ML and TLS Fingerprints", Springer 2026 [memory, from team notes] | JA4+ vs flow features; JA4TS | Same question |
| Nguyen-Huu, Phan, Nguyen-An, "Multi-View Fusion for Encrypted C2 Detection: A Leakage-Controlled Measurement Study of Evaluation Pitfalls", arXiv 2609.27311, ASIANComNet 2026 [read-abstract] | A misplaced preprocessing step adds 0.28 F1; fusion adds 0.022; flow-vs-endpoint counting flips class balance 55.1% → 4.2%; joint attack beats every configuration | Their future work = time-based and leave-one-family-out splits, independent benign corpus, problem-space evasion, JA4+ re-evaluation. That is this project. Cite them as the closest work and adopt their checklist |
| "When Handshakes Tell the Truth: Detecting Web Bad Bots via TLS Fingerprints", arXiv 2602.09606 [read-abstract] | XGBoost/CatBoost on features parsed from JA4DB (~227k records) | Shows JA4+XGBoost is standard; mimicry acknowledged as limitation |
| "Applying JEPA-Style Predictive Learning to JA4-Derived Network Fingerprints", arXiv 2607.08465 [title seen only] | Self-supervised learning on JA4 fingerprints (2026) | Read before claiming nobody does representation learning on JA4 |
| "Extending C2 Traffic Detection Methodologies: From TLS 1.2 to TLS 1.3-enabled Malware", RAID 2024, DOI 10.1145/3678890.3678921 [read-abstract] | TLS 1.3 C2 classifiers; in-house C2 + legitimate datasets; campus validation; CIC DoH-Browsing as benign TLS 1.3 | TLS 1.3 shift; good source of related-work framing |
| Novo, PhD defence "Detection of Encrypted Malware Command and Control Traffic", U. Porto [read-abstract]; Novo & Morla, AISec 2020 (flow-based detection and proxy-based evasion) [memory] | TLS record lengths/types; evasion via proxies | Evasion prior art |
| "Tweaking Metasploit to Evade Encrypted C2 Traffic Detection", arXiv 2209.00943 [read-abstract] | ML detector detects Metasploit C2; source modifications evade it | Problem-space evasion prior art |
| Anderson & McGrew: AISec 2016 (contextual flow data), KDD 2017 (noisy labels, non-stationarity), IMC 2019 "TLS Beyond the Browser" [memory] | Foundations: TLS metadata + flow features; fingerprints map to libraries/apps | Classic citations; "fingerprints identify libraries, not intent" is your thesis in one line |

## B. Shortcut learning, leakage and evaluation pitfalls (your method's backbone)

| Paper | Key point | Use |
|---|---|---|
| Flood, Engelen, Aspinall, Desmet, "Bad Design Smells in Benchmark NIDS Datasets", EuroS&P 2024 (Distinguished Paper) [read-abstract] | Six design smells in seven highly-cited NIDS datasets; correlate with poor diversity, murky labels | Frame "class = environment" as a data design smell |
| Liu, Engelen et al., "Error Prevalence in NIDS datasets: CIC-IDS-2017 and CSE-CIC-IDS-2018", IEEE CNS 2022 [read-abstract] | Many undocumented errors in orchestration, features, labelling | Why CIC-IDS2017 is BENIGN_FP only |
| Wang, Xie, Wang, Cui, "Bias in the Shadows: Explore Shortcuts in Encrypted Network Traffic Classification" (BiasSeeker), arXiv 2601.10180 [read-abstract] | Model-agnostic statistical detection of dataset-specific shortcut features on 19 datasets | Closest general method; yours is JA4-specific, malware-specific, with environment metadata and interventions |
| Zhao, Boffa, Vassio, Mellia, "ShortcutCatcher: Making Traffic Classification Reliable" (Politecnico di Torino, ACM 2025/26) [read-abstract] | Uncovers shortcut dependencies across tasks and architectures | Related; app classification, not malware |
| Jerabek, Luxemburk, Plný, Koumar, Pešek, Hynek, "When Simple Model Just Works: Is Network Traffic Classification in Crisis?", arXiv 2506.08655 [read-abstract] | >50% redundant samples in most TC datasets; duplicates cross splits; conflicting labels cap accuracy | Your **label-conflict floor** is the JA4 version of their "theoretical maximum accuracy" argument — cite it |
| Pešek & Luxemburk, 1-NN baseline, TMA 2025 poster [read-abstract] | Simple baseline matches deep learning | Supports "lookup table next to every result" |
| "The Sweet Danger of Sugar: Debunking Representation Learning for Encrypted Traffic Classification", arXiv 2507.16438 [read-abstract] | Shallow baseline beats representation-learning models; evaluation pitfalls | Pitfalls |
| "SoK: Decoding the Enigma of Encrypted Network Traffic Classifiers", arXiv 2503.20093 [team notes] | Legacy datasets, leakage, temporal overfitting, exclude SNI | Critique of Dataset A's sources |
| "Unmasking Shortcut Learning in IoT Intrusion Detection", arXiv 2609.28725 (Sep 2026) [read-abstract] | Random vs PCAP-disjoint; behaviour-only features generalise better than identity-loaded ones | Same month as your work: the topic is live |
| Beltiukov et al., "In Search of netUnicorn", ACM CCS 2023 [read-abstract]; Jacobs et al., "AI/ML for Network Security: The Emperor has no Clothes" (Trustee), ACM CCS 2022 [read-abstract via citations] | Models fail across environments; iterative multi-environment data collection; shortcut diagnosis via decision trees | Your counterfactual grid is a small, JA4-specific netUnicorn-style intervention |
| Arp et al., "Dos and Don'ts of Machine Learning in Computer Security", USENIX Security 2022 [memory] | Pitfall checklist (sampling bias, label inaccuracy, data snooping, spurious correlations, lab-only evaluation) | Map each of your protocols to a pitfall in the paper's intro |
| Pendlebury et al., TESSERACT, USENIX Security 2019 [memory] | Spatial and temporal bias in malware classification | Justifies P5 temporal |
| Kapoor & Narayanan, leakage in ML-based science (Patterns 2023) [memory] | Leakage taxonomy | Deliberate-leak test |

## C. Datasets as papers (cite when you use them)

CTU-13 — García et al., Computers & Security 2014 [read-abstract]. CTU-SME-11 — Bendl, master's
thesis CTU 2023, Zenodo 7958259 [read-abstract]. CESNET-TLS-Year22 — Hynek et al., Scientific Data
11 (2024) [read-abstract]. FlowPrint / Cross-Platform — van Ede et al., NDSS 2020 [read-abstract].
"Towards a better labeling process for network security datasets", arXiv 2305.01337 [team notes].
DataZoo — arXiv 2310.19568 [read-abstract]. IoT-23 — Garcia, Parmisano, Erquiaga 2020.
ENNetTSd-2025 — "CNNRes-DIndRNN…", Future Internet 18(1):8 (2026) [read-abstract]: merges benign
CIC-IDS2017/MCFP-Normal/VPN-NonVPN with malicious MCFP/CTU-13/USTC — a current example of exactly the
class-equals-environment construction you measure.

## D. ECH, mimicry and evasion (threat model and future-proofing)

- RFC 9849, TLS Encrypted Client Hello; draft-campling-ech-deployment-considerations-12 (July 2026)
  on loss of SNI visibility for threat detection [read-abstract].
- "Stealth over TLS: the emergence of ECH-based C&C in ECHidna malware", Virus Bulletin 2025 slides:
  malware using ECH with statically linked BoringSSL [read-abstract]. Statically linked BoringSSL gives
  a Chromium-family cipher segment — exactly the fingerprint confusion in your corpus.
- MITRE ATT&CK T1036.012 Browser Fingerprint (masquerading by spoofing TLS/HTTP fingerprints) [secondary source; verify on attack.mitre.org].
- Frolov & Wustrow, "The use of TLS in censorship circumvention", NDSS 2019 (uTLS) [memory].
- Vectra, JA3/S randomisation and cipher stunting in C2 frameworks [read-abstract, industry].
- Venugopalan et al., IMC 2025: commercial bot services evade bot detectors ~45–53% [secondary source; verify].
- JA4 sorts ciphers/extensions, so order randomisation does not change it; impersonation libraries
  (curl_cffi, tls-client, uTLS) reproduce browser JA4s exactly.

## E. Gaps this project fills (state them as "in the work we reviewed", never "nobody has ever")

1. Capture environment recorded per capture and used as a first-class evaluation variable for JA4
   detectors (protocols P6, P8; diagnostic `env_only`).
2. A label-conflict floor: the minimum error any JA4-only classifier must make, per dataset and per
   environment-matched subset.
3. Environment-matched benign controls from the same sandbox images (Tria.ge / ANY.RUN).
4. Within-capture contrast using IOC-verified C2 flows vs the same victim's background flows.
5. A JA4+ re-evaluation on IOC-verified, dated malware (MTA 2024 → 2025–26) — the Multi-View paper's
   stated future work.
6. An ECH ablation that measures how much of a detector's score comes from SNI.
7. (Optional) a factorial intervention on real, harmless traffic separating OS, TLS library and behaviour.

## Reading log (fill one block per paper before citing it)

```
paper: <short name>   read: abstract | full   date:
dataset(s) and split: <random flow | pcap-disjoint | family | temporal | cross-dataset>
benign and malicious from the same environment? yes | no | not stated
baselines reported: <lookup | trivial | none>
headline number and under which split:
one sentence I can say in the viva about how my work differs:
```
