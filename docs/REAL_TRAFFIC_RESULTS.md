# ech-idps on real traffic (14 Nov 2026, exploratory)

Everything in `README.md` up to this point was measured on the simulated corpus
(`datasets/generator.py`). This page is the first measurement of this repository's own
sensor and models on real captures. Numbers come from
`results_reference/real_pcap/real_pcap_results.csv` and `real_pcap_report.json`,
produced by `scripts/05_real_pcap_eval.py`. **All of it is exploratory**: the
2022-2026 captures are held back for a pre-registered confirmatory run
(`ja4next/docs/PREREG_ADDENDUM.md`).

## Data
Every public infection capture from malware-traffic-analysis.net, 2013-2021: one infected
Windows host plus that host's own normal traffic in each capture, so benign and malicious
connections share the machine and the network path. 894 capture files with labelled TLS
connections; 61,605 labelled connections. Malicious = the analyst's own indicator file or
post for that capture, abuse.ch SSLBL certificate, Feodo, or Maltrail; benign = major
vendor/CDN allowlist and on no indicator list. Evaluation is hostname-only (40,644
connections in 744 captures; at most 100 per capture and class are scored). The pipeline
that builds this is in `ja4next/`.

Three "sources" are three eras of the same analyst's lab: 2013-2016, 2017-2018, 2019-2021.

## 1. The sensor now works on real captures
| Check | Result |
|---|---|
| Labelled connections the sensor matched | 60,691 of 61,605 |
| Matched connections with a JA4 | 60,689 |
| JA4 agreement with an independent, FoxIO-validated extractor | 100% |
| Flows oriented the wrong way round | 1 |
| FoxIO reference captures (IPv4/TCP rows) through the sensor's pcap path | 148 correct, 0 wrong |
| Simulated pipeline (`run_all.py`) before vs after the fixes | identical: AUC 0.9695, recall 0.691 at 0.5% FPR |

Bugs fixed (none can show on the simulated corpus, which bypasses pcap parsing):
1. Ethernet trailer padding was counted as TCP payload (`sources._parse_frame`).
2. Packet direction came from the string order of the two addresses (`flow.canonical_key`):
   the ClientHello was lost and every direction feature flipped for about one connection in nine.
3. For the same reason `src_ip` could be the server, so a source-scoped block could hit a CDN.
4. JA4_c sorted the signature algorithms and had no separator (`ja4.compute_ja4`).
5. A ClientHello split over TCP segments was parsed from its first piece (wrong JA4).
6. Non-ASCII ALPN handling now follows FoxIO's reference code.
Also: pcapng, raw-IP and Linux-cooked captures are read; idle sweeps no longer scan the
table on every packet.

## 2. Tier 2 and D(x) on real traffic
| Model | Same source: AUC / TPR at 1% FPR | Unseen source: AUC / TPR at 1% FPR |
|---|---|---|
| Tier 2, 14-D vector | 0.990 / 0.844 | 0.877 / 0.550 |
| Tier 2 + D(x), four hand-written browser profiles | 0.989 / 0.840 | 0.798 / 0.251 |
| Tier 2 + D(x), classes learned from the data (TLS stack) | 0.987 / 0.783 | 0.878 / 0.561 |
| D(x) alone, hand-written profiles | 0.619 / 0.031 | 0.262 / 0.002 |
| D(x) alone, learned stacks | 0.569 / 0.045 | 0.592 / 0.025 |

Reading: the 14-D behaviour vector carries real signal. D(x) does not, on this data. With
the hand-written profiles the declared class is wrong for most flows (26,862 "safari" and
12,460 "firefox" on Windows hosts), and on an unseen source D(x) points the wrong way
(AUC 0.262) and drags Tier 2 down. Learning the classes from the data removes the harm
but adds nothing. Reason: on real infected hosts malware uses the operating system's TLS
library, so its behaviour is being compared with the right stack, and within a stack an
infected capture's malware is not an outlier. Pillar 1 as stated (a spoofed browser
fingerprint with robotic physics) is not what this data contains; it needs deliberate
impersonation (uTLS) captures to be tested fairly.

## 3. Host context (new, `module2_sensor/host_context.py`)
Each connection is described against its own host's traffic: share of the host's TLS
connections going to the same server, how many TLS stacks reach it, periodic contact, and
behaviour z-scores against the host's other connections on the same stack. It uses the
server address and port only, never the SNI, so it keeps working under ECH. It emits
numbers only; no address crosses into the ML plane and the 14-D vector is unchanged.

| Model | Same source: AUC / TPR at 1% FPR | Unseen source: AUC / TPR at 1% FPR |
|---|---|---|
| Tier 2, 14-D vector | 0.990 / 0.844 | 0.877 / 0.550 |
| **+ host context (whole capture)** | **0.997 / 0.953** | **0.973 / 0.813** |
| + host context, causal (only what the host did before) | 0.997 / 0.936 | 0.949 / 0.669 |
| + destination block only | 0.997 / 0.958 | 0.965 / 0.810 |
| + relative-behaviour block only | 0.993 / 0.856 | 0.934 / 0.585 |
| Host context alone (no 14-D) | 0.985 / 0.889 | 0.955 / 0.736 |
| Rule, no training: share of the host's connections to this server | 0.966 / 0.772 | 0.966 / 0.772 |

Gain over Tier 2 on an unseen source, paired bootstrap over captures (TPR at 1% FPR):
whole-capture +0.271 (95% CI 0.204 to 0.348); causal +0.125 (0.069 to 0.186).

## What we claim, and what we do not
- Claim: on same-host captures across three eras, describing a connection against its own
  host adds 0.27 detection at 1% false alarms on an unseen era, and a deployable causal
  version adds 0.12.
- Not claimed: real-world detection rates (one analyst's lab; captures are cut around the
  infection, so C2 may dominate a host's traffic more than on a busy machine; indicator
  lists may favour the destinations malware contacts most).
- Not claimed: that the idea is new in general. Within-bag normalisation (Bartos et al.,
  USENIX Security 2016), host baselining (Yen et al., ACSAC 2013) and beacon detection
  (Hu et al., DSN 2016) are prior work. The contribution is the reference set (same host,
  same TLS stack), the ECH-compatible form, and the cross-era measurement.
- Known negative: host context is worse than plain features at saying whether a whole
  host is infected (it always finds some "top destination"); use it to rank connections.

## Reproduce
```bash
cd ja4next && scripts/run_stage.sh labels && scripts/run_stage.sh crawl
YEARS=2013-2021 scripts/run_stage.sh download && scripts/run_stage.sh process
python3 -I scripts/export_echidps_labels.py data/processed/echidps_labels.csv
cd .. && python3 scripts/05_real_pcap_eval.py --labels ja4next/data/processed/echidps_labels.csv --out results/real_pcap
python3 tests/test_real_pcap_sensor.py && python3 tests/test_host_context.py
```

Reference copies of the ja4next result files are in `results_reference/ja4next/` (the `results/` folders are git-ignored).

## Additional analyses (14 Nov, exploratory; `ja4next/scripts/extras.py`, `results_reference/ja4next_extras/`)
- **TLS version matters.** On TLS 1.3 connections, host context lifts TPR at 1% FPR from 0.030 to 0.631 (AUC 0.834 to 0.945). On TLS 1.2 it lifts 0.079 to 0.807. The TLS 1.0 stratum is 94% malicious, so its benign side is too small to read.
- **TLS version alone is not a shortcut.** A depth-1 tree on the version scores AUC 0.272 on unseen eras: it inverts across eras.
- **Group-robust training gives no reliable gain.** A GroupDRO-style reweighting over era x label groups moves the worst-era AUC from 0.850 to 0.859 and lowers the overall AUC from 0.972 to 0.965. Not a reason to change the method.
- **Variance decomposition is a caveat.** Between-era share of raw behaviour features is 0.000 to 0.083, so eras barely differ in those features. Host-relative z-scores still show 0.10 to 0.26 between-capture share, so they are not fully capture-free.
