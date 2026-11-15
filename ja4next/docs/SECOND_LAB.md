# Second independent lab (Stratosphere MCFP): what it shows and what it does not

Exploratory, 15 Nov 2026. Scripts: `scripts/fetch_mcfp*.py`, `scripts/label_mcfp.py`, `src/ja4next/second_lab.py`,
`src/ja4next/feature_direction.py`, `src/ja4next/foreign_benign.py`, `src/ja4next/incidents.py`.
Numbers: `results/second_lab/`, `results/second_lab_weak/`, `results/foreign_benign/`, `results/incidents/`.

## Data
* Botnet captures: 220 small + 26 larger banking-trojan captures fetched (0 failures); Mixed/Normal: 32 fetched. TLS rows extracted, each pcap deleted.
* Labels come only from each capture's README (infected host IP, infection time) plus public feeds (SSLBL certificates, Feodo, Maltrail) and the vendor allowlist. No model labels.
* Hostname-only analysis: 95% of botnet connections carry no website name and are dropped (bare-IP shortcut guard).

## Detection in the second lab: NOT confirmed
Train on MTA 2013-2021, test on MCFP, capture-weighted, 3 seeds, hostname-only.

| Labels (test malware / benign captures) | TLS+BEH AUC | HR+TLS+BEH AUC | TLS+BEH TPR@1% | HR+TLS+BEH TPR@1% | HR minus TLS+BEH AUC, 95% CI |
|---|---|---|---|---|---|
| Strict: certificate-blacklist / Maltrail confirmed (8 / 23) | 0.950 | 0.953 | 0.293 | 0.332 | +0.01 [-0.12, +0.11] |
| Broad: any non-allowlisted hostname on the infected host after infection (15 / 23) | 0.621 | 0.675 | 0.136 | 0.167 | (not significant) |

Reading:
* Under strict labels every model except TCP/IP-only already reaches AUC ~0.95, and host-relative features add nothing reliable. An earlier run with only 6 malware captures looked much better for the host-relative model (TPR@1% 0.78 vs 0.02); that gap **did not survive adding two more captures**, which is why the small-n result must not be quoted.
* Under broad labels all models are weak (AUC 0.62-0.68).
* The reverse direction (train on 31 MCFP captures, test on MTA) gives HR+TLS+BEH +0.06 AUC [+0.04, +0.09] over TLS+BEH, but the training set is small.
* The label rule decides the answer. We report both and claim neither as confirmation.

## What does hold across labs
Single-feature ROC-AUC computed separately in each lab (`results/second_lab/feature_direction.csv`): of 215 features, 156 point the same way in both labs;
among the 31 features that separate classes clearly (|AUC-0.5| >= 0.1) in **both** labs, **30 point the same way**. The strongest are destination-context features:
`hr_dest_n_conns` (0.89 MTA / 0.92 MCFP), `hr_ja4s_share` (0.95 / 0.79), `hr_beacon_periodicity` (0.76 / 0.90), `hr_dest_share` (0.95 / 0.76).
Caveat: the malicious class in both labs is dominated by beaconing C2 connections that the blacklists can confirm, which these features naturally reward.

# Incident grouping (idea from the concurrent SCBD-R project; exploratory, `results/incidents/`)
Leave-one-source-out on MTA 2013-2021 hostname-only; incident = host + destination + 1 hour (5,672 labelled incidents,
1,559 malicious). Threshold = 1% connection FPR on held-out benign.

| Set | Connection TPR@1% | Incident AUC (max) | Incident TPR@1% | Benign alerting incidents per host |
|---|---|---|---|---|
| TLS+BEH | 0.128 | 0.823 | 0.263 | 0.183 |
| HRb+TLS+BEH | 0.150 | 0.839 | 0.330 | 0.169 |
| HR+TLS+BEH | 0.778 | 0.924 | 0.578 | 0.125 |

Reading: grouping lowers benign alerts per host only modestly here (0.213 connection alerts -> 0.125 incidents for the
HR model, about 1.7x), far from SCBD-R's 44.6x. MTA benign hosts have few connections per hour, so there is little to merge.
Incident-level TPR is lower than connection-level for HR+TLS+BEH because many malicious incidents are single connections.
The host-relative model stays best at both levels.

# Clean foreign benign: Stratosphere CTU-Normal and CTU-Mixed (exploratory, `results/foreign_benign/flag_rates.csv`)
Data: 32 captures fetched (0 failures), 108,929 TLS connections. Benign ground truth without any allowlist:
17 CTU-Normal captures (documented normal host, 74,046 hostname connections; Windows and Kali Linux, scripted browsing of
Alexa/Quantcast top sites) and 3 Mixed "before infection"/"only normal" files (675 connections, a real user).
Models trained on 80% of MTA 2013-2021 captures; threshold = 1% FPR on the held-out 20% MTA benign.

| Set | Clean normal hosts flagged | Real user before infection flagged |
|---|---|---|
| ENV (TCP/IP only) | 76.3% | 32.3% |
| TLS | 0.0% | 19.4% |
| BEH | 7.8% | 11.4% |
| TLS+BEH | 1.7% | 11.4% |
| HRb+TLS+BEH | 0.2% | 7.0% |
| HR+TLS+BEH | 0.0% | 0.7% |

Reading: on benign traffic from another lab, the environment-only model raises alarms on three quarters of connections
(the lab shortcut again), while the host-relative model raises almost none. Caveats: scripted top-site browsing is easy
benign traffic for destination-context features (each site is visited a few times); the real-user set is only 3 captures;
the Mixed malicious side could not be tested (READMEs give no machine-readable C&C list; feeds confirm 3 connections).
This is a false-alarm result only, not a detection result.
