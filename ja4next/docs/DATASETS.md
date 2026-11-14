# Data sources: what to add next (checked 14 Nov 2026)

All URLs were checked live on 14 Nov 2026 unless marked *not verified*. Never download or open any file with
"malware", ".exe.zip" or "-and-artifacts" in its name: those are live samples.

## In use now
| Source | Role | Notes |
|---|---|---|
| malware-traffic-analysis.net (MTA) posts 2013-2021 | same-host infections (one Windows host + its own background traffic per pcap) | Crawled by `crawl_mta.py`; zip password `infected_YYYYMMDD` = post date (fallback: filename date, then `infected`). 2019-2021: 454 pcap zips (~4.4 GB) and 188 analyst IOC files. |
| MTA 2022-2026 | **holdout**, listed in the manifest only | Never download before the pre-registration is frozen. |
| Maltrail static trails | weak labels | Moved in 2026 to github.com/stamparm/trails (`trails.csv.gz`, 1.86 M trails). New licence: research use is fine, but **publishing per-flow labels derived from it may need permission**; publish labelling code, not labels. **Not independent of MTA**: per-family trail files cite MTA and Unit 42. |
| abuse.ch SSLBL certificate SHA1 list | gold labels (TLS <= 1.2) | CC0; 11,261 entries since 2014; still updated. |
| Feodo Tracker aggressive list | gold labels | CC0; first_seen starts 2021-01-17, so it only covers 2021 captures. |

## Add next (ranked)
1. **MTA training exercises 2019-2021** (38, https://www.malware-traffic-analysis.net/training-exercises.html). Not in the yearly indexes. Multi-host AD LANs with infected and clean hosts, plus `*-answers.pdf.zip` analyst answers = independent ground truth. Add a `sources/mta_exercises.py` (skill `/add-source`).
2. **Stratosphere CTU-Mixed-Capture-1...9-2** (https://mcfp.felk.cvut.cz/publicDatasets/, ~19 GB). The only public captures where a real user keeps working on the same Windows machine before, during and after infection. Labels: README timelines (infection time, C2 IP). Check each for malicious TLS first (Mixed-6 DarkVNC C2 on 443 is not TLS). Skip `*.exe.zip`, `*.json`, `*.html`. Licence: cite Garcia, Malware Capture Facility Project.
3. **CTU-SME-11** (Zenodo 10.5281/zenodo.7958259, CC BY 4.0, 96.6 GB). 2023, Windows 7/AD, Ubuntu 22.04, macOS, Android, iPhone; same-device benign + malicious with expert `conn.log.labeled`. Mac only (size).
4. **MCFP CTU-Malware-Capture-Botnet-*** (411 Windows VM captures 2013-2021). Malware + the same VM's OS chatter, different lab and path from MTA: the natural cross-lab test of the confound claim.
5. **Active Countermeasures "Malware of the Day"** (*not verified*; Cloudflare blocks scripts). The only source found with Havoc, Mythic, Sliver and AdaptixC2 captured on the Windows target with its OS background. Download manually and confirm the licence by email.
6. **TQH-C2 v1.2.5** (Zenodo 10.5281/zenodo.23905375, CC BY 4.0, 39.9 GB). Linux containers; Sliver TLS 1.3, Merlin HTTP/3-QUIC and HTTP/2, Mythic. A TLS 1.3/QUIC stress test, **not** same-host realism (the README says destination IP/port separate the classes perfectly; strip them).
7. **Ryšavý 2026 Brno annotated TLS dataset** (Zenodo 10.5281/zenodo.18336960, CC BY 4.0, 70 MB Parquet). 828k Triage sandbox TLS connections from 2025 with JA4/JA4S and an OS-service tag: malware-driven and OS-driven connections in the same sandbox VM. Quick test of sandbox mimicry. Pcaps on request.
8. **Benign at scale / modern TLS:** CESNET-TLS-Year22 (JA3 only), CESNET-QUICEXT-25, ARPA47 (Zeek logs with confirmed **ECH** sessions, 2026, CC BY 4.0). No public malware-over-ECH dataset exists.

## Label rules that follow from the checks
* Train only on labels whose terms allow it: MTA analyst IOCs, SSLBL and Feodo (CC0). abuse.ch's Terms of Use (§7.3, updated 21 Oct 2026) forbid using its data to train AI models without consent; treat ThreatFox/URLhaus as evaluation-only, and they now keep only 90 days / 6 months of history anyway (exports need an Auth-Key).
* Maltrail and ET Open both cite MTA (73 ET rules do), so they are not independent labels for MTA pcaps. Report gold-only results (MTA IOC + SSLBL + Feodo) beside all-label results.
* Same-host caveat: on 2019-2021 Windows 10 hosts, browsers speak TLS 1.3 while SChannel malware speaks TLS 1.2, so the `t13`/`t12` prefix can separate classes on the same host. Report results stratified by TLS version.
* Deduplicate by pcap SHA-256 across sources (Unit 42 quizzes and MTA posts share an author).
