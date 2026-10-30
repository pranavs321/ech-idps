# Beyond the Hash: learning from JA4+ pre-hash components

**Research question.** JA3/JA4 fingerprints only work as a lookup: an unknown hash tells you nothing.
Can a model that reads the pre-hash inputs (cipher suites, extensions, signature algorithms, and the
JA4S/JA4T/JA4H inputs) detect malicious clients and attribute the client family when the exact
fingerprint has never been seen before?

See `RESEARCH_PLAN.md` for the research questions, the novelty argument, the paper outline and the timeline.

---

## 1. Setup (Ubuntu / WSL2 recommended)

```bash
sudo apt install -y tshark unzip        # tshark is only needed for the FoxIO validation
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
bash scripts/smoke_test.sh              # must end with "SMOKE TEST PASSED"
bash scripts/get_threat_intel.sh        # JA4DB snapshot + FoxIO mapping
```

## 2. Put your PCAPs in this folder layout (labels come from the path)

```
data/raw/
  benign/<source>/<app_or_group>/*.pcap(ng)        e.g. benign/stratosphere_normal/CTU-Normal-20/x.pcap
  malicious/<source>/<family>/*.pcap(ng)           e.g. malicious/mta/lumma/2025-01-15-traffic.pcap
```

- `<source>` is the dataset name (stratosphere, mta, ctu13, iscx, own_lab ...). It is used by the
  leave-dataset-out test.
- `<family>` is the malware family or benign application. It is used for leave-family-out and attribution.
- **Important:** for every malicious PCAP, write the victim IP into `data/meta/infected_hosts.csv`
  (format in `infected_hosts.example.csv`). MTA posts and Stratosphere READMEs always state it.
  Without this file a heuristic (the most frequent client) is used, and it is flagged in the output.
- Pinned Tranco list: ID daily, date 2026-10-07, SHA-256 2f7b9a1ee3dbbf834f5ea6a3ef48a66bca83b8a49cacd87efad8cd769d176967. Downloaded to `data/meta/tranco.csv`
  for stronger background-noise filtering.

## 3. Run

```bash
bash scripts/run_all.sh
```

or stage by stage:

| Stage | Command | Output |
|---|---|---|
| Extract | `python -m ja4lab.extract --pcap-root data/raw --out data/interim/connections.csv` | 1 row per TCP connection: JA3, JA4, JA4_r, JA4_ro, JA4S, JA4T, JA4TS, JA4H and all raw components |
| Clean + dedup | `python -m ja4lab.label --in ... --out data/processed/instances.csv --infected data/meta/infected_hosts.csv` | client instances plus a `.report.csv` of how much was dropped and why |
| Experiments | `python -m ja4lab.experiments --instances data/processed/instances.csv --out results` | `rq1_collisions.csv`, `rq2_detection.csv`, `rq3_ablation.csv`, `rq5_attribution.csv`, `importance_*.csv`, figures, `SUMMARY.md` |
| Threat intel | `python -m ja4lab.threatintel coverage --instances ...` | how many of your fingerprints any database knows |
| Public benchmark | `python -m ja4lab.threatintel benchmark` | attribution on JA4DB raw strings (reproducible by anyone) |
| Data quality | `python scripts/measure_extraction_gap.py --pcap-root data/raw --out results/extraction_gap.csv` | naive per-packet parsing vs reassembly |

## 4. Verified correctness (report this in the paper)

Agreement with the reference implementations on FoxIO's 39 test PCAPs (`tests/validate_against_foxio.py`):

| Fingerprint | Agreement | Remaining differences |
|---|---|---|
| JA4 | 150/151 | 1 non-ASCII ALPN: we follow the written spec (hex rule), FoxIO python uses '9' |
| JA4S | 85/85 | none |
| JA4H | 69/71 | 2 are HTTP/2 inside TLS and need decryption keys (out of scope) |
| JA4T | 39/39 (vs `ja4plus`) | none |
| JA3 | matches Wireshark | none |

`tests/test_reassembly.py` splits a real 2 KB post-quantum Chrome ClientHello into 64-byte segments,
shuffles them and injects retransmissions. The result must be the identical JA4, counted exactly once.

## 5. Known limitations (state them, reviewers like honesty)

- QUIC (UDP/443) is counted but not fingerprinted. Use the `ja4plus` package for QUIC Initial decryption if you need it.
- JA4H exists only for plaintext HTTP. Many malware families still use HTTP C2, while HTTPS headers are encrypted.
- Heavily ECH-deployed traffic hides SNI but not the outer ClientHello structure, so the method still applies.
- `results_SMOKE/` is synthetic, and so is anything from `make_smoke_data.py`. **Never report these numbers.**

## 6. Licences

JA4 (TLS client) is BSD-3. JA4S/JA4H/JA4T are under the FoxIO License 1.1, which permits academic
and internal use; commercial resale needs an OEM licence. Cite FoxIO. Our code is your team's.

## 7. Safety

Malware PCAPs can contain live binaries inside HTTP transfers. Work inside a VM, never export
objects from the captures, and keep MTA zip passwords out of scripts. Do not put CISAI/NDA-covered
captures in public repos or external tools.
