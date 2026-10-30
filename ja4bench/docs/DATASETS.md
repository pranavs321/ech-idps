# Datasets: what to get, in what order, and why

The full machine-readable catalogue (URLs, roles, verification status) is `config/sources.yaml`.
This page explains the strategy. Entries marked *memory* there must be checked before you cite them.

## The principle

More data does not fix shortcut learning. Ten datasets where malware always comes from one place and
benign traffic from another just teach the model ten "places". What makes the project strong is
**data where class and environment are decoupled**, plus enough independent sources to test transfer.
So every capture gets environment metadata, and every source is assigned a role before it is used.

## The three environment-matched designs (the core of the paper)

| Design | How class and environment are decoupled | Sources |
|---|---|---|
| **Within-capture contrast** | Same victim host, same OS, same minutes: flows to IOC-listed C2 endpoints are malicious; the same host's OS-update/background flows are benign; everything else is unlabelled | MTA 2024 (35 IOC-verified captures, already in ja4lab), MTA 2025–26 + `malware-traffic/indicators` |
| **Sandbox-matched benign** | Benign software run in the *same* sandbox images as the malware | Tria.ge low-score runs of known software; ANY.RUN "No threats detected" runs |
| **Same real network** | Benign users and infected VMs on one network in the same week | CTU-SME-11, Stratosphere mixed captures, CTU-13 (normal + botnet labels in one capture), CTU-50-FEEL if obtainable |

Plus one that already exists in public data: the **mobile half of the Matoušek corpus**, where benign
apps and malware both ran on the HashApp Android emulator.

## Priority order (stop at any tier and you still have a paper)

**Tier 1 — have now or in days (enough for a complete paper)**
1. Matoušek CSVs (done; `results_reference/`), then its pcaps → re-extract with ja4lab for TTL /
   window / MSS / JA4T so the environment-only baseline uses real TCP fields (T04).
2. ja4lab MTA 2024 corpus → flow-level IOC labels → within-capture contrast (T05–T08).
3. Dataset A rebuilt from its public parts (CTU-13, USTC-TFC2016, Stratosphere normal) with ja4lab,
   so the 99.98% can be reproduced and broken without waiting for anyone's files (T10–T11).

**Tier 2 — the environment-matched and temporal evidence**
4. CTU-SME-11, Windows-VM device subsets first (T14).
5. Stratosphere mixed captures (T15).
6. MTA 2025–2026 with the indicators repo (T16) → temporal protocol P5.
7. Tria.ge public tasks: malware families 2023–2026 + low-score known-software runs (T12).
8. ANY.RUN "No threats detected" tasks of common installers/updaters (T13).

**Tier 3 — false-alarm realism and breadth**
9. CESNET-TLS-Year22 (JA3-level false-alarm rate at ISP scale; check fields first).
10. Benign app/browser sets: Cross-Platform (Android + iOS), CIC DoH-Browsing, CSTNET-TLS 1.3,
    CipherSpectrum, ISCX-VPN non-VPN part.
11. Android: CIC-AndMal2017, Android Mischief (real phones).

## Environment metadata: record this for EVERY capture (`data/meta/capture_meta.csv`)

```
capture_id, source, env_group, vantage, platform, os, os_build, host_kind (bare_metal|vm|emulator|sandbox),
capture_date, year, family, label_basis, victim_ip, sha256, notes
```

`env_group` is "the recording setup": same sandbox image, same lab machine, same network = same group.
When unknown, write `unknown` — never guess. Unknown environment is itself reported.

## Label policy (append-only, three tiers)

- `ioc_verified` — flow's destination matches a published C2 indicator resolved through the capture's
  own DNS; strongest.
- `source_asserted` — the dataset says so (most public datasets; host-level, therefore noisy).
- `sandbox_verdict` — sandbox score/family tag.
- `inferred` — our heuristic (e.g. dominant internal host); reported separately.
- `os_background` — benign OS/browser background flow from a known list; used only in the
  within-capture design, never to relabel a dataset's published labels.

## Safety and legality

- PCAPs only. Never run or extract samples; never use `--export-objects`. PCAP archives from MTA and
  sandboxes may contain malware in HTTP payloads: keep them in `data/raw/` (git-ignored), never open
  them in tools that auto-extract files.
- Respect each source's terms: Triage public cloud tasks are visible to everyone and anything you submit
  becomes public, so do not submit. ANY.RUN's API is paid; manual downloads only.
- Keep `MANIFEST.sha256` for every downloaded batch; sources change.

## Not used (and why)

- HIKARI-2021 and similar: synthetic traffic — fails the "real traffic only" rule.
- CSV-only datasets (CICFlowMeter features without pcaps): no ClientHello, so no JA4.
- MAWI-style backbone traces: payload-truncated (verify), so no ClientHello.
- Censys: scans today's servers; cannot label historical client traffic. Optional appendix only:
  enrich C2 servers with JA4S/JA4X. Research access needs a research plan, intent to publish and an
  academic affiliation; the free tier allows a few searches per month.
