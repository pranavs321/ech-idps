# Novelty: what we can claim, what we cannot, and what reviewers will cite against us

## Verdict
Each ingredient of "host-relative features + host-level detection" has prior work. The defensible contribution is
the **specific design and its measurement**:
1. *Stack-conditioned host-relative features*: each TLS connection's post-handshake behaviour standardised against
   the same host's other connections that share its JA4, within one capture. Motivated by our natural-mimicry
   finding (malware shares the host's TLS stack, so its stack peers are a natural control group).
2. A measured invariance claim: host-constant nuisances (MSS, TTL, VPN egress, latency, padding) cancel by
   construction; we test it with ELI, source identifiability and a nuisance-injection stress test.
3. The evaluation design: leave-one-source-out and leave-one-year-out on same-host captures, with
   domain-generalisation baselines, SCBD-R's per-stack conformal design, and environment-matched negative bags.
4. Negative results reported as findings: sandbox-to-real collapse; per-JA4 conformal thresholds help on simulated
   but hurt on real mimicry; a label-free host x JA4 outlier score fails because malware connections are the
   *majority, self-similar* members of their own stack in an infected capture.

## Safe wording
- "We introduce stack-conditioned host-relative features, which describe each TLS connection's post-handshake
  behaviour relative to the same host's other connections that share its client TLS stack (JA4) within a capture."
- "By construction this removes effects that are constant within a host and capture; empirically it lowers
  source identifiability from X to Y and survives host-level nuisance injection (AUC drop X vs Y)."
- "To our knowledge, this is the first evaluation of within-host, JA4-stratified relative features for
  encrypted-malware detection under leave-one-source-out shift on same-host captures."
- "Our design builds on within-bag invariant representations [Bartoš et al. 2016], host baselining
  [McDaniel et al. 2006; Yen et al. 2013], beacon detection [Tegeler et al. 2012; Hu et al. 2016] and host-level
  multiple-instance learning [Pevný & Somol 2016; Prasse et al. 2019]."

## Never write
"first host-relative detection", "first MIL for encrypted traffic", "environment-invariant",
"eliminates leakage", "robust to adaptive attackers".

## Closest prior work (must cite and differentiate)
| Work | Overlap | Our difference |
|---|---|---|
| Bartoš, Sofka, Franc, *Optimized Invariant Representation of Network Traffic for Detecting Unseen Malware Variants*, USENIX Security 2016 | Per-bag normalisation for invariance to environment shift | Their bag = flows from one user to one hostname (HTTP proxy logs); ours = the host's other connections sharing its JA4, across destinations; we measure leakage (ELI) and test cross-source |
| Pevný & Somol, *Discriminative Models for Multi-instance Problems with Tree Structure*, AISec 2016; Prasse et al., Machine Learning 2019 | Host-as-bag detection from all traffic | TLS/JA4 features on public multi-source data; environment-matched negative bags |
| Grill & Rehák, WIFS 2014 | Host-relative User-Agent discrepancy | Our same-host data shows the TLS analogue (JA4 discrepancy) fails: 89.5% natural mimicry |
| Anderson & McGrew AISec 2016, IMC 2019, arXiv 2020 | TLS + contextual flows from the same host; SChannel sharing | Absolute features, no cross-source test |
| BotFinder (CoNEXT 2012), BAYWATCH (DSN 2016), Beehive (ACSAC 2013), Oprea et al. (DSN 2015), MADE (ACSAC 2018), EarlyCrow (ISC 2022) | Beaconing, destination rarity, host profiles | We keep destination context (HRd) separate because IOC labels make malicious destinations rare by construction |
| Rosetta (USENIX Security 2023), DI-NIDS (KBS 2023), SEROA (arXiv 2611.07550) | Environment-shift robustness for traffic classifiers | Feature-side, not loss-side; needs no training on the target environment |

## Objections to pre-empt (and where we answer them)
1. Contaminated baseline: infected captures are malware-dominated, so the host baseline is partly malicious -> median/MAD statistics, minimum peer count, fallback host x JA4 -> host; we show the label-free outlier score fails for exactly this reason.
2. Capture-position shortcut: infections start early in MTA captures -> position features (POS) are an audit family, never in a proposed model; we report POS alone.
3. Label provenance: IOC labels make malicious destinations rare -> destination context (HRd) and certificate features (SRV; SSLBL labels are certificate hashes) are reported separately from relative behaviour (HRb).
4. Per-domain scaling can hide separability (Rayamajhi 2026) -> absolute, relative and absolute+relative are always shown side by side.
5. MIL needs negative bags -> environment-matched negative bags (same host minus its labelled malicious connections).

## Baselines to add on the Mac (CPU is enough)
ERM (done), per-source standardisation (done: `TLS+BEHsrc`), dropping source-predictive features, MLP-based DANN
(Ganin et al. JMLR 2016), GroupDRO (Sagawa et al. ICLR 2020; groups = source x label), V-REx, JTT; DomainBed-style
model selection (Gulrajani & Lopez-Paz ICLR 2021). Report worst-source as well as mean.

## New papers since the 8-11 Nov sweep (add to the related work)
- Huang & Yang, *SoK: Where Do Flow Labels Come From?*, arXiv 2609.02140 (label-provenance ceilings 0.56-0.76)
- Guan et al., *When Handshakes Go Dark (FLARE)*, arXiv 2611.12442 (TLS 1.3 / QUIC / ECH)
- Liu et al., *SEROA*, arXiv 2611.07550; Liu et al., arXiv 2611.07452 (pre-trained models vs shallow under leakage control)
- Wu et al., *obfsgen*, arXiv 2611.15019; Wu, Divakaran, Gurusamy, *NetGuise*, arXiv 2610.27456 (adaptive shaping)
- Tantaroudas et al., Preprints 202610.1120 (one TCP window field gives AUC 0.985 on CIC-IDS2017: same shortcut as MSS 1357)
- Rayamajhi, Preprints 202610.1041 (target-only control; per-domain scaling objection)
- Sohail, arXiv 2609.19091 (AI-agent polling looks like beaconing)
- Luo et al., *C2Detector*, Computer Networks 2026, doi 10.1016/j.comnet.2026.111992
- Mücke et al., *Discovering ECH Deployments*, IMC 2026, doi 10.1145/3777912.3839832
- Rossow et al., *Prudent Practices*, S&P 2012; Lever et al., *A Lustrum of Malware Network Communication*, S&P 2017 (sandbox effects)
- Possible duplicate to check: "Wang IWQoS 2026" may be the same work as BiasSeeker, arXiv 2601.10180.
