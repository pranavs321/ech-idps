# Research & Novelty Positioning — Verified Against Current Literature

Researched September 2026. This checks your dossier's four gap claims against what
is actually published, names the closest competing work, and tells you exactly
which claims to keep, which to narrow, and which to drop.

**Read the "VERDICT" line under each gap first.** That's the short answer.

---

## 0. Three things in your dossier that are now factually out of date

Fix these before submission — they're the easiest marks to lose.

### 0.1 ECH is no longer a draft. It's an RFC.

Your dossier cites "Rescorla, Oku, Sullivan & Wood — IETF draft-ietf-tls-esni
(RFC-track)". That is stale. <cite index="10-2">In March 2026 the IETF published RFC 9849, standardizing TLS Encrypted Client Hello</cite>. <cite index="5-1">RFC 9848 defines its DNS bootstrapping</cite>.

**Action:** update reference [4] to RFC 9849 (and add RFC 9848). This also
*strengthens* your framing — you're no longer defending against a hypothetical
draft, you're responding to a ratified standard.

### 0.2 Deployment numbers are worth citing — and they cut both ways

<cite index="5-1">Measuring traffic from January to March 2025, Corrata found slightly under 10%</cite> ECH adoption. Meanwhile
<cite index="9-1">in 2026, many browsers enable ECH by default when they detect valid SVCB/HTTPS records and get ECHConfig</cite>.

**Action:** state deployment honestly (still minority, but browser-default and
rising). An examiner asking "is this a real problem yet?" gets a number, not a
vibe. Frame it as *getting ahead of* the visibility cliff.

### 0.3 A citable real-world ECH failure exists now

<cite index="5-1">CVE-2026-42505, published July 8, 2026, sits in Go's crypto/tls: pre-shared key identities leaked into the unencrypted outer ClientHello, letting a passive observer de-anonymize ECH handshakes, the exact outcome ECH exists to prevent. Rated a medium 5.3 on CVSS v3.1 and classed under CWE-201, it was fixed in go1.25.12, go1.26.5, and go1.27.0-rc.2</cite>.

**Action:** one sentence in your intro. It shows you're tracking the ecosystem,
and it supports your "outer ClientHello still leaks things" technical precision
in Section 2.2.

---

## 1. GAP 1 — "No consistency metric between declared identity and observed physics"

### VERDICT: **NARROW IT. Do not claim it outright.** The consistency *idea* is published. Your *setting* is what's new.

### What exists — and this is the one that can sink you in review

The consistency-check idea is well established in the **bot-detection / anti-fraud**
world. A February 2026 arXiv paper on detecting bad bots via TLS fingerprints
states it plainly: <cite index="21-1">Legitimate browsers show internal consistency: the User-Agent string (application, version, OS, device class) normally matches the TLS Client Hello characteristics observed—extension sets, cipher-suite order and protocol version. When a client claims to be "Chrome on iOS" but its TLS handshake reflects a different library or cipher ordering, that inconsistency is a strong sign of impersonation or automation (Husák et al., 2016)</cite>.

So: **"declared identity vs observed evidence" as a detection principle dates to
Husák et al. 2016.** If you claim you invented consistency-checking, a reviewer
who knows this literature will reject the paper.

Commercial anti-bot vendors describe the same layering, including timing:
<cite index="20-1">Detection that works looks at signals the spoofing tools do not touch: TLS handshake characteristics, behavioral patterns (mouse movement trajectory, typing cadence, scroll behavior), timing inconsistencies between claimed browser version and actual rendering engine behavior, and cross-session device signals that persist through fingerprint resets</cite>.

### Why you are still novel — state it exactly this way

The published consistency work compares **User-Agent (an HTTP header) against the
TLS fingerprint**. That comparison requires reading the HTTP layer, which means
you must either *terminate TLS* (CDN, WAF, server-side) or *decrypt*. **Under TLS
1.3 + ECH, a passive network observer cannot do this.** The User-Agent is gone.

Your contribution is the substitution:

| | Prior consistency work | This project |
|---|---|---|
| Declared identity | User-Agent string (HTTP) | JA4 of outer ClientHello |
| Evidence compared against | TLS handshake structure | **Packet timing/size side-channel** |
| Vantage point | Server-side / TLS-terminating | **Passive, in-network, no decryption** |
| Works post-ECH? | **No** — needs HTTP layer | **Yes** — both signals survive ECH |
| Output | Boolean mismatch / heuristic | **Calibrated likelihood ratio D(x) with a stated FPR** |

**Your defensible sentence:** *"Consistency-based impersonation detection is
established (Husák 2016; bot-detection literature), but every published instance
compares a cleartext application-layer claim against the handshake, which
requires a TLS-terminating vantage point. We transpose the principle to a purely
passive, post-ECH setting by replacing the application-layer claim with the
observable outer-ClientHello fingerprint and the corroborating evidence with the
involuntary timing/size side-channel — and we formalise the comparison as a
calibrated likelihood-ratio statistic rather than a heuristic mismatch rule."*

### Also relevant — KL divergence is already in this space

A comprehensive August 2026 review of encrypted-traffic detection under TLS 1.3
and ECH <cite index="4-1">explicitly examines the methodological assumptions and mathematical foundations underlying representative approaches, including Random Forest aggregation, Kullback–Leibler divergence, Discrete Fourier Transform (DFT), and Shannon entropy</cite>.

**Action:** cite this review (Electronics, 2026, doi:10.3390/electronics15173846)
and be explicit that KL divergence is already used in the field. Your novelty is
not "we used KL", it's *what you compute it between* (class-conditional physics
under a declared identity) and *what you derive from it* (the cost bound).

---

## 2. GAP 2 — "No adaptive-adversary evasion-cost analysis"

### VERDICT: **KEEP. This is your strongest claim.** Nothing found contradicts it.

I found no published IDS that inverts website-fingerprinting overhead bounds
(Tamaraw / WTF-PAD / FRONT) into an attacker evasion-cost floor. The WF-defence
literature remains framed as a *defender's privacy cost*, exactly as your
dossier says.

### One adjacent result you should cite, because it's the same spirit

A USENIX Security 2024 result on detecting TLS-in-TLS is referenced as
<cite index="23-1">shown to be detectable with low false-positive rates (Xue et al., USENIX Security 2024) and deployed at ISP scale</cite>.

That's a passive, low-FPR, at-scale detection of an obfuscation technique — the
nearest neighbour to your operating regime. Cite it as evidence that passive
statistical detection at line rate is a real, deployed discipline, not a toy.

### Sharpen the claim to survive a hostile reviewer

Do **not** say "we prove evasion is impossible." Say:

> *The total-variation floor is distribution-free and proven: driving D below τ
> forces the adversary to reshape at least sqrt((D−τ)/2n) of their packets
> (Pinsker). Converting that floor into milliseconds and bytes requires the
> adversary's utility function, which we parameterise explicitly and measure
> empirically via a shaping sweep. The claim is a **priced** evasion, not an
> impossible one.*

This is already written up in `docs/EVASION_COST_THEOREM.md`.

---

## 3. GAP 3 — "Explainability that only talks, never acts"

### VERDICT: **NARROW IT.** Someone got partway there in 2026. Your specific mechanism survives.

### The closest prior art — find it before your reviewer does

A 2026 Frontiers paper proposes "Explainability-as-Intervention (XAI2)". It
<cite index="28-1">explicitly incorporates explanation outputs into predefined operational procedures, allowing explainability to guide threshold calibration, alert refinement, and validation of intrusion alerts</cite>, and describes <cite index="28-1">A structured decision-support workflow is developed that converts explanation outputs generated by SHAP and LIME into predefined operational actions, including threshold calibration and alert refinement, while preserving the underlying machine learning model</cite>. They report <cite index="28-1">The proposed Explainability-as-Intervention (XAI2) framework reduced the observed false-positive rate from 18% to 6%</cite>.

**This partially breaks your Gap 3 claim as written.** Your dossier says the
attribution vector "is never consumed by the mitigation logic." XAI2 consumes it
— for threshold calibration and alert refinement.

### What XAI2 does NOT do, and you do

Read their workflow carefully: <cite index="28-1">Flowchart illustrating a cybersecurity process beginning with a network event, proceeding to AI detection using a random forest model, followed by XAI explanation via LIME or SHAP, analyst validation, and ending with a response decision to mitigate or ignore</cite>.

Three gaps remain, and they're yours:

1. **Their output is binary** — "mitigate or ignore." Yours selects **scope**
   (flow / 5-tuple / source IP), **mechanism** (alert / RST / kernel drop), and
   **TTL** (60s → permanent). A structured action, not a switch.
2. **Theirs has a human in the loop** ("analyst validation"). Yours is inline and
   autonomous, which forces the harder problem of bounding collateral damage
   *by construction*.
3. **Nobody partitions attribution mass by attributability.** Your
   endpoint-intrinsic vs infrastructure-coincidental split — and the rule that
   infra-coincidental evidence can *never* escalate to a source-wide ban
   regardless of model confidence — is not in the literature I found.

**Your revised Gap 3 sentence:** *"Recent work (XAI2, 2026) begins to consume
attribution operationally, but only to calibrate thresholds and refine alerts
under analyst validation, with a binary mitigate/ignore outcome. No published
system partitions attribution mass by whether the evidence is intrinsic to the
endpoint or shared with its network co-tenants, nor uses that partition to
select the scope, mechanism and time-to-live of an autonomous enforcement
action. Consequently no prior system bounds collateral damage by construction."*

That is a narrower claim and it will survive review. The broad version will not.

---

## 4. GAP 4 — "No ECH-era evaluation dataset"

### VERDICT: **KEEP, and it just got stronger.**

Nothing found contradicts this. Independent confirmation that the problem is
real: an IEEE study asked whether ECH breaks traffic classification and found
<cite index="6-1">the performance of the state-of-the-art traffic classification algorithms degrades significantly with the introduction of the ECH. Hence, novel approaches to real-time traffic classification are required</cite>.

That's a citable, peer-reviewed sentence saying *exactly* what your project
claims. Put it in your introduction.

**Action:** this is your most tractable publishable artifact. A real corpus
(uTLS + tc-netem + lab C2, per `docs/DATASET.md`) would be genuinely first.

---

## 5. The competitor you must address: Cisco's Encrypted Visibility Engine

This is commercial state of the art and an examiner may well raise it.

### What EVE does

<cite index="12-1">EVE identifies client applications and processes in TLS and QUIC encrypted traffic by fingerprinting the ClientHello message – without ever decrypting the connection</cite>, with <cite index="12-1">a database of over 10,000 known client process fingerprints, paired with 35 billion connections determining destination context of the encrypted connection</cite>. <cite index="11-1">Through machine learning (ML) technology, Cisco processes over one billion TLS fingerprints and over 10,000 malware samples daily to create and update EVE fingerprints</cite>. It can also <cite index="11-1">leverage the threat score to block malicious encrypted traffic</cite>.

On ECH specifically: <cite index="7-1">Starting with VDB 416 (released October 2025), Cisco introduced the "ECH Servers" Application ID detector. This allows firewalls to identify connections to known ECH-capable CDN providers, giving you visibility into which traffic is likely using ECH obfuscation</cite>.

### Why EVE does not pre-empt you — the two-sentence answer

**One:** EVE is a **fingerprint matcher**. <cite index="16-1">The library fingerprints and analyzes incoming encrypted sessions and matches it against a set of known fingerprints</cite>, and <cite index="19-1">If EVE does not recognize a fingerprint, it identifies client application and estimates the threat score of the first flow using the destination details, such as IP address, port, and server name</cite>. It is **identity-based** — precisely the paradigm uTLS defeats for free. A perfectly cloned Chrome ClientHello matches the *Chrome* fingerprint, and EVE's fallback leans on **destination details**, which is the thing ECH deletes.

**Two:** EVE's ECH handling detects *that traffic is using ECH*, not *what is
inside it*. <cite index="14-1">With ECH, the actual SNI is only transmitted after the HTTPS session has been encrypted</cite> — Cisco's own documentation frames ECH as a visibility loss to be flagged, not solved.

**Your line:** *"The deployed commercial state of the art (Cisco EVE) matches
observed fingerprints against a curated database and falls back to destination
context. Both inputs are exactly what the post-ECH mimicry adversary defeats:
the fingerprint is forged and the destination is encrypted. We do not extend the
fingerprint database — we change the question from 'which process is this?' to
'is this process's behaviour consistent with what it claims to be?'"*

Also worth knowing: Cisco's own ECH guidance to enterprises is largely
*avoidance* — the IETF deployment-considerations draft lists mitigations like
<cite index="8-1">Remove ECH parameters from HTTPS/SVCB records at the resolver, so TLS falls back to a normal, non ECH ClientHello</cite> and <cite index="8-1">Drop HTTPS (type 65) and SVCB (type 64) records so the end-point never receives ECH configuration information</cite>. **That is the industry admitting it has no detection answer — only suppression.** Your project offers detection *with* ECH intact, which is a strong motivating contrast for your introduction.

---

## 6. Your revised novelty statement (use this verbatim)

> Consistency-based impersonation detection exists, but requires a
> TLS-terminating vantage point and dies under ECH. Attribution-consuming XAI
> exists, but only calibrates thresholds under analyst supervision. Commercial
> encrypted-traffic detection exists, but is fingerprint-matching plus
> destination context — both defeated by, respectively, uTLS and ECH.
>
> This work contributes: **(1)** a calibrated likelihood-ratio consistency
> statistic between a forgeable declared cryptographic identity and an
> involuntary physical side-channel, computed passively without decryption and
> functional post-ECH; **(2)** an inversion of website-fingerprinting overhead
> bounds into a provable evasion-cost floor on any adversary suppressing that
> statistic; and **(3)** an enforcement policy in which attribution mass,
> partitioned by endpoint-intrinsic versus infrastructure-coincidental evidence,
> selects mitigation scope, mechanism and time-to-live — bounding collateral
> damage by construction rather than by tuning.

---

## 7. References to ADD to your dossier

```
[15] IETF RFC 9849, "TLS Encrypted Client Hello", March 2026.          [replaces the draft cite]
[16] IETF RFC 9848, "Bootstrapping TLS ECH via DNS", March 2026.
[17] Husák, M. et al. "HTTPS traffic analysis and client identification
     using passive SSL/TLS fingerprinting." 2016.                       [the consistency ancestor]
[18] "When Handshakes Tell the Truth: Detecting Web Bad Bots via TLS
     Fingerprints." arXiv:2602.09606, 2026.                             [closest to Gap 1]
[19] "Explainability-as-Intervention (XAI2)." Frontiers in Computer
     Science, 2026, doi:10.3389/fcomp.2026.1863891.                     [closest to Gap 3]
[20] "Encrypted-Traffic Detection in the TLS 1.3 Era: A Comprehensive
     Review." Electronics, 2026, doi:10.3390/electronics15173846.
[21] "Is Encrypted ClientHello a Challenge for Traffic Classification?"
     IEEE.                                                              [supports Gap 4]
[22] Xue, D. et al. "Detecting TLS-in-TLS." USENIX Security 2024.
[23] Cisco Encrypted Visibility Engine, technical documentation.        [commercial SOTA]
[24] Aneja & Aneja, browser TLS message-sequence dissimilarity, 2024.
[25] CVE-2026-42505 / GO-2026-5856, Go crypto/tls ECH PSK leak, July 2026.
```

---

## 8. Honest bottom line

**Two of your four gaps survive fully** (Gap 2, Gap 4). **Two need narrowing**
(Gap 1, Gap 3) — the *ideas* exist, but not in your setting and not with your
mechanism.

This is a normal, healthy outcome for a literature check, and narrowing is
**good for you**: your dossier already says *"Reviewers reward a narrow,
defensible claim and punish grandiosity."* This document is that principle
applied with actual evidence.

A project that says "here is exactly who got close, here is the specific step
they didn't take, here is why that step matters" reads as mature. A project that
claims four untouched gaps reads as one that didn't search hard enough.
