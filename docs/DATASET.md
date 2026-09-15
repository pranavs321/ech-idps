# The ECH-Era Mimicry Dataset

## Why this exists

Gap 4 in the dossier: **no public dataset** pairs ECH-enabled benign traffic
with fingerprint-spoofed, timing-shaped C2 beacons. CTU-13 predates TLS 1.3;
the CIC corpora contain no ECH and no adaptive mimicry adversary. Until such a
dataset exists, the post-ECH detection problem is literally unmeasurable with
public data. `datasets/generator.py` makes it measurable *now* so the whole
pipeline can be built and evaluated — and whoever publishes the first *real*
such corpus defines the benchmark.

## What the generator produces

Four populations, written through the real Module 2 sensor path so the feature
vectors are computed exactly as they would be on live traffic:

| Population | What it is | Role |
|------------|------------|------|
| `benign_direct` | Human browsing from a dedicated host | Clean baseline |
| `benign_shared` | Human browsing from a NAT/CDN egress | The co-tenant population Pillar 3 protects |
| `malware_naive` | C2 with its own hand-rolled fingerprint, robotic timing | Tier 1 should catch this — it's a control |
| `malware_mimicry` | C2 with a **byte-perfect cloned Chrome JA4** + timing/size shaping | The adversary the project exists for |

Each `malware_mimicry` flow is assigned a **shaping intensity** `s ∈ [0, 1]`
from a sweep. `s = 0` is a raw robotic beacon; `s = 1` is heavily humanised.
The sweep is what makes the evasion-cost curve visible.

## The behavioural models

Benign classes are drawn from per-class parametric models (`HUMAN_MODELS`):

- **Browsers (chrome/firefox/safari):** bursty page loads, human think-time
  pauses, download-heavy, wide size spread.
- **mobile_app:** a *polling* client — sync loops and push keepalives produce
  genuinely periodic, low-jitter, size-uniform traffic with almost no think
  pauses. **This class is modelled deliberately, not incidentally.** Its physics
  overlaps heavily with an unshaped beacon, which is precisely why the system
  needs a *consistency* test rather than a behaviour classifier: regular timing
  is plausible if you declare a mobile SDK, and damning if you declare desktop
  Chrome. It is the class that makes the feature-13 ablation a real experiment.

C2 is drawn from `C2_MODEL`: tight periodicity, narrow size lattice, no think
time, upstream-leaning.

## How the attacker's cost is modelled (this is the important part)

The single most important design choice in the generator: **the attacker's cost
is a measured consequence of the shaping schedule, not a free parameter.**

A naive generator would dial "added latency" and "padding overhead" up alongside
`s`. That would make the evasion-cost curve *circular* — you would be plotting
an assumption. Instead the mimicry generator uses a **task-queue model**
(`_c2_flow`) under two constraints a real implant genuinely faces:

1. **It doesn't control when its cover story wants packets.** Adopting the human
   schedule means emitting packets when the implant has nothing to say. Those
   are pure filler — bytes carrying no C2 payload. That is the padding-overhead
   term, and it is *counted* from the generated packets.
2. **It doesn't control when the operator has work.** A task becomes ready on
   the native beacon tick but can only leave on an upstream packet the cover
   schedule permits. The wait is dwell latency — again, *measured* off the
   schedule.

Plus an **operational deadline** (`DEADLINE_MS`): the implant may not go
arbitrarily long without completing a C2 exchange, because an implant that can't
be tasked for minutes is operationally useless. This deadline is the residual
the attacker cannot shape away for free — it forces a delivery even when the
cover distribution wanted a long pause, which is why detector recall degrades
*gracefully* as `s → 1` instead of cliff-dropping. The attacker's counter-move
is to raise the deadline, and that trade — recall vs dwell time — is exactly
what the theorem prices.

## Honesty caveats — carry these into the review

1. **These are simulated flows, not captures.** They are adequate for exercising
   the pipeline, demonstrating the cost curve's shape, and fixing calibration.
   They are **not** adequate for a headline accuracy number in a paper.
2. **The realism of any single flow is not the point.** The property that makes
   the results meaningful is that the *cost axis is derived from the traffic*,
   not assumed. A detector that stays accurate as `s` rises is being shown to
   force a real, quantified price.
3. **State this before a reviewer does.** "We evaluate on a synthetic corpus
   because no public ECH-era mimicry dataset exists; a real testbed is future
   work" is a position of rigour. Pretending the numbers are production-grade is
   not.

## Replacing the generator with real captures

The path to a publishable dataset, which is itself a citable deliverable:

1. **Benign:** capture real browsing through ECH-enabled resolvers and CDNs
   (Cloudflare fronts ECH today). Multiple browsers, multiple sites, a mobile
   app population.
2. **Malware:** build C2 beacons with **uTLS** or **curl-impersonate** for the
   fingerprint forgery, and shape their timing/sizes with **tc-netem** across
   the same intensity sweep the generator uses. Frameworks like a lab Cobalt
   Strike / Mythic / Sliver in a contained testbed give realistic beacon
   behaviour.
3. **Label and release** with the shaping intensity recorded per flow, so the
   cost curve is reproducible.

The generator's populations, shaping sweep and cost accounting are designed to
mirror what that real corpus would contain, so swapping simulated flows for
captured ones is a drop-in replacement at the `read_pcap` boundary — the rest of
the pipeline does not change.
