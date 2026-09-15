# The Evasion-Cost Bound (Pillar 2)

This is the strongest and most defensible novelty in the project, and also the
one most likely to be probed in review. This document states it carefully,
sketches the proof, and — crucially — is honest about what is proven versus
what is empirical.

## Informal statement

An attacker whose malware speaks a native command-and-control (C2) rhythm
cannot make that rhythm look human *for free*. Every unit of statistical
indistinguishability they buy costs them a measurable amount of the thing they
are trying to protect: beacon latency (how quickly the operator can task the
implant) and padding bandwidth (how much inconspicuous cover traffic they must
generate). Below a certain point, hiding the physics costs more than the C2
channel is worth.

## Setup and notation

- Let `H` be the distribution over per-packet observations (inter-arrival gap,
  size, direction) of **genuine human browsing** for the declared class `c`.
- Let `M` be the attacker's **native C2 distribution** — regular, low-jitter,
  size-uniform.
- The detector computes `D(x)`, the log-likelihood ratio of the observed
  physics under the best-fit class versus the declared class (see
  `dissonance.py`). For a beacon declaring Chrome, `D(x)` is large because the
  physics fits a machine far better than it fits Chrome.
- The detector fires when `D(x) > τ`, where `τ` is calibrated to a chosen
  false-positive rate on benign traffic.

For a flow of `n` observations, `D(x)` is a sample estimate of

```
    n · D_KL(M ‖ H)
```

the Kullback–Leibler divergence between the attacker's distribution and the
human distribution, scaled by the number of observations the detector sees.

## Theorem (target form)

> To drive `D(x) ≤ τ`, an adversary shaping a native distribution `M` toward
> the human distribution `H` must produce a shaped distribution `M′` with
> `D_KL(M′ ‖ H) ≤ τ/n`. Any implementation of that shaping by **delaying** and
> **padding** real C2 traffic incurs expected added latency and padding
> overhead lower-bounded by a function of `D_KL(M ‖ H)` and the attacker's
> required C2 responsiveness.

## Proof sketch

**Step 1 — the divergence floor.** The detector fires above `τ`, and `D(x)`
estimates `n · D_KL(M ‖ H)`. To evade, the adversary must move to a distribution
`M′` close enough to `H` that `n · D_KL(M′ ‖ H) ≤ τ`, i.e.
`D_KL(M′ ‖ H) ≤ τ/n`. This is the target the shaping must hit.

**Step 2 — divergence to total variation (Pinsker).** Pinsker's inequality
gives, for any two distributions,

```
    TV(P, Q) ≤ sqrt( D_KL(P ‖ Q) / 2 )
```

Turned around, moving from `M` (divergence `D_KL(M‖H)` from human) to any `M′`
with divergence `≤ τ/n` requires shifting probability mass by at least

```
    TV(M, M′) ≥ TV(M, H) − TV(M′, H)
             ≥ sqrt( D_KL(M‖H) / 2 ) − sqrt( (τ/n) / 2 )      (approx.)
```

That `TV(M, M′)` is a **lower bound on the fraction of packets whose timing or
size the adversary must alter**. This part is distribution-free and is exactly
what `evasion_cost_lower_bound()` returns:

```python
tv_floor = sqrt( max(0, D_observed − τ) / (2n) )
```

**Step 3 — from packets-altered to operational cost.** Shaping is not free
motion in distribution space; the adversary can only *delay* packets (never
send them earlier) and *pad* them (never shrink real payload). This asymmetry
is the crux, and it is why the direction of the inequality holds:

- **Latency.** To insert human-scale think-time gaps, the implant must hold
  outbound C2 data during those gaps. The expected added dwell time before the
  operator can act is bounded below by the mass of `H` sitting at longer gaps
  than `M` natively uses.
- **Padding.** To match human size structure — which has high entropy across a
  wide lattice — a beacon emitting near-constant records must append filler
  bytes. Those bytes carry no C2 payload by construction, so the bandwidth
  overhead is bounded below by the entropy gap between `M`'s size distribution
  and `H`'s.

The precise constants depend on the attacker's utility function (their latency
budget `L` and bandwidth budget `B`), which is why the theorem is stated
*parametrically* in those budgets rather than as a single universal number.

## What is proven vs what is empirical — be precise about this

**Proven, distribution-free:** the total-variation floor in Step 2. Given a
detector firing at `τ` and an observed `D`, the fraction of packets the attacker
must reshape has a hard lower bound. No modelling assumptions.

**Empirical, and honestly labelled as such:** the *conversion* of that floor
into milliseconds and bytes. That conversion depends on the attacker's utility
function and on the specific cover class. This is why the evaluation includes a
**shaping sweep** (`scripts/03_evaluate.py`, Result B): it plots detector recall
against the attacker's *measured* cost across shaping intensities, so the cost
curve is read off generated traffic rather than asserted.

If an examiner presses on "is this actually a theorem or just a curve", the
honest answer is: **the total-variation floor is a theorem; the dollar value of
that floor in latency and bandwidth is measured, and the two together are what
make the claim useful.** Claiming more than that is the mistake to avoid.

## The empirical finding worth highlighting

The sweep reveals which cost binds, and it is not the one you might expect. For
a **browser** cover story, the dominant penalty is **bandwidth, not latency**.
Dense, bursty, human-like traffic actually gives the implant *more* sending
opportunities, so task latency can *fall* while filler-byte volume explodes by
an order of magnitude. The theorem bounds a *sum* of costs; which term dominates
depends on the cover class the attacker picks. That is a genuine, publishable
observation and it emerged from the implementation, not from the premise.

## The intellectual move, in one line

The website-fingerprinting community spent a decade proving overhead bounds for
traffic shaping (Tamaraw, WTF-PAD, FRONT) — always as a **defender's privacy
cost**. This project **inverts** those bounds into an **attacker's evasion
cost**. Same mathematics, opposite sign, and to our knowledge no published IDS
carries a theorem of this shape. That inversion is the single strongest lever
for a Q1 venue.
