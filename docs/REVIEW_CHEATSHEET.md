# Review Cheatsheet

One page. The questions an examiner is likely to ask, and honest answers you
can give without scrambling. Read this the morning of your review.

---

**Q: Explain your project in two sentences.**
A: TLS 1.3 and ECH hide everything useful about encrypted traffic, and the one
signal that's left — the TLS fingerprint — attackers forge for free, so their
malware's handshake looks exactly like Chrome. My system ignores *what the
connection claims to be* and instead tests whether its packet timing and sizes
are physically *possible* for that claim, catching disguised malware without
decrypting anything.

---

**Q: What's actually novel here? Isn't this just ML on flow features?**
A: Three things, and only these three. (1) A single calibrated statistic `D(x)`
that scores the *disagreement* between declared crypto identity and observed
physics — not "is this malware" but "is this behaviour possible for what it
claims to be." (2) An evasion-cost bound: I prove the attacker must pay a
minimum price in latency and bandwidth to fool the consistency test. (3) The
explainability vector *drives* the enforcement decision instead of just being a
report. The individual ML components — XGBoost, Isolation Forest, XDP, SHAP —
are all off-the-shelf, and I say so explicitly. The novelty is in the coupling.

---

**Q: `D(x)` alone only gets AUC ~0.75. Isn't Pillar 1 weak?**
A: On its own, yes — and that's the thesis, not a bug. A cloned fingerprint
means feature 13 is near-identical for benign Chrome and mimicry Chrome, so no
single feature separates them. `D(x)`'s value is that it makes the
*class-conditional* physics boundary explicit: "this timing is fine for a mobile
app but impossible for Chrome." The full detector reaches ~0.91 recall at 0.5%
FPR. The demo shows `D(x)` hitting 50–400 nats against a threshold of 5 on
actual mimicry beacons — that's where it earns its place.

---

**Q: Your dataset is fake. Why should I believe any of this?**
A: It's simulated, and I'm upfront about that — no public ECH-era mimicry
dataset exists, which is itself Gap 4 in my analysis. What makes the results
meaningful isn't the realism of any single flow, it's that the attacker's cost
is *measured off the generated traffic*, not assumed. The cost curve would be
circular if I dialled cost up by hand; instead it falls out of a task-queue
model with real delay-and-pad-only constraints. The path to real captures
(uTLS + tc-netem + a lab C2 framework) is documented, and it's a drop-in
replacement at the PCAP boundary.

---

**Q: Can't a patient attacker just evade it?**
A: Yes, and I don't claim otherwise. The theorem prices evasion; it doesn't make
it impossible. A low-and-slow implant with a huge latency budget can shape under
threshold. My claim is *cost*, not *impossibility* — and for a channel whose
entire purpose is stealth, an order-of-magnitude bandwidth increase is a real
deterrent even if it's not a wall.

---

**Q: Show me the evasion-cost theorem. Is it actually proven?**
A: The total-variation floor is proven and distribution-free: via Pinsker,
driving `D` below `τ` forces the attacker to reshape at least
`sqrt((D−τ)/2n)` of their packets. What's *empirical* is converting that floor
into milliseconds and bytes, because that depends on the attacker's utility
function. So: the floor is a theorem, its dollar-value is measured, and the two
together are the useful result. I don't overclaim it as a closed-form
impossibility. (Full statement: `docs/EVASION_COST_THEOREM.md`.)

---

**Q: Why does Pillar 3 (attribution-driven enforcement) matter? Isn't checking
IP reputation before blocking standard?**
A: Checking reputation is standard. What's new is that the *feature-attribution
vector* decides the response. If the model condemned a flow mainly on the
attacker's own beacon rhythm (endpoint-intrinsic evidence), I ban the source. If
it condemned it on features a thousand users behind the same NAT share
(infrastructure-coincidental), banning the source would punish bystanders — so I
only cut that one connection, briefly. In the evaluation this took innocent-flow
disruption on shared infrastructure to *zero* versus hundreds under naive
blocking, by vetoing ~90% of would-be escalations. The key insight: model
*confidence* and *attributability* are different quantities, and conflating them
is how automated response takes down a university's Wi-Fi at 3am.

---

**Q: Your XDP program claims nanosecond drops. Did you measure that?**
A: The nanosecond figure is the native-XDP cost from the literature for a hash
lookup + drop. I run a portable Python twin for the evaluation so it's
reproducible without root, and the real C program is in `xdp_filter.c`. If I
were quoting a measured latency I'd first check `ip link show` reports `xdp`
(native) not `xdpgeneric`, because virtualised NICs silently fall back to
generic mode which is ~10x slower. I flag that explicitly rather than quoting a
generic-mode number as native.

---

**Q: What would you do with more time?**
A: Three things, in order: (1) build the real ECH testbed to replace the
synthetic corpus and get a defensible headline accuracy number; (2) formalise
the latency/bandwidth constants in the evasion-cost bound for named cover
classes; (3) wire the Tier-3 novelty verdicts into an active-learning loop so
today's anomalies become tomorrow's labelled training data. The first is the one
that turns this from a strong prototype into a Q1 submission.

---

**Q: What's the single most important limitation?**
A: The synthetic dataset. Everything else is either honestly scoped or fixable
with engineering. The dataset is the one thing standing between this and a
publishable accuracy claim, and it's why the whole architecture is built so the
real corpus drops in without touching the pipeline.

---

**If you get a question you can't answer:** say "I haven't measured that
directly, but here's how I'd approach it" and reason out loud. That reads far
better than bluffing a number. Examiners reward knowing the edges of your own
work.
