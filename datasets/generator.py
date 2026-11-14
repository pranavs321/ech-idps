"""
The ECH-era mimicry corpus generator.

Section 4, Gap 4 of the dossier: no public dataset pairs ECH-enabled benign
traffic with JA4-spoofed, timing-shaped C2. Until captures from a real testbed
land, the system is unmeasurable. This module makes it measurable now, by
generating flows from explicit behavioural models.

Be honest about what this is, in the report and in the viva: these are
*simulated* flows drawn from parametric distributions, not captures. They are
adequate for (a) exercising the full pipeline end to end, (b) demonstrating the
shape of the evasion-cost curve, and (c) fixing the threshold calibration
procedure. They are not adequate for a headline accuracy claim in a paper --
that needs the real testbed described in docs/DATASET.md. State this before a
reviewer states it for you; it converts a weakness into evidence of rigour.

What the generator gets right, and why the curve is meaningful
-------------------------------------------------------------
The key property is not realism of any single flow, it is that the *attacker's
cost is modelled as a coupled consequence of evasion*, not as a free parameter.
When shaping intensity s rises:

  - injected delay is drawn and ADDED to the beacon's inter-arrival gaps, so
    the beacon's own latency rises. We record that latency, we do not invent it.
  - pad bytes are appended to reach a randomised target size, so overhead rises
    and we record actual bytes sent versus bytes of payload.

So the cost axis of the evasion-cost curve is measured from the generated
traffic itself. A detector that stays accurate as s rises is being shown to
force a real, quantified price.

Populations produced
--------------------
  benign_direct        browsing from a dedicated client IP
  benign_shared        browsing from a NAT/CDN egress -- the co-tenant
                       population that Pillar 3 protects
  malware_naive        C2 with its own odd fingerprint and robotic timing
                       (Tier 1 should take this)
  malware_mimicry      C2 with a byte-perfect cloned Chrome JA4 and shaping
                       intensity s -- the adversary the project exists for
"""

from __future__ import annotations

import ipaddress
import math
import random
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

import numpy as np

from idps.features import SPLT_PACKETS
from idps.ja4 import BROWSER_PROFILES, synth_client_hello
from idps.module2_sensor.flow import Flow, Packet

# ---------------------------------------------------------------------------
# Address pools. Shared ranges are what Module 5 must treat carefully.
# ---------------------------------------------------------------------------
DEDICATED_POOL = "198.51.100.0/24"     # TEST-NET-2, dedicated hosts
SHARED_POOL = "203.0.113.0/24"         # TEST-NET-3, stands in for NAT/CDN
ATTACKER_POOL = "192.0.2.0/24"         # TEST-NET-1, attacker VPS
C2_SERVER_POOL = "100.64.0.0/24"


def _pool(cidr: str) -> List[str]:
    return [str(ip) for ip in ipaddress.ip_network(cidr).hosts()]


# ---------------------------------------------------------------------------
# Behavioural models
# ---------------------------------------------------------------------------
@dataclass
class BehaviourModel:
    """
    A parametric model of a class's physics. One per declared class, which is
    exactly what the dissonance statistic conditions on.
    """
    name: str
    # think-time: probability a gap is a human pause, and its scale (ms)
    think_prob: float
    think_scale: float
    # intra-burst gaps, lognormal in ms
    burst_gap_mu: float
    burst_gap_sigma: float
    # request/response sizes
    up_size_mu: float
    up_size_sigma: float
    down_size_mu: float
    down_size_sigma: float
    # probability the next packet is upstream
    up_prob: float
    periodic: bool = False          # fixed callback interval?
    period_ms: float = 0.0
    jitter_frac: float = 0.0        # native jitter as fraction of period


HUMAN_MODELS: Dict[str, BehaviourModel] = {
    # Desktop browsing: bursty page loads punctuated by reading pauses, mostly
    # downstream, wide size spread.
    "chrome": BehaviourModel(
        "chrome", think_prob=0.22, think_scale=900.0,
        burst_gap_mu=2.4, burst_gap_sigma=1.05,
        up_size_mu=5.9, up_size_sigma=0.75,
        down_size_mu=7.0, down_size_sigma=1.15,
        up_prob=0.34),
    "firefox": BehaviourModel(
        "firefox", think_prob=0.25, think_scale=1000.0,
        burst_gap_mu=2.5, burst_gap_sigma=1.10,
        up_size_mu=5.95, up_size_sigma=0.72,
        down_size_mu=6.95, down_size_sigma=1.20,
        up_prob=0.33),
    "safari": BehaviourModel(
        "safari", think_prob=0.20, think_scale=850.0,
        burst_gap_mu=2.35, burst_gap_sigma=1.00,
        up_size_mu=5.85, up_size_sigma=0.70,
        down_size_mu=7.05, down_size_sigma=1.10,
        up_prob=0.35),
    # Native app traffic: a polling client. Sync loops, push-notification
    # keepalives and telemetry produce genuinely periodic, low-jitter,
    # size-uniform traffic with almost no think pauses.
    #
    # This class is the reason the whole project needs a *consistency* test
    # rather than a behaviour classifier, so it is modelled deliberately, not
    # incidentally. Its physics overlaps heavily with an unshaped C2 beacon:
    # both are regular, both are small, neither pauses to read anything. A
    # detector that only looks at f1-f12 therefore faces a forced choice --
    # flag every benign polling app, or miss every beacon. Neither is
    # acceptable.
    #
    # The declared identity is what breaks the tie. Regular timing is entirely
    # plausible *if the connection declares a mobile SDK stack*, and deeply
    # implausible if it declares desktop Chrome. That is precisely what D(x)
    # measures, and it is why the f13 ablation in scripts/03_evaluate.py is a
    # meaningful experiment rather than a formality.
    "mobile_app": BehaviourModel(
        "mobile_app", think_prob=0.04, think_scale=2500.0,
        burst_gap_mu=6.6, burst_gap_sigma=0.35,
        up_size_mu=5.6, up_size_sigma=0.30,
        down_size_mu=5.9, down_size_sigma=0.40,
        up_prob=0.48,
        periodic=True, period_ms=760.0, jitter_frac=0.22),
}

# Native C2: a sleep-loop beacon. Tight periodicity, narrow size lattice,
# upstream-leaning, no think time.
# The operator's tasking deadline: the longest the implant may go without
# completing a C2 exchange. A real constraint -- an implant that cannot be
# tasked for minutes at a time is operationally useless for hands-on-keyboard
# work. Raising it is the attacker's main counter to timing-consistency
# detection, and it is paid for in dwell time.
DEADLINE_MS = 4000.0

C2_MODEL = BehaviourModel(
    "c2", think_prob=0.0, think_scale=0.0,
    burst_gap_mu=0.0, burst_gap_sigma=0.0,
    up_size_mu=5.2, up_size_sigma=0.18,
    down_size_mu=5.6, down_size_sigma=0.22,
    up_prob=0.52,
    periodic=True, period_ms=1500.0, jitter_frac=0.03)


def custom_c2_hello() -> bytes:
    """
    A ClientHello no browser would ever emit: a minimal cipher list in library
    order, no ALPN, no GREASE, none of the browser padding/session extensions.
    Registered temporarily into the profile table so the existing wire builder
    can serialise it, then removed -- it is traffic, not a reference profile.
    """
    BROWSER_PROFILES["_c2_custom"] = {
        "ciphers": [0xC030, 0xC02F, 0xC02C, 0xC02B, 0x009F, 0x009E, 0x1302,
                    0x1301],
        "extensions": [0x000A, 0x000B, 0x000D, 0x0017, 0x002B, 0x0033],
        "alpn": "",
    }
    try:
        return synth_client_hello("_c2_custom", ech=True, sni=False)
    finally:
        BROWSER_PROFILES.pop("_c2_custom", None)


@dataclass
class GeneratedFlow:
    flow: Flow
    label: int                       # 0 benign, 1 malicious
    population: str
    declared_truth: str
    shaping: float = 0.0             # s in [0, 1]
    phi: float = 0.0                 # volume-matching fraction
    added_latency_ms: float = 0.0    # measured, not assumed
    padding_overhead: float = 0.0    # measured, not assumed


# ---------------------------------------------------------------------------
# Flow synthesis
# ---------------------------------------------------------------------------
def _human_flow(rng: random.Random, model: BehaviourModel,
                n: int) -> Tuple[List[float], List[int], List[bool]]:
    """
    Draw a benign flow. Classes flagged `periodic` (the polling apps) get a
    fixed-interval schedule with proportional jitter rather than the bursty
    lognormal gaps of a browser, because that is what a sync loop actually
    emits -- and reproducing it faithfully is what makes the benign population
    genuinely hard rather than conveniently separable.
    """
    gaps, sizes, dirs = [], [], []
    for i in range(n):
        forward = rng.random() < model.up_prob
        mu = model.up_size_mu if forward else model.down_size_mu
        sg = model.up_size_sigma if forward else model.down_size_sigma
        size = int(min(1460, max(32, rng.lognormvariate(mu, sg))))
        sizes.append(size)
        dirs.append(forward)
        if i == 0:
            gaps.append(0.0)
            continue
        if rng.random() < model.think_prob:
            gaps.append(rng.expovariate(1.0 / model.think_scale))
        elif model.periodic:
            gaps.append(max(1.0, model.period_ms * (
                1.0 + rng.uniform(-model.jitter_frac, model.jitter_frac))))
        else:
            gaps.append(rng.lognormvariate(model.burst_gap_mu,
                                           model.burst_gap_sigma))
    return gaps, sizes, dirs


def _c2_flow(rng: random.Random, n: int,
             shaping: float, phi: float, target: BehaviourModel
             ) -> Tuple[List[float], List[int], List[bool], float, float]:
    """
    Generate a beacon shaped toward `target` with intensity s, under a task
    queue model, and measure what the shaping costs the operator.

    The model, and why it is built this way
    ---------------------------------------
    A naive implementation would treat "added latency" and "padding overhead"
    as free parameters that we dial up alongside s. That would make the
    evasion-cost curve circular -- we would be plotting an assumption. So the
    costs here are *consequences* of the schedule, derived from two constraints
    a real mimicry implant genuinely faces:

      1. It does not control when its cover story wants packets. Adopting the
         human schedule means emitting packets at moments when the implant has
         nothing to say. Those packets are pure filler: bytes on the wire
         carrying no C2 payload. That is the padding-overhead term.

      2. It does not control when its operator has work. A task becomes ready
         on the native beacon tick, but can only leave on an upstream packet
         that the cover schedule permits. The wait between those two moments is
         the latency term -- dwell time before the operator can act.

    Both are then *measured off the generated schedule*, not asserted. So when
    the evaluation harness plots recall against cost, the cost axis is read out
    of the traffic, which is what makes the curve the empirical face of the
    evasion-cost theorem rather than a restatement of its premise.
    """
    s = max(0.0, min(1.0, shaping))
    gaps: List[float] = []
    sizes: List[int] = []
    dirs: List[bool] = []

    useful_bytes = 0
    wire_bytes = 0
    latencies: List[float] = []

    period = C2_MODEL.period_ms
    t = 0.0                       # clock along the shaped schedule, ms
    next_task_ready = 0.0         # native tick at which work becomes available
    pending = False               # is a task waiting to go out?
    last_delivery = 0.0

    for i in range(n):
        # ---- when does the shaped schedule want this packet? --------------
        if i == 0:
            gap = 0.0
        else:
            native = period * (1.0 + rng.uniform(-C2_MODEL.jitter_frac,
                                                 C2_MODEL.jitter_frac))
            if rng.random() < target.think_prob:
                human = rng.expovariate(1.0 / target.think_scale)
            else:
                human = rng.lognormvariate(target.burst_gap_mu,
                                           target.burst_gap_sigma)
            gap = (1.0 - s) * native + s * human

            # ---- the operational deadline -----------------------------
            # The cover distribution occasionally asks for a long pause. An
            # implant with a tasking deadline cannot always grant it: past
            # `deadline_ms` without delivering, it must transmit whatever the
            # cover story wanted.
            #
            # This is the residual the adversary cannot shape away for free,
            # and it is why recall does not simply fall off a cliff at s=1.
            # Perfect mimicry would require surrendering the deadline
            # entirely, which means unbounded dwell time before the operator
            # can act -- the latency term of the evasion-cost theorem,
            # showing up as a constraint rather than as an assumption. The
            # attacker's counter-move is to raise DEADLINE_MS; the curve in
            # scripts/03_evaluate.py is what that trade looks like.
            if pending and (t + gap - last_delivery) > DEADLINE_MS:
                gap = max(1.0, DEADLINE_MS - (t - last_delivery))
        gaps.append(gap)
        t += gap

        if t >= next_task_ready:
            pending = True

        # ---- direction: the cover story is download-heavy, C2 is not ------
        up_prob = (1.0 - s) * C2_MODEL.up_prob + s * target.up_prob
        forward = rng.random() < up_prob
        dirs.append(forward)

        # ---- does this packet carry real work, or is it filler? -----------
        carries_work = forward and pending
        want = int(min(1460, max(32, rng.lognormvariate(
            C2_MODEL.up_size_mu if forward else C2_MODEL.down_size_mu,
            C2_MODEL.up_size_sigma if forward else C2_MODEL.down_size_sigma))))

        if carries_work:
            useful_bytes += want
            latencies.append(max(0.0, t - next_task_ready))
            pending = False
            last_delivery = t
            next_task_ready = t + period
        # filler packets contribute nothing to useful_bytes by construction

        # ---- size: pad toward the cover distribution ----------------------
        if phi > 0:
            mu = target.up_size_mu if forward else target.down_size_mu
            sg = target.up_size_sigma if forward else target.down_size_sigma
            desired = int(min(1460, max(32, rng.lognormvariate(mu, sg))))
            size = int(want + phi * max(0, desired - want))
            size = min(1460, size + int(rng.random() * phi * 64))
        else:
            size = want
        wire_bytes += size
        sizes.append(size)

    # A flow that never delivered real work has infinite nominal overhead and
    # undefined latency. Both are meaningless as reported numbers, so charge a
    # single nominal message as the denominator and the whole observed window
    # as the latency. That keeps the per-flow statistics bounded, which matters
    # because the evaluation aggregates them -- one unbounded flow would
    # otherwise dominate the mean for its entire shaping level and turn the
    # cost curve into noise. (This is why scripts/03_evaluate.py reports the
    # median rather than the mean as well.)
    if not latencies:
        latencies = [sum(gaps)]
    nominal = int(math.exp(C2_MODEL.up_size_mu))
    denom = max(useful_bytes, nominal)
    overhead = (wire_bytes - useful_bytes) / denom
    mean_latency = float(np.mean(latencies))
    return gaps, sizes, dirs, mean_latency, max(0.0, overhead)


def _assemble(rng: random.Random, src: str, dst: str, dport: int,
              gaps: List[float], sizes: List[int], dirs: List[bool],
              hello: bytes, t0: float) -> Flow:
    from idps.module2_sensor.flow import canonical_key

    sport = rng.randint(32768, 60999)
    key, _ = canonical_key(src, sport, dst, dport)
    flow = Flow(key=key, start_ts=t0, last_ts=t0, initiator=(src, sport),
                initiator_certain=True)
    t = t0
    for i, (gap, size, forward) in enumerate(zip(gaps, sizes, dirs)):
        t += gap / 1000.0
        payload = hello if i == 0 else b""
        pkt_size = len(hello) if i == 0 else size
        flow.add(Packet(ts=t, size=pkt_size,
                        forward=True if i == 0 else forward,
                        payload=payload))
    return flow


def generate(n_benign: int = 6000, n_malware_naive: int = 800,
             n_malware_mimicry: int = 2400,
             phi_levels: Optional[List[float]] = None,
             shared_fraction: float = 0.35,
             seed: int = 1337) -> List[GeneratedFlow]:
    """
    Produce the corpus. `phi_levels` is the sweep: each mimicry flow is
    assigned one level of volume-matching, so the evaluation harness can plot
    recall against the attacker's measured cost at that level.
    """
    if phi_levels is None:
        phi_levels = [0.0, 0.15, 0.3, 0.45, 0.6, 0.75, 0.9, 0.95, 1.0]

    rng = random.Random(seed)
    dedicated, shared = _pool(DEDICATED_POOL), _pool(SHARED_POOL)
    attackers, c2 = _pool(ATTACKER_POOL), _pool(C2_SERVER_POOL)

    # Pre-build the ClientHello bytes once per profile. The mimicry population
    # reuses the *chrome* bytes verbatim: that is what uTLS does, and it is
    # why feature 13 alone can never separate them.
    hellos = {name: synth_client_hello(name, ech=True, sni=False)
              for name in BROWSER_PROFILES}

    out: List[GeneratedFlow] = []
    t0 = 1_760_000_000.0

    # --- benign -----------------------------------------------------------
    class_names = list(HUMAN_MODELS.keys())
    weights = [0.46, 0.18, 0.14, 0.22]      # rough desktop/mobile population mix
    for i in range(n_benign):
        cls = rng.choices(class_names, weights=weights)[0]
        model = HUMAN_MODELS[cls]
        n = rng.randint(8, SPLT_PACKETS)
        gaps, sizes, dirs = _human_flow(rng, model, n)
        is_shared = rng.random() < shared_fraction
        src = rng.choice(shared if is_shared else dedicated)
        flow = _assemble(rng, src, f"93.184.{rng.randint(0,255)}.{rng.randint(1,254)}",
                         443, gaps, sizes, dirs, hellos[cls],
                         t0 + i * 0.37)
        flow.truth = {"label": 0, "class": cls}
        out.append(GeneratedFlow(
            flow=flow, label=0,
            population="benign_shared" if is_shared else "benign_direct",
            declared_truth=cls))

    # --- naive malware: own fingerprint, no shaping ------------------------
    # A hand-rolled Go/OpenSSL-style stack: short cipher list in the library's
    # own preference order, no ALPN, none of the browser-specific extensions.
    # Structurally unlike any browser profile, so feature 13 collapses and
    # Tier 1 takes it on the JA4 hash alone. This is the adversary that
    # existing fingerprint blocklists already handle -- it is in the corpus as
    # a control, to show what the harder population costs.
    naive_hello = custom_c2_hello()
    for i in range(n_malware_naive):
        n = rng.randint(8, SPLT_PACKETS)
        gaps, sizes, dirs, _, _ = _c2_flow(rng, n, 0.0, 0.0, HUMAN_MODELS["chrome"])
        flow = _assemble(rng, rng.choice(attackers), rng.choice(c2), 443,
                         gaps, sizes, dirs, naive_hello, t0 + i * 0.91)
        flow.truth = {"label": 1, "class": "c2_naive"}
        out.append(GeneratedFlow(flow=flow, label=1,
                                 population="malware_naive",
                                 declared_truth="mobile_app"))

    # --- mimicry malware: cloned Chrome hello + shaping sweep --------------
    for i in range(n_malware_mimicry):
        phi = phi_levels[i % len(phi_levels)]
        n = rng.randint(8, SPLT_PACKETS)
        gaps, sizes, dirs, lat, ovh = _c2_flow(rng, n, 1.0, phi,
                                               HUMAN_MODELS["chrome"])
        # co-tenancy: a slice of beacons run from compromised hosts behind the
        # same shared egress as innocent users. This is the collateral-damage
        # case Pillar 3 has to get right.
        behind_nat = rng.random() < 0.30
        src = rng.choice(shared if behind_nat else attackers)
        flow = _assemble(rng, src, rng.choice(c2), 443, gaps, sizes, dirs,
                         hellos["chrome"], t0 + i * 0.55)
        flow.truth = {"label": 1, "class": "c2_mimicry", "shaping": 1.0, "phi": phi}
        out.append(GeneratedFlow(flow=flow, label=1,
                                 population="malware_mimicry",
                                 declared_truth="chrome", shaping=1.0, phi=phi,
                                 added_latency_ms=lat, padding_overhead=ovh))

    rng.shuffle(out)
    return out


def to_pcap(gen_flows: List[GeneratedFlow], path: str,
            limit: Optional[int] = None) -> str:
    """
    Write the corpus as a real PCAP so the sensor path is exercised for real.

    This matters for the demo: the flows that reach the ML engine during
    scripts/04_demo_live.py have been parsed off the wire by the same code
    that would run on a live interface, not handed over as arrays.
    """
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    pkts = []
    for gf in gen_flows[:limit]:
        f = gf.flow
        src, sport, dst, dport, _ = f.key
        for p in f.packets:
            if p.forward:
                ip = IP(src=src, dst=dst)
                tcp = TCP(sport=sport, dport=dport, flags="PA")
            else:
                ip = IP(src=dst, dst=src)
                tcp = TCP(sport=dport, dport=sport, flags="PA")
            payload = p.payload if p.payload else bytes(
                min(p.size, 1400))
            # Wrap in Ethernet so the PCAP has a standard link layer that
            # PcapReader parses without falling back to Raw. The MACs are
            # placeholders -- nothing downstream reads them.
            pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / ip / tcp / payload
            pkt.time = p.ts
            pkts.append(pkt)
    pkts.sort(key=lambda p: p.time)
    wrpcap(path, pkts)
    return path
