# Architecture

## The central design decision: why split the plane

A detector that consults machine learning for every packet becomes the
bottleneck it was meant to protect. At line rate you cannot afford a
user-space round trip, a feature computation and an XGBoost inference per
packet — you would add milliseconds to every flow and fall over under load.

So enforcement and analysis are separated:

- **Data plane (Module 1).** An eBPF/XDP program attached at the earliest
  point the kernel can run code on a received frame — before `sk_buff`
  allocation, before the network stack, before conntrack. It does exactly one
  thing: look the source up in a hash map and either `XDP_DROP` or `XDP_PASS`.
  That costs on the order of nanoseconds and never touches user space.

- **Control plane (Modules 2–5).** Flow assembly, the 14-D feature vector, the
  three ML tiers, TreeSHAP and the SOAR policy. This runs in user space and is
  allowed to take milliseconds, because its output is not "should this packet
  pass" but "should this *source* be added to the kernel's drop map."

The two planes communicate through a **BPF map**. When Module 5 decides to
block, it writes an entry into the map that the XDP program reads on the hot
path. From that moment, packets from the condemned source are dropped in-kernel
and never reach the analysis plane again. **The control plane's latency is
paid once per verdict, not once per packet.** That is the whole reason the
design works.

```
   fast path (per packet, ns)          slow path (per flow, ms)
   ┌───────────────────────┐           ┌──────────────────────────┐
   │  XDP program           │  map      │  sensor → 3-tier ML →     │
   │  lookup + drop/pass    │◀──────────│  TreeSHAP → SOAR policy   │
   └───────────────────────┘  write     └──────────────────────────┘
        kernel space                          user space
```

## Data flow, end to end

1. A frame arrives. The XDP program (`xdp_filter.c`) checks `blocked_ips` and
   `blocked_tuples`. Hit → `XDP_DROP`. Miss → `XDP_PASS`.
2. Module 2 (`module2_sensor/`) assembles the packet into a bidirectional flow
   keyed by canonical 5-tuple, captures the outer ClientHello, and once the
   first 15 packets are seen (or the flow goes idle) computes:
   - features 1–12: the SPLT physics (sizes, inter-arrival gaps, bursts,
     directionality);
   - feature 13: JA4 similarity of the observed fingerprint to the reference
     profile of the class it declares;
   - feature 14: coarse flow context.
   The 5-tuple is **stripped** here — the vector that crosses into the analysis
   plane carries no addressable data.
3. Module 3 (`module3_ml/engine.py`) runs the cascade: Tier 1 blocklist → Tier
   2 XGBoost (with `D(x)`) → Tier 3 Isolation Forest. Each tier can terminate
   with a verdict, and the verdict records *which* tier fired.
4. If Tier 2 condemned the flow, Module 4 (`module4_xai/treeshap.py`) computes
   the exact TreeSHAP attribution and the family-mass split.
5. Module 5 (`module5_soar/`) looks up the source's co-tenancy context, runs
   the attribution-driven policy, applies the result to the data plane, and
   files an auditable incident.

## The privacy boundary

Feature extraction strips IPs and ports before the vector leaves the sensor.
Module 5 re-attaches an address at enforcement time, from its own store. So the
analytical plane — the ML, the attributions, the logged feature vectors — never
holds data that identifies an endpoint. This is not incidental; it is what lets
you argue the detection pipeline is privacy-clean even though it operates on
everyone's traffic.

## Why two separate block maps

`blocked_ips` (source-address bans) is **wide**: one entry stops all traffic
from a host. `blocked_tuples` (5-tuple bans) is **narrow**: it stops one
conversation. They are separate because Module 5's whole job is choosing
between them based on how attributable the evidence is. A source ban is only
ever written when the evidence is endpoint-intrinsic; shared-infrastructure
verdicts get tuple-scoped entries so bystanders behind the same NAT keep
working. See `docs/REVIEW_CHEATSHEET.md`.

Both maps are `LRU_HASH`, not plain `HASH`. A plain hash that fills up rejects
new inserts — which silently turns enforcement *off* exactly when an attacker
is spraying spoofed source ports at you. LRU degrades by forgetting its oldest
entry instead. That is the failure mode you want from a security control.

## TTLs are enforced in-kernel

Each map entry carries an `expires_ns` timestamp. The XDP program compares it
against `bpf_ktime_get_ns()` on lookup, so an expired block stops matching even
if the user-space daemon that was supposed to reap it has died. **Never rely on
a user-space process to end a block on time.** The kernel enforces expiry
itself; user space only tidies up.

## RST is a separate mechanism from XDP drop

A common mistake in IDPS architecture diagrams is to treat "reset the
connection" and "drop the packets" as the same action. They are not. XDP can
only drop *inbound* frames from the receive path. Tearing down an already
established TCP connection requires either injecting a spoofed RST to both
endpoints or deleting the conntrack entry — neither of which XDP does. Module 5
models these as distinct mechanisms (`Mechanism.RST` vs `Mechanism.XDP_DROP`)
for exactly this reason.

## Attach modes (read before quoting a latency number)

Native XDP runs in the NIC driver and is where nanosecond figures come from,
but it needs driver support. Many virtualised NICs — including most VM setups
students test on — lack it, and the attach **silently falls back** to
generic/SKB mode, which runs after `sk_buff` allocation and is roughly an order
of magnitude slower. If you put a latency number in your report, run
`ip link show <iface>` and say whether it reports `xdp` (native) or
`xdpgeneric`. Quoting a native-XDP figure measured in generic mode is the kind
of thing a sharp examiner catches.

## Recalibration

The dissonance model encodes "how does a real Chrome/Firefox/Safari/mobile
client behave." Browsers change — new TLS extension orders, new HTTP behaviours,
new sub-resource loading patterns. A stale class model drifts and raises false
positives. In deployment the class-conditional densities and the JA4 reference
profiles (`ja4.py::BROWSER_PROFILES`) should be refreshed from a browser-farm
capture on each major browser release. This is limitation #4 in the README and
is worth stating before an examiner asks "what happens when Chrome updates?"
