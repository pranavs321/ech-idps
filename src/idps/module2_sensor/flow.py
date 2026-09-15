"""
Module 2a -- flow assembly.

Groups individual packets into bidirectional conversations keyed by the
canonical 5-tuple, holds the first SPLT_PACKETS packets of each, and captures
the outer ClientHello when it appears.

Privacy note, and it matters for the paper as much as for ethics: the 5-tuple
lives only inside this module. The record that leaves the sensor toward the ML
plane carries the 14-D vector and nothing that identifies an endpoint. Module 5
re-attaches an address at enforcement time, from its own store. The analytical
plane therefore never holds addressable data.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..features import SPLT_PACKETS

FlowKey = Tuple[str, int, str, int, int]  # src, sport, dst, dport, proto


def canonical_key(src: str, sport: int, dst: str, dport: int,
                  proto: int = 6) -> Tuple[FlowKey, bool]:
    """
    Return a direction-independent key plus a flag saying whether the observed
    packet travels in the forward (initiator -> responder) direction.

    Ordering by (ip, port) makes both halves of a conversation hash to the same
    bucket without needing to see the SYN.
    """
    a, b = (src, sport), (dst, dport)
    if a <= b:
        return (src, sport, dst, dport, proto), True
    return (dst, dport, src, sport, proto), False


@dataclass
class Packet:
    ts: float          # seconds, monotonic or capture time
    size: int          # transport payload length, headers excluded
    forward: bool      # True if initiator -> responder
    payload: bytes = b""


@dataclass
class Flow:
    key: FlowKey
    start_ts: float
    packets: List[Packet] = field(default_factory=list)
    client_hello: Optional[bytes] = None
    total_packets: int = 0
    total_bytes: int = 0
    last_ts: float = 0.0
    emitted: bool = False
    # Ground truth, only populated by the synthetic generator. Never read by
    # the detector -- it rides along so the evaluation harness can score.
    truth: Optional[dict] = None

    @property
    def src_ip(self) -> str:
        return self.key[0]

    @property
    def dst_ip(self) -> str:
        return self.key[2]

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.start_ts)

    @property
    def splt_ready(self) -> bool:
        return len(self.packets) >= SPLT_PACKETS

    def add(self, pkt: Packet) -> None:
        self.total_packets += 1
        self.total_bytes += pkt.size
        self.last_ts = pkt.ts
        if len(self.packets) < SPLT_PACKETS:
            self.packets.append(pkt)
        if self.client_hello is None and pkt.forward and pkt.payload[:1] == b"\x16":
            self.client_hello = pkt.payload


class FlowTable:
    """
    Bounded flow table with idle expiry.

    The bound is deliberate. An unbounded table is a denial-of-service target:
    an attacker who can spray spoofed source ports can exhaust sensor memory
    and blind the detector without ever tripping it. Capacity is enforced by
    evicting the least recently active flow.
    """

    def __init__(self, idle_timeout: float = 30.0, capacity: int = 200_000):
        self.idle_timeout = idle_timeout
        self.capacity = capacity
        self.flows: Dict[FlowKey, Flow] = {}
        self.stats = {"created": 0, "evicted": 0, "expired": 0, "emitted": 0}

    def observe(self, src: str, sport: int, dst: str, dport: int,
                ts: float, size: int, payload: bytes = b"",
                proto: int = 6, truth: Optional[dict] = None) -> Flow:
        key, forward = canonical_key(src, sport, dst, dport, proto)
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.capacity:
                self._evict_one()
            flow = Flow(key=key, start_ts=ts, last_ts=ts, truth=truth)
            self.flows[key] = flow
            self.stats["created"] += 1
        flow.add(Packet(ts=ts, size=size, forward=forward, payload=payload))
        return flow

    def _evict_one(self) -> None:
        oldest = min(self.flows.values(), key=lambda f: f.last_ts)
        del self.flows[oldest.key]
        self.stats["evicted"] += 1

    def ready_flows(self, now: Optional[float] = None) -> List[Flow]:
        """
        Flows eligible for feature extraction: either the SPLT window is full,
        or the flow went idle. Emitting on idle is what catches short flows --
        a beacon that sends six packets and sleeps would otherwise never be
        scored.
        """
        now = now if now is not None else time.time()
        out: List[Flow] = []
        for flow in list(self.flows.values()):
            if flow.emitted:
                if now - flow.last_ts > self.idle_timeout:
                    del self.flows[flow.key]
                    self.stats["expired"] += 1
                continue
            idle = now - flow.last_ts > self.idle_timeout
            if flow.splt_ready or (idle and len(flow.packets) >= 4):
                flow.emitted = True
                self.stats["emitted"] += 1
                out.append(flow)
            elif idle:
                del self.flows[flow.key]
                self.stats["expired"] += 1
        return out

    def flush(self) -> List[Flow]:
        """Emit every flow with enough packets. Used at end of a PCAP."""
        out = [f for f in self.flows.values()
               if not f.emitted and len(f.packets) >= 4]
        for f in out:
            f.emitted = True
        self.stats["emitted"] += len(out)
        return out
