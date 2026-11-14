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
    Return a direction-independent key, plus a flag saying whether the packet's
    sender is the first endpoint of that key.

    Ordering by (ip, port) makes both halves of a conversation hash to the same
    bucket without needing to see the SYN. The flag is ONLY a hashing detail:
    it does not say who opened the connection. An earlier version used it as
    the packet direction, which on real captures flipped every direction
    feature and lost the ClientHello whenever the client's address happened to
    sort after the server's (about one connection in nine), and made Module 5
    aim source-scoped blocks at the server. Direction now comes from
    `Flow.initiator`, which is set from the TCP handshake (see `observe`).
    """
    a, b = (src, sport), (dst, dport)
    if a <= b:
        return (src, sport, dst, dport, proto), True
    return (dst, dport, src, sport, proto), False


# A ClientHello can span several TCP segments (post-quantum key shares push
# Chrome's past 1.7 kB). Buffer at most one maximum-size TLS record + header.
CH_MAX_BYTES = 16_389


def _looks_like_client_hello(payload: bytes) -> bool:
    return (len(payload) >= 6 and payload[0] == 0x16 and payload[1] == 0x03
            and payload[5] == 0x01)


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
    # (ip, port) of the endpoint that opened the connection. None until the
    # handshake (or, failing that, the first payload packet) decides it.
    initiator: Optional[Tuple[str, int]] = None
    initiator_certain: bool = False
    ch_buffer: bytes = b""
    ch_done: bool = False
    # Ground truth, only populated by the synthetic generator. Never read by
    # the detector -- it rides along so the evaluation harness can score.
    truth: Optional[dict] = None

    def _ends(self) -> Tuple[Tuple[str, int], Tuple[str, int]]:
        a, b = (self.key[0], self.key[1]), (self.key[2], self.key[3])
        if self.initiator is None or self.initiator == a:
            return a, b
        return b, a

    @property
    def src_ip(self) -> str:
        return self._ends()[0][0]

    @property
    def src_port(self) -> int:
        return self._ends()[0][1]

    @property
    def dst_ip(self) -> str:
        return self._ends()[1][0]

    @property
    def dst_port(self) -> int:
        return self._ends()[1][1]

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
        if pkt.forward and not self.ch_done and pkt.payload:
            self._collect_client_hello(pkt.payload)

    def _collect_client_hello(self, payload: bytes) -> None:
        """
        Reassemble a ClientHello that spans TCP segments. Parsing only the
        first segment yields a confident but wrong fingerprint (truncated
        extension list), which is worse than no fingerprint.
        """
        if not self.ch_buffer:
            if not _looks_like_client_hello(payload):
                if payload[:1] == b"\x16" and self.client_hello is None:
                    # Synthetic corpus / odd framing: keep the old behaviour.
                    self.client_hello = payload
                    self.ch_done = True
                return
            self.ch_buffer = payload
        elif payload != self.ch_buffer[-len(payload):]:   # skip retransmits
            self.ch_buffer += payload
        need = 5 + int.from_bytes(self.ch_buffer[3:5], "big")
        if len(self.ch_buffer) >= need:
            self.client_hello = self.ch_buffer[:need]
            self.ch_done = True
        elif len(self.ch_buffer) > CH_MAX_BYTES:
            self.ch_done = True          # give up; leave client_hello unset

    def flip_direction(self) -> None:
        """Called when better evidence shows the provisional guess was wrong."""
        for p in self.packets:
            p.forward = not p.forward


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
                proto: int = 6, truth: Optional[dict] = None,
                syn: bool = False, ack: bool = False) -> Flow:
        """
        Feed one TCP segment. Direction evidence, strongest first:
          1. SYN without ACK: the sender opened the connection.
          2. SYN+ACK: the receiver opened it.
          3. A ClientHello: its sender is the client.
          4. No handshake seen (capture started mid-flow): the endpoint with
             the higher port is taken as the client, provisionally.
        Segments without payload (pure SYN/ACK) set the direction but are not
        added to the SPLT window: they carry no size or timing information the
        feature vector uses.
        """
        key, _ = canonical_key(src, sport, dst, dport, proto)
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.capacity:
                self._evict_one()
            flow = Flow(key=key, start_ts=ts, last_ts=ts, truth=truth)
            self.flows[key] = flow
            self.stats["created"] += 1
        sender, receiver = (src, sport), (dst, dport)
        if syn and not flow.initiator_certain:
            self._set_initiator(flow, receiver if ack else sender, True)
        if not payload:
            return flow
        if not flow.initiator_certain and _looks_like_client_hello(payload):
            self._set_initiator(flow, sender, True)
        if flow.initiator is None:
            guess = sender if sport >= dport else receiver
            self._set_initiator(flow, guess, False)
        flow.add(Packet(ts=ts, size=size, forward=(sender == flow.initiator),
                        payload=payload))
        return flow

    @staticmethod
    def _set_initiator(flow: Flow, who: Tuple[str, int], certain: bool) -> None:
        if flow.initiator is not None and flow.initiator != who:
            flow.flip_direction()
        flow.initiator = who
        flow.initiator_certain = certain

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
