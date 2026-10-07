"""
Packet sources feeding the flow table.

Three are provided:
  read_pcap   -- offline replay of a capture file (evaluation, demo, viva)
  live_sniff  -- real capture from an interface (needs root)
  replay_records -- bypass the wire entirely and feed pre-built FlowRecords
                    (used when training on a synthetic corpus, where
                    materialising millions of packets would be wasteful)

Everything downstream of here sees the same Flow objects, so a result measured
on a PCAP and a result measured live come from an identical code path.
"""

from __future__ import annotations

from typing import Callable, Iterator, Optional

from .extractor import FlowRecord, extract
from .flow import FlowTable


import struct


def _parse_frame(raw: bytes):
    """
    Decode one link-layer frame to (src, sport, dst, dport, size, payload)
    by reading the bytes directly, without scapy's layer dispatch.

    Why not use pkt.getlayer(IP)? Because scapy's link-layer type registration
    can be clobbered when heavy libraries (xgboost, shap) are imported after
    scapy in the same process -- the reader then falls back to Raw and
    getlayer(IP) silently returns None. That failure is invisible and cost us
    real debugging time. Parsing the bytes ourselves sidesteps it entirely and
    is also just faster. Handles Ethernet + IPv4 + TCP, which is all the demo
    and the sensor need; other frame types return None and are skipped.
    """
    try:
        if len(raw) < 14:
            return None
        # Ethernet II. Handle an optional 802.1Q VLAN tag.
        ethertype = struct.unpack_from("!H", raw, 12)[0]
        off = 14
        if ethertype == 0x8100:                       # VLANwhat is
            ethertype = struct.unpack_from("!H", raw, 16)[0]
            off = 18
        if ethertype != 0x0800:                       # not IPv4
            return None
        if len(raw) < off + 20:
            return None
        vihl = raw[off]
        if (vihl >> 4) != 4:
            return None
        ihl = (vihl & 0x0F) * 4
        proto = raw[off + 9]
        if proto != 6:                                # not TCP
            return None
        src = ".".join(str(b) for b in raw[off + 12:off + 16])
        dst = ".".join(str(b) for b in raw[off + 16:off + 20])
        tcp_off = off + ihl
        if len(raw) < tcp_off + 20:
            return None
        sport, dport = struct.unpack_from("!HH", raw, tcp_off)
        data_off = (raw[tcp_off + 12] >> 4) * 4
        payload = raw[tcp_off + data_off:]
        return src, sport, dst, dport, len(payload), payload
    except (struct.error, IndexError):
        return None


def _iter_frames(reader):
    """Yield decoded tuples from a scapy PcapReader, parsing bytes directly."""
    for pkt in reader:
        raw = bytes(pkt)
        parsed = _parse_frame(raw)
        if parsed is None:
            continue
        src, sport, dst, dport, size, payload = parsed
        if not payload:
            continue  # pure ACK / control: no SPLT information
        ts = float(getattr(pkt, "time", 0.0))
        yield src, sport, dst, dport, ts, size, payload


def _iter_scapy(packets):
    """Kept for compatibility; delegates to the byte parser."""
    for pkt in packets:
        raw = bytes(pkt)
        parsed = _parse_frame(raw)
        if parsed is None:
            continue
        src, sport, dst, dport, size, payload = parsed
        if not payload:
            continue
        ts = float(getattr(pkt, "time", 0.0))
        yield src, sport, dst, dport, ts, size, payload


def read_pcap(path: str, idle_timeout: float = 30.0) -> Iterator[FlowRecord]:
    """Replay a capture file and yield one FlowRecord per scored flow."""
    from scapy.utils import PcapReader

    table = FlowTable(idle_timeout=idle_timeout)
    last_ts = 0.0
    with PcapReader(path) as reader:
        for src, sport, dst, dport, ts, size, payload in _iter_frames(reader):
            last_ts = ts
            table.observe(src, sport, dst, dport, ts, size, payload)
            for flow in table.ready_flows(now=ts):
                rec = extract(flow)
                if rec is not None:
                    yield rec
    for flow in table.flush():
        rec = extract(flow)
        if rec is not None:
            yield rec


def live_sniff(iface: str, bpf: str = "tcp port 443",
               on_record: Optional[Callable[[FlowRecord], None]] = None,
               idle_timeout: float = 15.0) -> None:
    """
    Capture from a live interface. Requires CAP_NET_RAW (run as root).

    In the deployed split-plane design this is the control plane: it only ever
    observes. Dropping is Module 1's job, in kernel, which is why a slow
    Python consumer here cannot stall the datapath.
    """
    from scapy.sendrecv import sniff

    table = FlowTable(idle_timeout=idle_timeout)

    def handle(pkt):
        for src, sport, dst, dport, ts, size, payload in _iter_scapy([pkt]):
            table.observe(src, sport, dst, dport, ts, size, payload)
            for flow in table.ready_flows(now=ts):
                rec = extract(flow)
                if rec is not None and on_record is not None:
                    on_record(rec)

    sniff(iface=iface, filter=bpf, prn=handle, store=False)
