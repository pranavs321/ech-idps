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

import struct
from typing import Callable, Iterator, Optional

from .extractor import FlowRecord, extract
from .flow import FlowTable


# pcap link-layer types the byte parser understands -> offset of the IP header
# (None means "work it out from the frame").
_LINK_ETHERNET, _LINK_NULL, _LINK_RAW, _LINK_RAW2 = 1, 0, 101, 228
_LINK_SLL, _LINK_SLL2 = 113, 276


def _ip_offset(raw: bytes, linktype: int):
    if linktype == _LINK_ETHERNET:
        if len(raw) < 14:
            return None
        ethertype = struct.unpack_from("!H", raw, 12)[0]
        off = 14
        if ethertype == 0x8100:                       # 802.1Q VLAN tag
            if len(raw) < 18:
                return None
            ethertype = struct.unpack_from("!H", raw, 16)[0]
            off = 18
        return off if ethertype == 0x0800 else None
    if linktype in (_LINK_RAW, _LINK_RAW2):
        return 0
    if linktype == _LINK_NULL:
        return 4
    if linktype == _LINK_SLL:
        return 16 if len(raw) >= 16 and raw[14:16] == b"\x08\x00" else None
    if linktype == _LINK_SLL2:
        return 20 if len(raw) >= 20 and raw[0:2] == b"\x08\x00" else None
    return None


def _parse_frame(raw: bytes, linktype: int = _LINK_ETHERNET):
    """
    Decode one link-layer frame to
        (src, sport, dst, dport, size, payload, syn, ack)
    by reading the bytes directly, without scapy's layer dispatch.

    Why not use pkt.getlayer(IP)? Because scapy's link-layer type registration
    can be clobbered when heavy libraries (xgboost, shap) are imported after
    scapy in the same process -- the reader then falls back to Raw and
    getlayer(IP) silently returns None. Parsing the bytes ourselves sidesteps
    it entirely and is also just faster. Handles IPv4 + TCP over Ethernet,
    raw IP, loopback and Linux cooked captures; anything else returns None.

    The TCP payload is bounded by the IP header's total-length field, not by
    the end of the frame. Ethernet pads frames shorter than 60 bytes, and on
    real captures those 2-6 trailer bytes used to be counted as tiny data
    packets, polluting the first-15-packets window with ACKs.
    """
    try:
        off = _ip_offset(raw, linktype)
        if off is None or len(raw) < off + 20:
            return None
        vihl = raw[off]
        if (vihl >> 4) != 4:
            return None
        ihl = (vihl & 0x0F) * 4
        if raw[off + 9] != 6:                         # not TCP
            return None
        total_len = struct.unpack_from("!H", raw, off + 2)[0]
        ip_end = off + total_len if total_len >= ihl + 20 else len(raw)
        ip_end = min(ip_end, len(raw))                # snaplen-truncated frame
        src = ".".join(str(b) for b in raw[off + 12:off + 16])
        dst = ".".join(str(b) for b in raw[off + 16:off + 20])
        tcp_off = off + ihl
        if len(raw) < tcp_off + 20:
            return None
        sport, dport = struct.unpack_from("!HH", raw, tcp_off)
        data_off = (raw[tcp_off + 12] >> 4) * 4
        flags = raw[tcp_off + 13]
        payload = raw[tcp_off + data_off:ip_end]
        return (src, sport, dst, dport, len(payload), payload,
                bool(flags & 0x02), bool(flags & 0x10))
    except (struct.error, IndexError):
        return None


def _iter_raw(path: str):
    """
    Yield (ts, raw_bytes, linktype) from a pcap or pcapng file without
    dissecting packets (an order of magnitude faster than PcapReader).
    """
    from scapy.utils import RawPcapNgReader, RawPcapReader

    with RawPcapReader(path) as reader:
        is_ng = isinstance(reader, RawPcapNgReader)
        for raw, meta in reader:
            if is_ng:
                res = meta.tsresol or 1_000_000
                ts = ((meta.tshigh << 32) | meta.tslow) / res
                linktype = meta.linktype
            else:
                ts = meta.sec + meta.usec / (1e9 if reader.nano else 1e6)
                linktype = reader.linktype
            yield ts, raw, linktype


def _iter_frames(path: str):
    """Decoded TCP segments of a capture file, control segments included."""
    for ts, raw, linktype in _iter_raw(path):
        parsed = _parse_frame(raw, linktype)
        if parsed is None:
            continue
        src, sport, dst, dport, size, payload, syn, ack = parsed
        if not payload and not syn:
            continue  # pure ACK / FIN: no SPLT or direction information
        yield src, sport, dst, dport, ts, size, payload, syn, ack


def _iter_scapy(packets):
    """Live-capture path: scapy packets -> the same tuples as _iter_frames."""
    for pkt in packets:
        parsed = _parse_frame(bytes(pkt))
        if parsed is None:
            continue
        src, sport, dst, dport, size, payload, syn, ack = parsed
        if not payload and not syn:
            continue
        ts = float(getattr(pkt, "time", 0.0))
        yield src, sport, dst, dport, ts, size, payload, syn, ack


def read_pcap(path: str, idle_timeout: float = 30.0) -> Iterator[FlowRecord]:
    """Replay a capture file and yield one FlowRecord per scored flow."""
    table = FlowTable(idle_timeout=idle_timeout)
    next_sweep = None
    for src, sport, dst, dport, ts, size, payload, syn, ack in _iter_frames(path):
        flow = table.observe(src, sport, dst, dport, ts, size, payload,
                             syn=syn, ack=ack)
        # Emit a flow the moment its window fills; sweep for idle flows once a
        # second of capture time (a full-table scan per packet is quadratic on
        # large captures).
        if flow.splt_ready and not flow.emitted:
            flow.emitted = True
            table.stats["emitted"] += 1
            rec = extract(flow)
            if rec is not None:
                yield rec
        if next_sweep is None or ts >= next_sweep:
            next_sweep = ts + 1.0
            for idle_flow in table.ready_flows(now=ts):
                rec = extract(idle_flow)
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
        for src, sport, dst, dport, ts, size, payload, syn, ack in _iter_scapy([pkt]):
            table.observe(src, sport, dst, dport, ts, size, payload,
                          syn=syn, ack=ack)
            for flow in table.ready_flows(now=ts):
                rec = extract(flow)
                if rec is not None and on_record is not None:
                    on_record(rec)

    sniff(iface=iface, filter=bpf, prn=handle, store=False)
