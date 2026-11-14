"""
Module 2c -- host context: each connection described against its own host.

Why this exists
---------------
On real infected machines the TLS fingerprint cannot carry detection: malware
calls the operating system's TLS library and so presents the same JA4 as the
host's own benign software (measured on public same-host captures; see
docs/REAL_TRAFFIC_RESULTS.md). Absolute behaviour features do not carry it far
either, because packet sizes and gaps also encode the network path and the
era, and those change from one site to the next.

What does survive a change of environment is how a connection sits inside its
own host's traffic: what share of the host's TLS connections go to this
destination, how many of the host's stacks talk to it, whether contact with it
is periodic, and whether this connection behaves like the host's other
connections on the same TLS stack. Anything that is constant for a host
(operating system, MTU, latency, VPN egress) is shared by the connection and
by its reference set, so it cancels.

This is also the right shape for the ECH era. Every quantity below needs only
the server address and port, never the SNI.

Privacy boundary
----------------
This module runs in the sensor plane, which already holds the 5-tuple. What
it emits is a vector of counts, shares and z-scores. No address, port or name
crosses into the ML plane, so AGENTS.md rule 2 holds, and the 14-D vector is
untouched (rule 1): host context is a separate, optional input, exactly as
D(x) is.

Two modes
---------
batch   every connection sees the host's whole capture (offline triage).
causal  every connection sees only what the host did BEFORE it (deployable
        online; the first connections of a host have little context).

Prior work this builds on: within-bag normalisation (Bartos et al., USENIX
Security 2016), host baselining (Yen et al., ACSAC 2013), beacon detection
(Hu et al., DSN 2016). The design choice here is the reference set: the same
host, and within it the same TLS stack.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Sequence

import numpy as np

from ..features import INDEX_BY_NAME
from .extractor import FlowRecord

# Physics features standardised against the host's own connections. Chosen
# from the "endpoint_intrinsic" family plus mean size and mean gap, which are
# path-dependent in absolute terms and become usable once made host-relative.
_RELATIVE = ["mean_pkt_size", "std_pkt_size", "size_lattice_entropy",
             "log_mean_iat", "iat_cv", "directionality_ratio",
             "up_down_pkt_ratio", "log_flow_duration"]

CONTEXT_NAMES: List[str] = (
    ["dest_share", "log_dest_conns", "dest_n_stacks",
     "stack_share", "stack_n_dests", "host_n_stacks", "log_host_conns",
     "beacon_log_median_gap", "beacon_gap_cv", "beacon_periodicity"]
    + [f"z_host_{n}" for n in _RELATIVE]
    + [f"z_stack_{n}" for n in _RELATIVE])
N_CONTEXT = len(CONTEXT_NAMES)
# Destination-context block and relative-behaviour block, for ablations.
DEST_IDX = list(range(0, 10))
RELATIVE_IDX = list(range(10, N_CONTEXT))

_MIN_PEERS = 3
_LOO_MAX = 40
_CAUSAL_WINDOW = 200   # past connections a causal z-score looks back over
_BEACON_TAIL = 64      # gaps kept per destination in causal mode


def _beacon(ts: Sequence[float]) -> tuple:
    if len(ts) < 3:
        return -1.0, -1.0, 0.0
    gaps = np.diff(np.asarray(ts, dtype=float))
    med = float(np.median(gaps))
    cv = float(np.std(gaps) / (np.mean(gaps) + 1e-9))
    per = float(np.mean(np.abs(gaps - med) <= 0.1 * med + 0.5)) if med > 0 else 0.0
    return float(np.log1p(max(med, 0.0))), cv, per


def _z(x: float, med: float, mad: float) -> float:
    return float(np.clip((x - med) / (1.4826 * mad + 1e-6 + 0.05 * abs(med)), -50, 50))


def _stats(ref: np.ndarray) -> tuple:
    """Column-wise median and MAD of a reference set (rows = connections)."""
    med = np.median(ref, axis=0)
    return med, np.median(np.abs(ref - med), axis=0)


def _robust_z(x: float, ref: np.ndarray) -> float:
    if ref.size < _MIN_PEERS:
        return 0.0
    med = float(np.median(ref))
    return _z(x, med, float(np.median(np.abs(ref - med))))


def host_context(records: Sequence[FlowRecord], causal: bool = False) -> np.ndarray:
    """
    Context vector for every record, shape (len(records), N_CONTEXT).

    `records` is one capture (or one time window) from one sensor. Hosts are
    told apart by source address; destinations by server address and port.
    """
    out = np.zeros((len(records), N_CONTEXT), dtype=np.float32)
    rel_ix = [INDEX_BY_NAME[n] for n in _RELATIVE]
    by_host: Dict[str, List[int]] = defaultdict(list)
    for i, r in enumerate(records):
        by_host[r.src_ip].append(i)

    for idx in by_host.values():
        idx = sorted(idx, key=lambda i: records[i].start_ts)
        dest = [(records[i].dst_ip, records[i].dst_port) for i in idx]
        stack = [records[i].stack or "none" for i in idx]
        ts = [records[i].start_ts for i in idx]
        phys = np.array([[records[i].features[j] for j in rel_ix] for i in idx],
                        dtype=float)
        if causal:
            _fill_causal(out, idx, dest, stack, ts, phys)
        else:
            _fill_batch(out, idx, dest, stack, ts, phys)
    return out


def _fill_batch(out, idx, dest, stack, ts, phys) -> None:
    n = len(idx)
    d_rows: Dict[tuple, List[int]] = defaultdict(list)
    s_rows: Dict[str, List[int]] = defaultdict(list)
    for k in range(n):
        d_rows[dest[k]].append(k)
        s_rows[stack[k]].append(k)
    d_stacks = {d: len({stack[k] for k in rows}) for d, rows in d_rows.items()}
    s_dests = {s: len({dest[k] for k in rows}) for s, rows in s_rows.items()}
    d_beacon = {d: _beacon([ts[k] for k in rows]) for d, rows in d_rows.items()}
    # Leave-one-out reference sets for small groups (one connection can move a
    # median of five); the whole group for large ones, where it cannot.
    n_c = phys.shape[1]
    everyone = np.arange(n)
    s_arr = {s: np.array(rows, dtype=int) for s, rows in s_rows.items()}
    host_stats = _stats(phys) if n > _LOO_MAX else None
    stack_stats = {s: _stats(phys[rows]) for s, rows in s_arr.items()
                   if rows.size > _LOO_MAX}
    for k in range(n):
        d, s = dest[k], stack[k]
        row = [len(d_rows[d]) / n, np.log1p(len(d_rows[d])), d_stacks[d],
               len(s_rows[s]) / n, s_dests[s], len(s_rows), np.log1p(n),
               *d_beacon[d]]
        if host_stats is not None:
            zh = [_z(phys[k, c], host_stats[0][c], host_stats[1][c]) for c in range(n_c)]
        else:
            others = np.delete(everyone, k)
            zh = [_robust_z(phys[k, c], phys[others, c]) for c in range(n_c)]
        if s in stack_stats:
            zs = [_z(phys[k, c], stack_stats[s][0][c], stack_stats[s][1][c])
                  for c in range(n_c)]
        else:
            peers = s_arr[s][s_arr[s] != k]
            zs = [_robust_z(phys[k, c], phys[peers, c]) if peers.size >= _MIN_PEERS
                  else zh[c] for c in range(n_c)]
        out[idx[k]] = row + zh + zs


def _fill_causal(out, idx, dest, stack, ts, phys) -> None:
    d_count: Dict[tuple, int] = defaultdict(int)
    s_count: Dict[str, int] = defaultdict(int)
    d_stacks: Dict[tuple, set] = defaultdict(set)
    s_dests: Dict[str, set] = defaultdict(set)
    d_ts: Dict[tuple, List[float]] = defaultdict(list)
    s_rows: Dict[str, List[int]] = defaultdict(list)
    for k in range(len(idx)):
        d, s = dest[k], stack[k]
        # Update with this connection's own handshake-time facts first: its
        # destination and stack are known the moment the ClientHello is seen.
        d_count[d] += 1
        s_count[s] += 1
        d_stacks[d].add(s)
        s_dests[s].add(d)
        d_ts[d] = (d_ts[d] + [ts[k]])[-_BEACON_TAIL:]
        seen = k + 1
        row = [d_count[d] / seen, np.log1p(d_count[d]), len(d_stacks[d]),
               s_count[s] / seen, len(s_dests[s]), len(s_count), np.log1p(seen),
               *_beacon(d_ts[d])]
        past = np.arange(max(0, k - _CAUSAL_WINDOW), k)
        peers = np.array(s_rows[s][-_CAUSAL_WINDOW:], dtype=int)
        zh = [_robust_z(phys[k, c], phys[past, c]) for c in range(phys.shape[1])]
        zs = [_robust_z(phys[k, c], phys[peers, c]) if peers.size >= _MIN_PEERS
              else zh[c] for c in range(phys.shape[1])]
        out[idx[k]] = row + zh + zs
        s_rows[s].append(k)
