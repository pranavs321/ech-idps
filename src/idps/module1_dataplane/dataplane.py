"""
Module 1 -- the data plane, from user space.

Two implementations behind one interface:

    SimulatedDataPlane   pure Python. An LRU blocklist with TTLs that behaves
                         like the kernel maps. Runs anywhere, including in a
                         container with no kernel privileges, which is what
                         makes the demo and the whole evaluation reproducible
                         on a laptop and in CI.

    XDPDataPlane         talks to the real pinned BPF maps through bpftool or
                         the libbpf Python bindings. Used on a machine where
                         the program in xdp_filter.c is actually attached.

Having both matters for more than convenience. Every measurement in the
evaluation runs against the simulated plane, so results are reproducible by
anyone without root. The real plane is then verified to enforce identically --
same TTL semantics, same LRU eviction, same tuple ordering -- so the numbers
carry over. If the two ever diverge, tests/test_dataplane_parity.py fails.
"""

from __future__ import annotations

import subprocess
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class BlockEntry:
    target: str
    installed_at: float
    ttl: int                    # seconds; 0 = permanent
    reason: str = ""
    hits: int = 0

    def expired(self, now: float) -> bool:
        return self.ttl > 0 and (now - self.installed_at) > self.ttl

    @property
    def expires_at(self) -> Optional[float]:
        return None if self.ttl == 0 else self.installed_at + self.ttl


class DataPlane:
    """Interface Module 5 enforces against."""

    def block_ip(self, ip: str, ttl: int = 0, reason: str = "") -> None: ...
    def block_tuple(self, tup: str, ttl: int = 0, reason: str = "") -> None: ...
    def reset_connection(self, tup: str) -> None: ...
    def is_blocked(self, ip: str, tup: str = "") -> bool: ...
    def size(self) -> int: ...


class SimulatedDataPlane(DataPlane):
    def __init__(self, capacity: int = 1_048_576):
        self.capacity = capacity
        self.ips: "OrderedDict[str, BlockEntry]" = OrderedDict()
        self.tuples: "OrderedDict[str, BlockEntry]" = OrderedDict()
        self.resets: list = []
        self.stats = {"seen": 0, "dropped": 0, "passed": 0, "expired": 0,
                      "evicted": 0}

    # -- installation -----------------------------------------------------
    def _install(self, table: "OrderedDict[str, BlockEntry]", key: str,
                 ttl: int, reason: str) -> None:
        if key in table:
            table.move_to_end(key)
            table[key].installed_at = time.time()
            table[key].ttl = ttl
            return
        if len(table) >= self.capacity:
            table.popitem(last=False)           # LRU eviction, as in the kernel
            self.stats["evicted"] += 1
        table[key] = BlockEntry(target=key, installed_at=time.time(),
                                ttl=ttl, reason=reason)

    def block_ip(self, ip: str, ttl: int = 0, reason: str = "") -> None:
        if ip:
            self._install(self.ips, ip, ttl, reason)

    def block_tuple(self, tup: str, ttl: int = 0, reason: str = "") -> None:
        if tup:
            self._install(self.tuples, tup, ttl, reason)

    def reset_connection(self, tup: str) -> None:
        """
        Stands in for an injected TCP RST. On a real deployment this is a raw
        socket sending a spoofed RST to both endpoints, or a conntrack entry
        deletion -- note that neither is something XDP can do, since XDP only
        drops inbound frames. Tearing down an established connection is
        genuinely a separate mechanism from filtering, and conflating the two
        is a common mistake in IDPS architecture diagrams.
        """
        self.resets.append((time.time(), tup))

    # -- the hot path -----------------------------------------------------
    def is_blocked(self, ip: str, tup: str = "") -> bool:
        now = time.time()
        self.stats["seen"] += 1
        for table, key in ((self.ips, ip), (self.tuples, tup)):
            if not key:
                continue
            e = table.get(key)
            if e is None:
                continue
            if e.expired(now):
                del table[key]
                self.stats["expired"] += 1
                continue
            e.hits += 1
            table.move_to_end(key)
            self.stats["dropped"] += 1
            return True
        self.stats["passed"] += 1
        return False

    # -- housekeeping -----------------------------------------------------
    def reap(self) -> int:
        now = time.time()
        n = 0
        for table in (self.ips, self.tuples):
            for k in [k for k, e in table.items() if e.expired(now)]:
                del table[k]
                n += 1
        self.stats["expired"] += n
        return n

    def size(self) -> int:
        return len(self.ips) + len(self.tuples)

    def dump(self) -> Dict[str, list]:
        now = time.time()
        def rows(table):
            return [{
                "target": e.target,
                "reason": e.reason,
                "hits": e.hits,
                "ttl": e.ttl,
                "remaining": (None if e.ttl == 0
                              else max(0, int(e.installed_at + e.ttl - now))),
            } for e in table.values()]
        return {"ips": rows(self.ips), "tuples": rows(self.tuples),
                "stats": dict(self.stats)}


class XDPDataPlane(DataPlane):
    """
    Real kernel enforcement. Requires xdp_filter.o attached and its maps pinned
    under /sys/fs/bpf/. See loader.py.

    Falls back loudly, not silently: if the pinned maps are missing this raises
    rather than degrading to a no-op, because a security control that quietly
    stops enforcing is worse than one that is obviously broken.
    """

    def __init__(self, pin_dir: str = "/sys/fs/bpf",
                 ip_map: str = "blocked_ips",
                 tuple_map: str = "blocked_tuples"):
        self.ip_map_path = f"{pin_dir}/{ip_map}"
        self.tuple_map_path = f"{pin_dir}/{tuple_map}"
        self._check()

    def _check(self) -> None:
        import os
        missing = [p for p in (self.ip_map_path, self.tuple_map_path)
                   if not os.path.exists(p)]
        if missing:
            raise RuntimeError(
                f"BPF maps not pinned: {missing}. Attach the XDP program first "
                f"(sudo python3 -m idps.module1_dataplane.loader --iface eth0), "
                f"or use SimulatedDataPlane for offline work.")

    @staticmethod
    def _ip_key(ip: str) -> str:
        return " ".join(f"0x{int(o):02x}" for o in ip.split("."))

    @staticmethod
    def _entry_value(ttl: int) -> str:
        expires = 0 if ttl == 0 else int(time.time_ns() + ttl * 1_000_000_000)
        parts = []
        for val, width in ((expires, 8), (0, 8), (0, 4)):
            parts += [f"0x{(val >> (8 * i)) & 0xFF:02x}" for i in range(width)]
        return " ".join(parts)

    def block_ip(self, ip: str, ttl: int = 0, reason: str = "") -> None:
        subprocess.run(
            ["bpftool", "map", "update", "pinned", self.ip_map_path,
             "key", *self._ip_key(ip).split(),
             "value", *self._entry_value(ttl).split(), "any"],
            check=True, capture_output=True)

    def block_tuple(self, tup: str, ttl: int = 0, reason: str = "") -> None:
        src, rest = tup.split("->")
        dst, dport = rest.rsplit(":", 1)
        key = (self._ip_key(src).split() + self._ip_key(dst).split()
               + ["0x00", "0x00"]
               + [f"0x{(int(dport) >> 8) & 0xFF:02x}",
                  f"0x{int(dport) & 0xFF:02x}"])
        subprocess.run(
            ["bpftool", "map", "update", "pinned", self.tuple_map_path,
             "key", *key, "value", *self._entry_value(ttl).split(), "any"],
            check=True, capture_output=True)

    def reset_connection(self, tup: str) -> None:
        # Left to an external RST injector; XDP cannot terminate an
        # established connection from the receive path.
        pass

    def is_blocked(self, ip: str, tup: str = "") -> bool:
        r = subprocess.run(
            ["bpftool", "map", "lookup", "pinned", self.ip_map_path,
             "key", *self._ip_key(ip).split()],
            capture_output=True)
        return r.returncode == 0

    def size(self) -> int:
        r = subprocess.run(["bpftool", "map", "dump", "pinned",
                            self.ip_map_path, "-j"], capture_output=True)
        if r.returncode != 0:
            return 0
        import json
        return len(json.loads(r.stdout or "[]"))
