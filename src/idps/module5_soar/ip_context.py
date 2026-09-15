"""
Module 5a -- address context.

Before enforcing anything, ask who else is behind this address. The answer
decides how much collateral a block would cause, and it is half of the input to
the policy table (the other half is the attribution mass from Module 4).

Sources, in the order a deployment should consult them:
  1. a local static map (site knowledge: your own NAT ranges, your VPN pools)
  2. RIR / WHOIS or an IP-intelligence feed, cached
  3. observed co-tenancy: how many distinct flows and declared classes have we
     seen from this address recently?

Source 3 is worth dwelling on, because it is the one that does not depend on
any external feed and cannot be poisoned by bad WHOIS data. If a single address
has recently produced flows declaring Chrome, Firefox, Safari and a mobile app
stack, it is almost certainly an egress shared by many users, whatever a
database says about it. That is a *measurement* of co-tenancy rather than a
lookup, and it is what keeps the collateral-damage guarantee honest on
infrastructure nobody has catalogued.
"""

from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set

DEDICATED = "dedicated"
SHARED = "shared"
UNKNOWN = "unknown"


@dataclass
class IPContext:
    ip: str
    kind: str                       # dedicated | shared | unknown
    owner: str = ""
    evidence: str = ""
    observed_classes: int = 0
    observed_flows: int = 0
    # Estimated number of innocent parties a source-scoped block would hit.
    # Deliberately conservative: when in doubt, assume bystanders exist.
    collateral_estimate: int = 0


class IPContextStore:
    def __init__(self, window_seconds: float = 900.0,
                 shared_class_threshold: int = 3,
                 shared_flow_threshold: int = 25):
        self.window = window_seconds
        self.shared_class_threshold = shared_class_threshold
        self.shared_flow_threshold = shared_flow_threshold
        self.static_map: List[tuple] = []           # (network, kind, owner)
        self._flows: Dict[str, Deque[float]] = defaultdict(deque)
        self._classes: Dict[str, Set[str]] = defaultdict(set)

    # -- configuration ----------------------------------------------------
    def add_range(self, cidr: str, kind: str, owner: str) -> None:
        self.static_map.append((ipaddress.ip_network(cidr), kind, owner))

    def load_defaults(self) -> "IPContextStore":
        """
        Site knowledge for the bundled demo corpus. Replace with your own
        ranges, or wire an IP-intelligence feed, before any real deployment.
        """
        self.add_range("203.0.113.0/24", SHARED, "Campus NAT egress")
        self.add_range("198.51.100.0/24", DEDICATED, "Managed workstation pool")
        self.add_range("192.0.2.0/24", UNKNOWN, "External, uncatalogued")
        self.add_range("100.64.0.0/10", UNKNOWN, "CGNAT space")
        return self

    # -- observation ------------------------------------------------------
    def observe(self, ip: str, declared_class: str,
                now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        q = self._flows[ip]
        q.append(now)
        cutoff = now - self.window
        while q and q[0] < cutoff:
            q.popleft()
        self._classes[ip].add(declared_class)

    # -- lookup -----------------------------------------------------------
    def lookup(self, ip: str) -> IPContext:
        kind, owner, evidence = UNKNOWN, "", "no catalogue entry"
        try:
            addr = ipaddress.ip_address(ip)
            for net, k, o in self.static_map:
                if addr in net:
                    kind, owner = k, o
                    evidence = f"static map: {net}"
                    break
        except ValueError:
            pass

        n_flows = len(self._flows.get(ip, ()))
        n_classes = len(self._classes.get(ip, ()))

        # Observed co-tenancy overrides a "dedicated" or "unknown" catalogue
        # entry, never the other way round. Escalating toward "shared" is the
        # safe direction: the failure mode is a block that is narrower than it
        # could have been, not one that hits bystanders.
        if (n_classes >= self.shared_class_threshold
                or n_flows >= self.shared_flow_threshold):
            if kind != SHARED:
                evidence = (f"observed co-tenancy: {n_classes} distinct client "
                            f"stacks across {n_flows} flows in the last "
                            f"{int(self.window / 60)} minutes")
            kind = SHARED

        if kind == SHARED:
            collateral = max(n_flows, self.shared_flow_threshold)
        elif kind == DEDICATED:
            collateral = 0
        else:
            collateral = max(1, n_flows // 4)

        return IPContext(ip=ip, kind=kind, owner=owner, evidence=evidence,
                         observed_classes=n_classes, observed_flows=n_flows,
                         collateral_estimate=collateral)
