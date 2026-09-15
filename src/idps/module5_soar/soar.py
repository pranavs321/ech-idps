"""
Module 5c -- the SOAR orchestrator.

Ties the pieces together: takes a verdict and its attribution, asks the address
store who else lives behind the source, runs the policy table, applies the
result to the data plane, and files an incident record.

The incident log is the audit trail. Every entry carries the verdict, the
statistic that produced it, the attribution that shaped the response and the
action taken -- enough for an analyst to reconstruct and, importantly, to
*contest* any automated decision. An enforcement system that cannot be argued
with after the fact will eventually be turned off by the people it annoys.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .ip_context import IPContextStore
from .policy import Mechanism, MitigationDecision, MitigationPolicy, Scope


@dataclass
class Incident:
    ts: float
    src_ip: str
    dst_ip: str
    dst_port: int
    verdict_label: str
    tier: str
    risk: float
    declared: str
    best_fit: str
    dissonance: float
    dissonance_tau: float
    reason: str
    decision: Dict[str, Any]
    attribution: Optional[Dict[str, Any]] = None
    evasion_cost: Dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


class SOAR:
    def __init__(self, dataplane, context_store: Optional[IPContextStore] = None,
                 policy: Optional[MitigationPolicy] = None,
                 log_path: Optional[str] = None,
                 max_incidents: int = 5000):
        self.dataplane = dataplane
        self.context = context_store or IPContextStore().load_defaults()
        self.policy = policy or MitigationPolicy()
        self.incidents: List[Incident] = []
        self.max_incidents = max_incidents
        self.log_path = log_path
        self.stats = {
            "flows_seen": 0,
            "malicious": 0,
            "xdp_drops": 0,
            "rst": 0,
            "alert_only": 0,
            "escalations_blocked": 0,
        }

    # -- main entry point -------------------------------------------------
    def handle(self, verdict, attribution=None) -> Optional[Incident]:
        rec = verdict.record
        self.stats["flows_seen"] += 1

        # Every flow updates the co-tenancy picture, benign ones included --
        # in fact especially benign ones, since they are the evidence that an
        # address is shared.
        if rec is not None:
            self.context.observe(rec.src_ip, verdict.declared)

        if not verdict.is_malicious:
            return None

        self.stats["malicious"] += 1
        ctx = self.context.lookup(rec.src_ip if rec else "")
        decision = self.policy.decide(verdict, attribution, ctx)
        self._apply(decision)

        incident = Incident(
            ts=time.time(),
            src_ip=rec.src_ip if rec else "",
            dst_ip=rec.dst_ip if rec else "",
            dst_port=rec.dst_port if rec else 0,
            verdict_label=verdict.label,
            tier=verdict.tier,
            risk=float(verdict.risk),
            declared=verdict.declared,
            best_fit=verdict.best_fit,
            dissonance=float(verdict.dissonance),
            dissonance_tau=float(verdict.dissonance_tau),
            reason=verdict.reason,
            decision=decision.as_dict(),
            attribution=attribution.as_dict() if attribution else None,
            evasion_cost=verdict.evasion_cost,
        )
        self.incidents.append(incident)
        if len(self.incidents) > self.max_incidents:
            self.incidents = self.incidents[-self.max_incidents:]
        if self.log_path:
            with open(self.log_path, "a") as fh:
                fh.write(json.dumps(incident.as_dict()) + "\n")
        return incident

    # -- enforcement ------------------------------------------------------
    def _apply(self, decision: MitigationDecision) -> None:
        if decision.escalation_blocked:
            self.stats["escalations_blocked"] += 1

        if decision.mechanism == Mechanism.XDP_DROP:
            if decision.scope == Scope.SOURCE_IP:
                self.dataplane.block_ip(decision.target,
                                        ttl=decision.ttl_seconds,
                                        reason=decision.rationale)
            else:
                self.dataplane.block_tuple(decision.target,
                                           ttl=decision.ttl_seconds,
                                           reason=decision.rationale)
            self.stats["xdp_drops"] += 1
        elif decision.mechanism == Mechanism.RST:
            self.dataplane.reset_connection(decision.target)
            # A reset alone stops this conversation but not the next one, so a
            # short-lived tuple entry backs it up.
            self.dataplane.block_tuple(decision.target,
                                       ttl=decision.ttl_seconds,
                                       reason=decision.rationale)
            self.stats["rst"] += 1
        else:
            self.stats["alert_only"] += 1

    # -- reporting --------------------------------------------------------
    def recent(self, n: int = 50) -> List[dict]:
        return [i.as_dict() for i in self.incidents[-n:][::-1]]

    def summary(self) -> dict:
        by_tier: Dict[str, int] = {}
        by_scope: Dict[str, int] = {}
        for i in self.incidents:
            by_tier[i.tier] = by_tier.get(i.tier, 0) + 1
            s = i.decision["scope"]
            by_scope[s] = by_scope.get(s, 0) + 1
        return {**self.stats, "by_tier": by_tier, "by_scope": by_scope,
                "blocklist_size": self.dataplane.size()}
