"""
Module 5b -- Pillar 3, attribution-driven enforcement.

This is the file where the second novelty claim actually lives, so it is worth
being precise about what is new.

Not new: consulting IP reputation before blocking. Plenty of SOAR platforms do
that.

New: the *feature-attribution vector is an input to the policy function*. The
system asks what the case against this flow is made of, and matches the
severity of the response to the kind of evidence supporting it:

    evidence intrinsic to the endpoint's own process
        -> the evidence travels with the attacker, so a source-scoped,
           persistent block is proportionate.

    evidence drawn from properties the address's neighbours share
        -> the evidence does not identify the endpoint, only its
           neighbourhood, so a source-scoped block would punish people the
           model never accused. Act on the flow, briefly.

The consequence is a bound by construction rather than by tuning: a verdict
that rests on shared-infrastructure features can never escalate to a persistent
source ban, no matter how high the model's confidence. Confidence and
attributability are different quantities, and conflating them is how automated
response takes down a university's entire outbound Wi-Fi at 3am.

The policy is a table, not a model. That is on purpose: enforcement decisions
need to be auditable and arguable in an incident review, and "the second model
said so" is not a defensible answer to "why was our CDN blocked".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional

from ..features import (CRYPTO_DECLARED, ENDPOINT_INTRINSIC,
                        INFRA_COINCIDENTAL)
from .ip_context import DEDICATED, SHARED, UNKNOWN, IPContext


class Scope(str, Enum):
    FLOW = "flow"                  # this connection only
    FIVE_TUPLE = "five_tuple"      # this src/dst/port pair
    SOURCE_IP = "source_ip"        # everything from this address


class Mechanism(str, Enum):
    ALERT_ONLY = "alert_only"      # no enforcement, analyst review
    RST = "rst"                    # tear down the live connection
    XDP_DROP = "xdp_drop"          # install in the kernel blocklist


@dataclass
class MitigationDecision:
    scope: Scope
    mechanism: Mechanism
    ttl_seconds: int
    target: str
    rationale: str
    intrinsic_mass: float
    infra_mass: float
    collateral_estimate: int
    escalation_blocked: bool = False   # did attribution veto a harsher action?

    def as_dict(self) -> dict:
        return {
            "scope": self.scope.value,
            "mechanism": self.mechanism.value,
            "ttl_seconds": self.ttl_seconds,
            "target": self.target,
            "rationale": self.rationale,
            "intrinsic_mass": round(self.intrinsic_mass, 4),
            "infra_mass": round(self.infra_mass, 4),
            "collateral_estimate": self.collateral_estimate,
            "escalation_blocked": self.escalation_blocked,
        }


@dataclass
class PolicyConfig:
    # Attribution mass on endpoint-intrinsic evidence required before a
    # source-scoped persistent action is permitted at all.
    intrinsic_threshold: float = 0.60
    # Above this much infrastructure-coincidental mass, the verdict is treated
    # as non-attributable regardless of model confidence.
    infra_veto_threshold: float = 0.40
    ttl_persistent: int = 86_400
    ttl_medium: int = 3_600
    ttl_short: int = 300
    ttl_minimal: int = 60
    # Tier 3 is novelty detection, not identification. It never enforces
    # beyond the flow, whatever its score.
    anomaly_max_scope: Scope = Scope.FLOW


class MitigationPolicy:
    def __init__(self, config: Optional[PolicyConfig] = None):
        self.config = config or PolicyConfig()

    def decide(self, verdict, attribution, ctx: IPContext) -> MitigationDecision:
        cfg = self.config

        fam = attribution.family_mass if attribution else {}
        intrinsic = (fam.get(ENDPOINT_INTRINSIC, 0.0)
                     + fam.get("dissonance", 0.0))
        infra = fam.get(INFRA_COINCIDENTAL, 0.0)
        crypto = fam.get(CRYPTO_DECLARED, 0.0)

        # ---- Tier 1: deterministic fingerprint match ----------------------
        # No attribution vector exists (no model ran), but the evidence is a
        # property of the client software itself, which is as endpoint-intrinsic
        # as evidence gets. Still respect co-tenancy: a shared egress can carry
        # a bad client without its neighbours being complicit.
        if verdict.tier == "tier1_blocklist":
            if ctx.kind == SHARED:
                return MitigationDecision(
                    scope=Scope.FIVE_TUPLE, mechanism=Mechanism.RST,
                    ttl_seconds=cfg.ttl_short, target=self._tuple(verdict),
                    rationale=(
                        "Known-malicious client fingerprint, but the source is "
                        f"shared infrastructure ({ctx.owner or ctx.evidence}). "
                        "Tearing down this conversation rather than banning an "
                        f"address roughly {ctx.collateral_estimate} other "
                        "sessions are using."),
                    intrinsic_mass=1.0, infra_mass=0.0,
                    collateral_estimate=ctx.collateral_estimate,
                    escalation_blocked=True)
            return MitigationDecision(
                scope=Scope.SOURCE_IP, mechanism=Mechanism.XDP_DROP,
                ttl_seconds=cfg.ttl_persistent, target=verdict.record.src_ip,
                rationale=("Known-malicious client fingerprint from a "
                           "non-shared source. Persistent kernel-level drop."),
                intrinsic_mass=1.0, infra_mass=0.0,
                collateral_estimate=ctx.collateral_estimate)

        # ---- Tier 3: novelty ---------------------------------------------
        if verdict.tier == "tier3_anomaly":
            return MitigationDecision(
                scope=cfg.anomaly_max_scope, mechanism=Mechanism.ALERT_ONLY,
                ttl_seconds=cfg.ttl_minimal, target=self._tuple(verdict),
                rationale=("Novelty detection only: the flow is outside the "
                           "clean baseline but no identity contradiction was "
                           "established. Raised for analyst review without "
                           "enforcement, because an unexplained anomaly is not "
                           "an attribution."),
                intrinsic_mass=intrinsic, infra_mass=infra,
                collateral_estimate=ctx.collateral_estimate)

        # ---- Tier 2: the attribution-driven path --------------------------
        # Case A: no usable incriminating mass. Should not normally happen,
        # but a policy that quietly defaults to "block hard" when its input is
        # missing is exactly the failure mode this pillar exists to prevent.
        if intrinsic + infra + crypto <= 1e-9:
            return MitigationDecision(
                scope=Scope.FLOW, mechanism=Mechanism.ALERT_ONLY,
                ttl_seconds=cfg.ttl_minimal, target=self._tuple(verdict),
                rationale=("Verdict carries no usable attribution mass. "
                           "Falling back to alert-only rather than enforcing "
                           "on evidence the system cannot characterise."),
                intrinsic_mass=0.0, infra_mass=0.0,
                collateral_estimate=ctx.collateral_estimate)

        # Case B: the case rests on the neighbourhood, not the endpoint.
        if infra >= cfg.infra_veto_threshold:
            mech = (Mechanism.RST if ctx.kind != SHARED
                    else Mechanism.ALERT_ONLY)
            return MitigationDecision(
                scope=Scope.FLOW, mechanism=mech,
                ttl_seconds=cfg.ttl_minimal, target=self._tuple(verdict),
                rationale=(
                    f"{infra * 100:.0f}% of the incriminating evidence comes "
                    "from features this address's co-tenants share, so the "
                    "verdict identifies a neighbourhood rather than an "
                    "endpoint. Scope held at the single flow regardless of "
                    f"model confidence ({verdict.risk:.2f})."),
                intrinsic_mass=intrinsic, infra_mass=infra,
                collateral_estimate=ctx.collateral_estimate,
                escalation_blocked=True)

        # Case C: strong endpoint-intrinsic evidence.
        if intrinsic >= cfg.intrinsic_threshold:
            if ctx.kind == DEDICATED:
                return MitigationDecision(
                    scope=Scope.SOURCE_IP, mechanism=Mechanism.XDP_DROP,
                    ttl_seconds=cfg.ttl_persistent,
                    target=verdict.record.src_ip,
                    rationale=(
                        f"{intrinsic * 100:.0f}% of the evidence is intrinsic "
                        "to this endpoint's own beaconing behaviour, and the "
                        f"address is dedicated ({ctx.owner}). Evidence follows "
                        "the host, so a persistent source-scoped drop is "
                        "proportionate."),
                    intrinsic_mass=intrinsic, infra_mass=infra,
                    collateral_estimate=ctx.collateral_estimate)
            if ctx.kind == SHARED:
                return MitigationDecision(
                    scope=Scope.FIVE_TUPLE, mechanism=Mechanism.RST,
                    ttl_seconds=cfg.ttl_short, target=self._tuple(verdict),
                    rationale=(
                        f"Evidence is {intrinsic * 100:.0f}% endpoint-intrinsic "
                        "and would justify a source ban, but the address is "
                        f"shared ({ctx.owner or ctx.evidence}) with an "
                        f"estimated {ctx.collateral_estimate} other active "
                        "sessions. Cutting the attacker's conversation and "
                        "applying a short cool-off to this pair instead."),
                    intrinsic_mass=intrinsic, infra_mass=infra,
                    collateral_estimate=ctx.collateral_estimate,
                    escalation_blocked=True)
            return MitigationDecision(
                scope=Scope.FIVE_TUPLE, mechanism=Mechanism.XDP_DROP,
                ttl_seconds=cfg.ttl_medium, target=self._tuple(verdict),
                rationale=(
                    f"Evidence is {intrinsic * 100:.0f}% endpoint-intrinsic but "
                    "the address is uncatalogued, so co-tenancy cannot be "
                    "ruled out. Dropping this pair for an hour rather than "
                    "banning an address of unknown occupancy."),
                intrinsic_mass=intrinsic, infra_mass=infra,
                collateral_estimate=ctx.collateral_estimate,
                escalation_blocked=True)

        # Case D: mixed evidence, with the declared-identity axis carrying
        # meaningful weight. f13 is forgeable, so it cannot support a wide
        # action on its own.
        return MitigationDecision(
            scope=Scope.FIVE_TUPLE, mechanism=Mechanism.RST,
            ttl_seconds=cfg.ttl_short, target=self._tuple(verdict),
            rationale=(
                f"Mixed evidence: {intrinsic * 100:.0f}% endpoint-intrinsic, "
                f"{infra * 100:.0f}% shared-infrastructure, {crypto * 100:.0f}% "
                "from the declared fingerprint. Below the bar for a source-"
                "scoped action, so the conversation is cut with a short "
                "cool-off."),
            intrinsic_mass=intrinsic, infra_mass=infra,
            collateral_estimate=ctx.collateral_estimate)

    @staticmethod
    def _tuple(verdict) -> str:
        r = verdict.record
        if r is None:
            return "unknown"
        return f"{r.src_ip}->{r.dst_ip}:{r.dst_port}"
