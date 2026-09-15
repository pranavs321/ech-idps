"""
Module 4 -- the explainability engine.

Computes exact TreeSHAP attributions for the Tier 2 verdict and turns them into
two things:

  1. a human-readable receipt for the analyst;
  2. a machine-readable attribution vector phi, and the distribution of its
     mass across feature families, which Module 5 consumes as a control signal.

Item 2 is the part that is novel (Pillar 3). Every SHAP-for-IDS system in the
survey stops at item 1. Here phi does not merely describe the response, it
selects it -- so the explanation has to be computed on the enforcement path,
not offline in a reporting job. That has a real engineering consequence: the
attribution must be fast enough to sit inline. TreeSHAP is chosen over
KernelSHAP precisely for this. KernelSHAP is model-agnostic but needs thousands
of perturbed evaluations per flow; TreeSHAP exploits the tree structure for an
exact result in time polynomial in depth, which is what makes inline
attribution affordable at all.

Attribution mass and what it means
----------------------------------
Signed SHAP values are what you want for a chart. For policy we want *evidence
weight*, so the split uses the magnitude of contributions that pushed the score
toward "malicious". A feature that argued for innocence should not earn the
attacker a harsher block by having a large negative value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from ..features import (CRYPTO_DECLARED, ENDPOINT_INTRINSIC,
                        INFRA_COINCIDENTAL, SCHEMA, describe)


@dataclass
class Attribution:
    """The receipt."""
    phi: np.ndarray                       # signed SHAP values, one per input
    names: List[str]
    base_value: float
    output: float
    family_mass: Dict[str, float]         # normalised, sums to 1
    top: List[Tuple[str, float, float]]   # (label, phi, share of |phi|)
    narrative: str

    def as_dict(self) -> dict:
        return {
            "base_value": float(self.base_value),
            "output": float(self.output),
            "family_mass": {k: float(v) for k, v in self.family_mass.items()},
            "contributions": [
                {"feature": n, "phi": float(p)}
                for n, p in zip(self.names, self.phi)
            ],
            "top": [{"feature": n, "phi": float(p), "share": float(s)}
                    for n, p, s in self.top],
            "narrative": self.narrative,
        }


class ExplainabilityEngine:
    def __init__(self, supervised_tier):
        import shap
        self.tier = supervised_tier
        self.names = supervised_tier.feature_names
        self.explainer = shap.TreeExplainer(supervised_tier.model)
        # Map each input position to a family. The derived D(x) input, if
        # present, is treated as crypto-coupled evidence: it is a statement
        # about the relationship between the declared identity and the physics,
        # so it belongs to neither pure family.
        self.families: List[str] = [f.family for f in SCHEMA]
        while len(self.families) < len(self.names):
            self.families.append("dissonance")

    # -- core -------------------------------------------------------------
    def explain(self, X: np.ndarray, dissonance: Optional[np.ndarray] = None
                ) -> Attribution:
        A = self.tier._inputs(np.asarray(X).reshape(1, -1), dissonance)
        raw = self.explainer.shap_values(A)
        phi = np.asarray(raw)[0] if np.asarray(raw).ndim > 1 else np.asarray(raw)
        phi = np.asarray(phi, dtype=float).ravel()
        base = float(np.ravel(self.explainer.expected_value)[0])

        family_mass = self._family_mass(phi)
        top = self._top(phi)
        return Attribution(
            phi=phi, names=list(self.names), base_value=base,
            output=float(base + phi.sum()),
            family_mass=family_mass, top=top,
            narrative=self._narrate(top, family_mass),
        )

    # -- helpers ----------------------------------------------------------
    def _family_mass(self, phi: np.ndarray) -> Dict[str, float]:
        """
        Share of incriminating evidence per family.

        Only positive contributions count. Clipping at zero is the whole point:
        Module 5 asks "what is the case against this flow made of", and a
        feature arguing for the defence is not part of that case.
        """
        pos = np.clip(phi, 0.0, None)
        total = float(pos.sum())
        out: Dict[str, float] = {
            ENDPOINT_INTRINSIC: 0.0,
            INFRA_COINCIDENTAL: 0.0,
            CRYPTO_DECLARED: 0.0,
            "dissonance": 0.0,
        }
        if total <= 1e-12:
            # Nothing argued for guilt. Return an explicit all-zero mass; the
            # policy layer reads this as "no usable evidence" and falls back to
            # the most conservative action rather than to a default family.
            return out
        for i, fam in enumerate(self.families[:len(phi)]):
            out[fam] = out.get(fam, 0.0) + float(pos[i]) / total
        return out

    def _top(self, phi: np.ndarray, k: int = 5
             ) -> List[Tuple[str, float, float]]:
        total = float(np.abs(phi).sum()) or 1.0
        order = np.argsort(-np.abs(phi))[:k]
        out = []
        for i in order:
            label = (describe(i).label if i < len(SCHEMA)
                     else "Cryptographic-physical dissonance D(x)")
            out.append((label, float(phi[i]), float(abs(phi[i]) / total)))
        return out

    def _narrate(self, top: List[Tuple[str, float, float]],
                 mass: Dict[str, float]) -> str:
        if not top:
            return "No attribution available."
        lead = top[0]
        parts = [
            f"{lead[0]} carried {lead[2] * 100:.0f}% of the decision weight."
        ]
        if len(top) > 1:
            second = top[1]
            parts.append(
                f"{second[0]} followed at {second[2] * 100:.0f}%.")
        intrinsic = mass.get(ENDPOINT_INTRINSIC, 0.0) + mass.get("dissonance", 0.0)
        infra = mass.get(INFRA_COINCIDENTAL, 0.0)
        parts.append(
            f"{intrinsic * 100:.0f}% of the incriminating evidence is intrinsic "
            f"to this endpoint's own behaviour and {infra * 100:.0f}% comes from "
            f"properties its network neighbours would share.")
        return " ".join(parts)


def format_receipt(attribution: Attribution, verdict) -> str:
    """Plain-text forensic receipt, suitable for a case file or a slide."""
    lines = [
        "FORENSIC ATTRIBUTION RECEIPT",
        "=" * 58,
        f"Verdict        : {verdict.label.upper()} (tier: {verdict.tier})",
        f"Declared class : {verdict.declared}",
        f"Physics fits   : {verdict.best_fit}",
        f"Dissonance D(x): {verdict.dissonance:.2f} nats "
        f"(threshold {verdict.dissonance_tau:.2f})",
        f"Model score    : {verdict.supervised_score:.4f}",
        "",
        "Why this connection was condemned:",
        f"  {verdict.reason}",
        "",
        "Feature contributions (TreeSHAP, exact):",
    ]
    for label, phi, share in attribution.top:
        bar = "#" * max(1, int(share * 40))
        lines.append(f"  {label:<44s} {phi:+7.3f}  {share * 100:5.1f}% {bar}")
    lines += [
        "",
        "Evidence composition:",
    ]
    for fam, m in sorted(attribution.family_mass.items(), key=lambda kv: -kv[1]):
        lines.append(f"  {fam:<22s} {m * 100:5.1f}%")
    if verdict.evasion_cost:
        ec = verdict.evasion_cost
        lines += [
            "",
            "Evasion cost for this flow (Pillar 2):",
            f"  Excess divergence above threshold : "
            f"{ec.get('excess_nats', 0):.2f} nats",
            f"  Minimum fraction of packets the attacker",
            f"  would have had to reshape to evade  : "
            f"{ec.get('min_fraction_packets_altered', 0) * 100:.1f}%",
        ]
    lines.append("=" * 58)
    return "\n".join(lines)
