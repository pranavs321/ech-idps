"""
Tier 1 -- the deterministic fingerprint check.

Runs before any model. If the outer ClientHello's JA4 is on a known-bad list,
we are done: no inference, no floating point, a verdict in microseconds.

This tier is not novel and the dossier does not claim it is. It is here for
throughput. In any real deployment a large share of hostile traffic still comes
from commodity implants that never bothered to clone a browser stack, and
spending an XGBoost inference plus a TreeSHAP attribution on those is waste.
Tier 1 clears them so the expensive tiers see only the traffic that needs
judgement.

Two match modes:
  exact   full JA4 string -- a specific client build
  prefix  JA4_a only (version/SNI-flag/counts/ALPN) -- a family of builds that
          share a handshake shape. Broader, so it carries a confidence penalty
          and is kept out of the persistent-ban path in Module 5.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional


@dataclass
class BlocklistHit:
    ja4: str
    label: str
    source: str
    mode: str          # "exact" | "prefix"
    confidence: float


class JA4Blocklist:
    def __init__(self) -> None:
        self.exact: Dict[str, dict] = {}
        self.prefix: Dict[str, dict] = {}

    def add(self, ja4: str, label: str, source: str = "local",
            mode: str = "exact") -> None:
        entry = {"label": label, "source": source}
        if mode == "prefix":
            self.prefix[ja4.split("_")[0]] = entry
        else:
            self.exact[ja4] = entry

    def check(self, ja4: Optional[str]) -> Optional[BlocklistHit]:
        if not ja4:
            return None
        hit = self.exact.get(ja4)
        if hit:
            return BlocklistHit(ja4, hit["label"], hit["source"], "exact", 0.99)
        hit = self.prefix.get(ja4.split("_")[0])
        if hit:
            return BlocklistHit(ja4, hit["label"], hit["source"], "prefix", 0.80)
        return None

    # -- persistence ------------------------------------------------------
    def save(self, path: str) -> None:
        Path(path).write_text(json.dumps(
            {"exact": self.exact, "prefix": self.prefix}, indent=2))

    @classmethod
    def load(cls, path: str) -> "JA4Blocklist":
        bl = cls()
        data = json.loads(Path(path).read_text())
        bl.exact = data.get("exact", {})
        bl.prefix = data.get("prefix", {})
        return bl

    def __len__(self) -> int:
        return len(self.exact) + len(self.prefix)
