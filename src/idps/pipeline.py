"""
End-to-end wiring of all five modules.

    packet -> [M1 kernel filter] -> [M2 flow sensor] -> [M3 3-tier ML]
           -> [M4 TreeSHAP] -> [M5 SOAR] -> back into [M1]

The loop closing back into Module 1 is the part worth pointing at during the
review: a verdict does not end at a dashboard, it becomes a kernel map entry,
so the next packet from that source is dropped before the OS sees it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

import numpy as np

from .module1_dataplane.dataplane import DataPlane, SimulatedDataPlane
from .module2_sensor.extractor import FlowRecord
from .module3_ml.dissonance import DissonanceModel
from .module3_ml.engine import DetectionEngine, Verdict
from .module3_ml.tier1_blocklist import JA4Blocklist
from .module3_ml.tier2_supervised import SupervisedTier
from .module3_ml.tier3_anomaly import AnomalyTier
from .module4_xai.treeshap import Attribution, ExplainabilityEngine
from .module5_soar.ip_context import IPContextStore
from .module5_soar.policy import MitigationPolicy
from .module5_soar.soar import SOAR

ARTIFACTS = Path(__file__).resolve().parents[2] / "artifacts"


@dataclass
class Result:
    verdict: Verdict
    attribution: Optional[Attribution]
    incident: Optional[object]


class IDPS:
    def __init__(self, engine: DetectionEngine, explainer: ExplainabilityEngine,
                 soar: SOAR, dataplane: DataPlane):
        self.engine = engine
        self.explainer = explainer
        self.soar = soar
        self.dataplane = dataplane

    # -- the loop ---------------------------------------------------------
    def process(self, rec: FlowRecord) -> Result:
        # Module 1: would the kernel already have dropped this? In the live
        # system we would never see it. Checking here keeps the offline replay
        # faithful to what the deployed system does, including the fact that a
        # blocked source stops generating alerts.
        tup = f"{rec.src_ip}->{rec.dst_ip}:{rec.dst_port}"
        if self.dataplane.is_blocked(rec.src_ip, tup):
            return Result(
                verdict=Verdict(label="malicious", tier="tier1_dataplane",
                                risk=1.0, confidence=1.0, declared=rec.declared,
                                reason="Source already in the kernel blocklist; "
                                       "dropped before the stack.",
                                record=rec),
                attribution=None, incident=None)

        # Module 3
        verdict = self.engine.evaluate(rec)

        # Module 4 -- only for model-driven verdicts. A blocklist hit has no
        # model to attribute over, and computing SHAP for a benign flow would
        # spend the expensive part of the pipeline on the common case.
        attribution = None
        if verdict.is_malicious and verdict.tier == "tier2_supervised":
            attribution = self.explainer.explain(
                rec.features, np.array([verdict.dissonance]))

        # Module 5 -> back into Module 1
        incident = self.soar.handle(verdict, attribution)
        return Result(verdict=verdict, attribution=attribution,
                      incident=incident)

    def process_many(self, records: Iterable[FlowRecord]) -> List[Result]:
        return [self.process(r) for r in records]


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------
def build(artifacts: Path = ARTIFACTS,
          dataplane: Optional[DataPlane] = None,
          log_path: Optional[str] = None) -> IDPS:
    """Load trained artifacts and assemble a running system."""
    artifacts = Path(artifacts)
    missing = [n for n in ("dissonance.joblib", "supervised.joblib",
                           "anomaly.joblib", "ja4_blocklist.json")
               if not (artifacts / n).exists()]
    if missing:
        raise FileNotFoundError(
            f"Missing trained artifacts {missing} in {artifacts}. "
            f"Run: python3 scripts/02_train.py")

    blocklist = JA4Blocklist.load(str(artifacts / "ja4_blocklist.json"))
    dissonance = DissonanceModel.load(str(artifacts / "dissonance.joblib"))
    supervised = SupervisedTier.load(str(artifacts / "supervised.joblib"))
    anomaly = AnomalyTier.load(str(artifacts / "anomaly.joblib"))

    engine = DetectionEngine(blocklist, dissonance, supervised, anomaly)
    explainer = ExplainabilityEngine(supervised)
    dp = dataplane or SimulatedDataPlane()
    soar = SOAR(dp, IPContextStore().load_defaults(), MitigationPolicy(),
                log_path=log_path)
    return IDPS(engine, explainer, soar, dp)
