"""
Pillar 1 -- Cryptographic-Physical Dissonance, D(x).

The idea in one line: stop asking "is this flow malicious?" and start asking
"is this flow's physical behaviour even possible for the client it claims to
be?"

Definition
----------
For a flow with physical feature vector x_phys (features 1-12) and declared
class c (read off the outer ClientHello, feature 13):

    D(x) = log [ P(x_phys | c*) / P(x_phys | c) ]

where c* = argmax_k P(x_phys | k) is the class the physics actually best fits.

    D(x) ~ 0   the physics is as plausible under the declared class as under
               any other -- the claim is consistent with the evidence.
    D(x) >> 0  some other class explains the observed physics far better than
               the one this connection declares -- the declaration is a lie.

A sign-convention note worth raising in the review
-------------------------------------------------
The dossier (Section 5, Pillar 1) writes the ratio the other way up, as
log[P(x|c) / P(x|c*)], while also saying "large D(x) means the connection is
lying". Those two statements are inconsistent: because c* is the argmax, the
dossier's ratio is bounded above by 0 and gets *more negative* as dissonance
grows. The form implemented here is the negation of the dossier's, which makes
D(x) >= 0 with larger meaning more dissonant, matching the prose and making
"threshold tau" a natural upper-tail test. Fix this in the paper before a
reviewer finds it.

Why a likelihood ratio and not a distance
-----------------------------------------
A raw likelihood P(x|c) would flag any unusual flow, including the benign long
tail. The ratio normalises that away: a flow with weird physics that is weird
in a way *typical of its declared class* scores near zero. Only flows whose
weirdness is specifically better explained by a different class are penalised.
That is what makes D(x) a consistency test rather than an outlier test -- and
it is why Tier 3 (Isolation Forest) is still needed for genuine novelty.

Calibration
-----------
Densities are Gaussian mixtures fitted per declared class on benign traffic
only. tau is then set to the (1 - target_fpr) quantile of D over held-out
benign flows, so the threshold carries a stated false-positive rate rather
than being hand-tuned.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import numpy as np
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler

from .cover_rate import calibrate_thresholds
from ..features import PHYSICS_IDX

# Classes with fewer than this many benign samples do not get their own
# density -- a mixture fitted on a handful of flows would be noise with a
# confident-looking likelihood attached to it.
MIN_SAMPLES_PER_CLASS = 120


@dataclass
class DissonanceConfig:
    n_components: int = 4
    covariance_type: str = "full"
    reg_covar: float = 1e-4
    target_fpr: float = 0.005
    random_state: int = 7


class DissonanceModel:
    """Class-conditional density model producing the D(x) statistic."""

    def __init__(self, config: Optional[DissonanceConfig] = None):
        self.config = config or DissonanceConfig()
        self.scaler: Optional[StandardScaler] = None
        self.densities: Dict[str, GaussianMixture] = {}
        self.classes: List[str] = []
        self.tau: float = float("inf")  # Global fallback
        self.tau_per_class: Dict[str, float] = {}
        self.calibration: Dict[str, float] = {}

    # -- fitting ---------------------------------------------------------
    def fit(self, X: np.ndarray, declared: Sequence[str],
            benign_mask: np.ndarray) -> "DissonanceModel":
        """
        Fit on benign flows only.

        Fitting on benign traffic exclusively is deliberate: the model encodes
        "how does a real chrome/firefox/safari/app client behave", which is a
        statement about the legitimate population. It must not be contaminated
        by malware, or the malware's own physics becomes plausible under the
        class it is impersonating -- the model would learn to excuse the
        attack.
        """
        Xp = np.asarray(X, dtype=np.float64)[:, PHYSICS_IDX]
        declared = np.asarray(declared)
        benign_mask = np.asarray(benign_mask, dtype=bool)

        self.scaler = StandardScaler().fit(Xp[benign_mask])
        Z = self.scaler.transform(Xp)

        for cls in sorted(set(declared[benign_mask])):
            sel = benign_mask & (declared == cls)
            if sel.sum() < MIN_SAMPLES_PER_CLASS:
                continue
            k = max(1, min(self.config.n_components, sel.sum() // 40))
            gm = GaussianMixture(
                n_components=k,
                covariance_type=self.config.covariance_type,
                reg_covar=self.config.reg_covar,
                random_state=self.config.random_state,
                max_iter=400,
            ).fit(Z[sel])
            self.densities[cls] = gm
        self.classes = sorted(self.densities.keys())
        if not self.classes:
            raise ValueError(
                "No declared class had enough benign samples to fit a density. "
                "Generate a larger corpus or lower MIN_SAMPLES_PER_CLASS.")

        # Calibrate tau on benign flows, so the threshold means "this FPR".
        d_benign = self.score(X[benign_mask], declared[benign_mask])
        self.tau = float(np.quantile(d_benign, 1.0 - self.config.target_fpr))
        self.tau_per_class = calibrate_thresholds(d_benign, declared[benign_mask], self.config.target_fpr)
        self.calibration = {
            "target_fpr": self.config.target_fpr,
            "tau": self.tau,
            "tau_per_class": self.tau_per_class,
            "benign_median": float(np.median(d_benign)),
            "benign_p95": float(np.quantile(d_benign, 0.95)),
            "n_benign": int(benign_mask.sum()),
        }
        return self

    # -- scoring ---------------------------------------------------------
    def _loglik_matrix(self, X: np.ndarray) -> np.ndarray:
        Z = self.scaler.transform(np.asarray(X, dtype=np.float64)[:, PHYSICS_IDX])
        return np.column_stack([self.densities[c].score_samples(Z)
                                for c in self.classes])

    def score(self, X: np.ndarray, declared: Sequence[str]) -> np.ndarray:
        """
        D(x) for each row. Non-negative; larger means more dissonant.
        """
        L = self._loglik_matrix(X)
        best = L.max(axis=1)
        idx = {c: i for i, c in enumerate(self.classes)}
        declared = np.asarray(declared)

        out = np.empty(len(declared), dtype=np.float64)
        for i, c in enumerate(declared):
            j = idx.get(c)
            if j is None:
                # The connection declares a class we have no behavioural model
                # for -- including the "unknown" case where no handshake was
                # observed. We cannot run a consistency test, so we return 0
                # and let Tier 3 handle it as a novelty question. Returning a
                # large value here would let an attacker manufacture alerts on
                # innocent traffic by withholding the hello.
                out[i] = 0.0
            else:
                out[i] = best[i] - L[i, j]
        return np.maximum(out, 0.0)

    def best_fit_class(self, X: np.ndarray) -> List[str]:
        """Which class the physics actually looks like. Used in the receipt."""
        L = self._loglik_matrix(X)
        return [self.classes[j] for j in L.argmax(axis=1)]

    def is_dissonant(self, X: np.ndarray, declared: Sequence[str]) -> np.ndarray:
        scores = self.score(X, declared)
        out = np.zeros(len(scores), dtype=bool)
        for i, c in enumerate(declared):
            tau = self.tau_per_class.get(c, self.tau)
            out[i] = scores[i] > tau
        return out

    # -- persistence ------------------------------------------------------
    def save(self, path: str) -> None:
        import joblib
        joblib.dump(self, path)
        meta = Path(path).with_suffix(".json")
        meta.write_text(json.dumps({
            "classes": self.classes,
            "physics_dims": PHYSICS_IDX,
            **self.calibration,
        }, indent=2))

    @staticmethod
    def load(path: str) -> "DissonanceModel":
        import joblib
        return joblib.load(path)


def evasion_cost_lower_bound(d_observed: float, tau: float,
                             n_packets: int = 15) -> Dict[str, float]:
    """
    Pillar 2, evaluated pointwise: the minimum shaping effort this specific
    flow would have needed to slip under tau.

    D(x) is a log-likelihood ratio, so it is an empirical estimate of n *
    D_KL(M || H) for a flow of n observations -- the information-theoretic
    distance between the attacker's native distribution M and the cover
    distribution H. To reach D <= tau the adversary must move its distribution
    to within tau/n nats of the cover per packet.

    Pinsker's inequality converts that divergence into a total-variation
    floor, which bounds below the fraction of packets whose timing or size the
    adversary must alter:

        TV(M, M') >= sqrt( max(0, D - tau) / (2n) )

    That fraction is the honest, distribution-free part of the claim. Turning
    it into milliseconds and bytes needs the operator's own utility function,
    which is why the full theorem in docs/EVASION_COST_THEOREM.md carries the
    attacker latency and bandwidth budgets as explicit parameters, and why the
    empirical sweep in the evaluation exists alongside the bound.

    Returns the excess divergence, the per-packet divergence and the TV floor.
    """
    excess = max(0.0, d_observed - tau)
    per_packet = excess / max(1, n_packets)
    tv_floor = math.sqrt(min(1.0, excess / (2.0 * max(1, n_packets))))
    return {
        "excess_nats": excess,
        "per_packet_nats": per_packet,
        "min_fraction_packets_altered": min(1.0, tv_floor),
    }
