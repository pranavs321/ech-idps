"""Stratosphere (MCFP) README parsing shared by the labelling and evaluation scripts."""
from __future__ import annotations
import datetime as dt
import os
import re

TZ = {"CEST": 2, "CET": 1, "UTC": 0, "GMT": 0}
PRIV = r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"


def readme(d: str, root: str = "data/mcfp_meta") -> str:
    p = os.path.join(root, d, "README.md")
    return open(p, errors="ignore").read() if os.path.exists(p) else ""


def infected_ip(text: str) -> str | None:
    m = re.findall(r"Infected host:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", text)
    return m[0] if m else None


def normal_ips(text: str) -> set[str]:
    return set(re.findall(r"Normal host:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", text))


def cc_ips(text: str) -> set[str]:
    return set(re.findall(r"C&?C IP (?:is|:)?\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", text, re.I))


def infect_time(text: str) -> float | None:
    """UTC epoch of the first README timeline entry that says 'infected' (CEST/CET/UTC dates)."""
    for ds, txt in re.findall(r"##\s*([A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ [\d:]+ [A-Z]{3,4} \d{4})\s*\n+\s*(.*)", text):
        if re.search(r"infect", txt, re.I) and not re.search(r"not infect|un-?infect", txt, re.I):
            parts = ds.split()
            base = dt.datetime.strptime(" ".join(parts[:4] + [parts[5]]), "%a %b %d %H:%M:%S %Y")
            base -= dt.timedelta(hours=TZ.get(parts[4], 0))
            return base.replace(tzinfo=dt.timezone.utc).timestamp()
    return None
