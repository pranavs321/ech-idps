"""Generic adapter driven by a YAML mapping file (see config/mappings/*.yaml).

Use it for ja4lab's data/processed/instances.csv, Vighnesh's dataset/master.csv, or any extractor
output. The mapping states, explicitly and in git, how each canonical column is obtained, so a
reviewer can see every labelling decision.

Mapping format
--------------
columns:            # canonical_name: source_column_name
  capture_id: pcap
  ja4: ja4
  sni: sni
constants:          # canonical_name: value applied to every row
  source: mta2024
  vantage: lan_tap
per_capture_csv: data/meta/capture_meta.csv   # optional: capture_id -> env_group, os, year, family...
label:
  column: label               # source column holding the label
  map: {malicious: 1, benign: 0, gray: -1}
  basis_column: ip_basis      # optional source column copied into label_basis
  basis_map: {ioc_file: ioc_verified, pcap_inference: inferred}
  default_basis: source_asserted
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import yaml


def load(csv_path: str | Path, mapping_path: str | Path) -> pd.DataFrame:
    m = yaml.safe_load(Path(mapping_path).read_text())
    raw = pd.read_csv(csv_path, low_memory=False, dtype=str)
    out = pd.DataFrame(index=raw.index)
    for canon, col in (m.get("columns") or {}).items():
        if col not in raw.columns:
            raise KeyError(f"mapping says {canon} <- '{col}' but column not in {csv_path}. "
                           f"Columns are: {list(raw.columns)[:40]}")
        out[canon] = raw[col]
    for canon, val in (m.get("constants") or {}).items():
        out[canon] = val
    pc = m.get("per_capture_csv")
    if pc:
        meta = pd.read_csv(pc, dtype=str)
        if "capture_id" not in meta.columns:
            raise KeyError(f"{pc} must have a capture_id column")
        out = out.merge(meta, on="capture_id", how="left", suffixes=("", "_meta"))
        for c in [c for c in out.columns if c.endswith("_meta")]:
            base = c[:-5]
            out[base] = out[base].fillna(out[c]) if base in out else out[c]
            out = out.drop(columns=c)
    lab = m["label"]
    src = raw[lab["column"]].astype(str).str.strip().str.lower()
    lmap = {str(k).lower(): int(v) for k, v in lab["map"].items()}
    out["label"] = src.map(lmap).fillna(-1).astype("int64")
    if lab.get("basis_column"):
        b = raw[lab["basis_column"]].astype(str).str.strip()
        out["label_basis"] = b.map(lab.get("basis_map", {})).fillna(lab.get("default_basis", "unknown"))
    else:
        out["label_basis"] = lab.get("default_basis", "source_asserted")
    if "proto" not in out:
        out["proto"] = out["ja4"].astype(str).str[0].map({"t": "tcp", "q": "quic"}).fillna("unknown")
    if "year" in out:
        out["year"] = pd.to_numeric(out["year"], errors="coerce").fillna(-1).astype("int64")
    else:
        out["year"] = -1  # schema.validate accepts it; P5_temporal will then skip and say why
    for c in ["dst_port", "ttl", "win", "mss", "wscale"]:
        if c in out:
            out[c] = pd.to_numeric(out[c], errors="coerce")
    if "capture_id" in out and "source" in out:
        out["capture_id"] = out["source"].astype(str) + ":" + out["capture_id"].astype(str)
    out.insert(0, "row_id", np.arange(len(out)))
    return out
