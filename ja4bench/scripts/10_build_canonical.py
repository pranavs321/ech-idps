#!/usr/bin/env python3
"""Build a canonical table.

  python scripts/10_build_canonical.py --adapter matousek --in data/external/matousek/datasets \
      --out data/canonical/matousek2024.csv.gz
  python scripts/10_build_canonical.py --adapter generic --in ../ja4lab/data/processed/instances.csv \
      --mapping config/mappings/ja4lab_mta2024.yaml --out data/canonical/mta2024.csv.gz

Refuses to write a table that fails schema validation. Prints the sha256 of the output.
"""
import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ja4bench import schema  # noqa: E402
from ja4bench.adapters import generic, matousek  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--adapter", required=True, choices=["matousek", "generic"])
ap.add_argument("--in", dest="inp", required=True)
ap.add_argument("--mapping")
ap.add_argument("--out", required=True)
a = ap.parse_args()

df = matousek.load(a.inp) if a.adapter == "matousek" else generic.load(a.inp, a.mapping)
problems = schema.validate(df)
if problems:
    print("SCHEMA PROBLEMS (nothing written):", *problems, sep="\n  ")
    sys.exit(1)
Path(a.out).parent.mkdir(parents=True, exist_ok=True)
df.to_csv(a.out, index=False, compression={"method": "gzip", "mtime": 0})
import gzip  # hash the DECOMPRESSED bytes: the .gz wrapper embeds a timestamp and is not reproducible
h = hashlib.sha256(gzip.open(a.out, "rb").read()).hexdigest()
print(f"wrote {a.out}  rows={len(df)}  captures={df.capture_id.nunique()}  content_sha256={h}")
print(df.groupby(["env_group", "label"]).size().rename("rows").to_string())
