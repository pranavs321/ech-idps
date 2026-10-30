#!/usr/bin/env python3
"""Machine check of the environment against requirements-lock.txt. Exit 1 on any mismatch.
This, not an agent's verdict, is the CHECK for task R0.   python scripts/check_env.py"""
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

bad = 0
print("python", sys.version.split()[0])
if sys.version_info[:2] != (3, 12):
    print("MISMATCH python: need 3.12.x"); bad += 1
for ln in (Path(__file__).resolve().parents[1] / "requirements-lock.txt").read_text().splitlines():
    ln = ln.split("#")[0].strip()
    if not ln:
        continue
    name, want = ln.split("==")
    try:
        have = version(name)
    except PackageNotFoundError:
        have = "NOT INSTALLED"
    ok = have == want
    bad += not ok
    print(f"{'MATCH   ' if ok else 'MISMATCH'} {name:14s} need {want:8s} have {have}")
print("RESULT:", "FAIL" if bad else "PASS")
sys.exit(1 if bad else 0)
