#!/usr/bin/env python3
"""Minimal test runner (no pytest dependency). Exit code 1 if any test fails."""
import importlib
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
failed = passed = 0
for mod_path in sorted((ROOT / "tests").glob("test_*.py")):
    mod = importlib.import_module(mod_path.stem)
    for name in sorted(n for n in dir(mod) if n.startswith("test_")):
        try:
            getattr(mod, name)()
            passed += 1
            print(f"PASS {mod_path.stem}.{name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {mod_path.stem}.{name}")
            traceback.print_exc()
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
