"""Stage 0: check tools and libraries before anything runs."""
import shutil
import subprocess
import sys

ok = True
ts = shutil.which("tshark")
if not ts:
    print("MISSING tshark: brew install --cask wireshark  (or: brew install wireshark)")
    ok = False
else:
    v = subprocess.run([ts, "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    print("tshark:", v)
for mod in ("pandas", "numpy", "sklearn", "xgboost", "pyarrow", "pyzipper", "cryptography"):
    try:
        m = __import__(mod)
        print(f"{mod}: {getattr(m, '__version__', 'ok')}")
    except ImportError:
        print(f"MISSING {mod}: pip install -r requirements.txt")
        ok = False
print("python:", sys.version.split()[0])
sys.exit(0 if ok else 1)
