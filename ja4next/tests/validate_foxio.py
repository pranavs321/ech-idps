"""Check our JA4 / JA4S against FoxIO's reference outputs.

Usage: python -I tests/validate_foxio.py <foxio_repo_dir>
Compares every TCP TLS stream in FoxIO's test pcaps with the expected JSON in
python/test/testdata, and prints agreement for our JA4, tshark's JA4 and our JA4S.
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ja4next.extract import extract  # noqa: E402

repo = sys.argv[1]
tot = ok = ok_ts = s_tot = s_ok = 0
miss = []
for exp_f in sorted(glob.glob(os.path.join(repo, "python/test/testdata/*.json"))):
    pcap = os.path.join(repo, "pcap", os.path.basename(exp_f)[:-5])
    if not os.path.exists(pcap):
        continue
    exp = json.load(open(exp_f))
    want = {}
    for r in exp:
        if "JA4.1" in r and r.get("JA4.1", "").startswith("t"):
            want[int(r["stream"])] = (r["JA4.1"], r.get("JA4S", ""))
    if not want:
        continue
    df = extract(pcap)
    got = {int(s): (j, js, jt) for s, j, js, jt in zip(df["stream"], df["ja4"], df["ja4s"], df["ja4_tshark"])} if len(df) else {}
    for s, (wj, ws) in want.items():
        tot += 1
        g = got.get(s)
        if g and g[0] == wj:
            ok += 1
        else:
            miss.append((os.path.basename(pcap), s, wj, g[0] if g else None))
        if g and g[2] == wj:
            ok_ts += 1
        if ws:
            s_tot += 1
            if g and g[1] == ws:
                s_ok += 1
            elif g:
                miss.append((os.path.basename(pcap), s, "JA4S " + ws, g[1]))
print(f"JA4 ours  : {ok}/{tot}")
print(f"JA4 tshark: {ok_ts}/{tot}")
print(f"JA4S ours : {s_ok}/{s_tot}")
for m in miss[:25]:
    print("MISMATCH", m)
