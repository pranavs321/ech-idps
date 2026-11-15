"""Download small MCFP botnet pcaps one at a time, extract TLS features, delete the pcap.
Only *.pcap/*.pcapng files are fetched (never the *.exe.zip samples). Resume-safe.
Usage: python -I -u scripts/fetch_mcfp.py [--max-mb 120]"""
import csv, hashlib, os, subprocess, sys, time, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ja4next.extract import extract
B = "https://mcfp.felk.cvut.cz/publicDatasets/"
max_mb = float(sys.argv[sys.argv.index("--max-mb") + 1]) if "--max-mb" in sys.argv else 9000
rows = [r for r in csv.DictReader(open("data/manifests/mcfp_mixed_normal_pcaps.csv")) if 1 <= float(r["mb"]) <= max_mb]
os.makedirs("data/raw/mcfp2", exist_ok=True); os.makedirs("data/interim/mcfp2", exist_ok=True)
man = "data/manifests/mcfp2_files.csv"
new = not os.path.exists(man)
mf = open(man, "a", newline=""); w = csv.writer(mf)
if new: w.writerow(["dir", "file", "bytes", "sha256", "date", "tls_connections"])
done = {(r["dir"], r["file"]) for r in csv.DictReader(open(man))}
for i, r in enumerate(rows):
    key = (r["dir"], r["file"])
    if key in done: continue
    dest = f"data/raw/mcfp2/{r['dir']}__{r['file']}"
    ok = False
    for a in range(3):
        rc = subprocess.run(["curl", "-s", "-f", "-C", "-", "-m", "7200", "-o", dest, f"{B}{r['dir']}/{r['file']}"],
                            stdin=subprocess.DEVNULL).returncode
        if rc == 0: ok = True; break
        time.sleep(3 * (a + 1))
    if not ok:
        print("FAILED", key, flush=True); 
        if os.path.exists(dest): os.remove(dest)
        continue
    h = hashlib.sha256()
    with open(dest, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    sha = h.hexdigest()
    try:
        df = extract(dest, "mcfp2", sha[:16])
        df["mcfp_dir"] = r["dir"]; df["pcap_name"] = r["file"]
        df.to_parquet(f"data/interim/mcfp2/{sha[:16]}.parquet", index=False); n = len(df)
    except Exception as e:
        print("extract failed", key, e, flush=True); n = -1
    w.writerow([r["dir"], r["file"], os.path.getsize(dest), sha, r["date"], n]); mf.flush()
    os.remove(dest)
    if i % 10 == 0: print(f"{i+1}/{len(rows)} {r['dir']} tls={n}", flush=True)
print("DONE", flush=True)
