"""
Correctness check: compare OUR extractor with FoxIO's reference implementation (python/ja4.py,
which uses tshark's reassembly) on FoxIO's own test pcaps. Put this table in the paper's
"Implementation / validation" section.

    bash scripts/get_foxio_reference.sh          # downloads FoxIO repo into third_party/
    python tests/validate_against_foxio.py

JA4T is not in FoxIO's python tool; it is cross-checked against the `ja4plus` package instead.
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ja4lab.extract import process_pcap  # noqa: E402

REF = Path(__file__).resolve().parents[1] / "third_party" / "ja4-main"
PCAPS = sorted((REF / "pcap").glob("*.pcap*"))


def foxio(pcap: Path) -> dict:
    out = subprocess.run(["python3", "ja4.py", str(pcap), "-J"], cwd=REF / "python",
                         capture_output=True, text=True, timeout=300).stdout
    dec, i, res = json.JSONDecoder(), 0, {}
    while True:
        j = out.find("{", i)
        if j < 0:
            break
        try:
            obj, i = dec.raw_decode(out, j)
        except json.JSONDecodeError:
            i = j + 1
            continue
        if "srcport" not in obj:
            continue
        k = (obj.get("src"), str(obj.get("srcport")), obj.get("dst"), str(obj.get("dstport")))
        res.setdefault(k, {}).update(obj)
    return res


def ja4plus_ja4t(pcap: Path) -> set:
    try:
        from scapy.all import rdpcap
        from ja4plus import JA4TFingerprinter
    except ImportError:
        return set()
    fp, out = JA4TFingerprinter(), set()
    try:
        for p in rdpcap(str(pcap)):
            r = fp.process_packet(p)
            if r:
                out.add(r)
    except Exception:
        pass
    return out


def main():
    if not PCAPS:
        sys.exit("Run scripts/get_foxio_reference.sh first")
    tot = {"ja4": [0, 0], "ja4s": [0, 0], "ja4h": [0, 0], "ja4t": [0, 0]}
    mism = []
    for p in PCAPS:
        rows, _ = process_pcap(str(p), {"pcap": p.name})
        ref = foxio(p)
        ours = {(r["src_ip"], str(r["src_port"]), r["dst_ip"], str(r["dst_port"])): r for r in rows}
        for k, o in ref.items():
            if k not in ours:
                continue
            r = ours[k]
            for ours_key, ref_key in (("ja4", "JA4.1"), ("ja4s", "JA4S"), ("ja4h", "JA4H")):
                if ref_key in o:
                    tot[ours_key][1] += 1
                    if r.get(ours_key) == o[ref_key]:
                        tot[ours_key][0] += 1
                    else:
                        mism.append((p.name, ours_key, o[ref_key], r.get(ours_key)))
        ref_t = ja4plus_ja4t(p)
        for r in rows:
            if r.get("ja4t") and ref_t:
                tot["ja4t"][1] += 1
                tot["ja4t"][0] += int(r["ja4t"] in ref_t)
        missed = [k for k, o in ref.items() if "JA4.1" in o and k not in ours]
        if missed:
            mism.append((p.name, "missed_connections", len(missed), ""))
    print("\n=== Agreement with reference implementations ===")
    for k, (ok, n) in tot.items():
        print(f"{k:5s}: {ok}/{n} match" + (f"  ({100*ok/n:.1f}%)" if n else ""))
    if mism:
        print("\nMismatches (inspect these; some are known reference-tool quirks, see README):")
        for m in mism[:40]:
            print("  ", m)


if __name__ == "__main__":
    main()
