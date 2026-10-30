"""
SMOKE TEST DATA ONLY - NOT RESULTS. Generates a synthetic instances.csv whose structure mirrors
real extracted data, so you can check the whole pipeline runs before your real PCAPs are ready.
Numbers produced from this file must NEVER appear in the report or paper.

    python scripts/make_smoke_data.py --out data/processed/SMOKE_instances.csv
"""
import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ja4lab import tlsparse as tp  # noqa: E402

R = random.Random(7)
G = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa]

STACKS = {
    "chrome": dict(grease=True, shuffle_ext=True,
                   ciphers=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
                   exts=[0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x44cd, 0xfe0d],
                   sig=[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
                   groups=[0x11ec, 0x001d, 0x0017, 0x0018], ks=[0x11ec, 0x001d], alpn=[b"h2", b"http/1.1"], win=64240, ttl=128),
    "firefox": dict(grease=False, shuffle_ext=False,
                    ciphers=[0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
                    exts=[0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0022, 0x0033, 0x002b, 0x000d, 0x002d, 0x001c, 0x001b, 0xfe0d],
                    sig=[0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201],
                    groups=[0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101], ks=[0x11ec, 0x001d, 0x0017], alpn=[b"h2", b"http/1.1"], win=64240, ttl=64),
    "schannel": dict(grease=False, shuffle_ext=False,
                     ciphers=[0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x000a],
                     exts=[0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0023, 0x0010, 0x0017, 0xff01],
                     sig=[0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601, 0x0603],
                     groups=[0x001d, 0x0017, 0x0018], ks=[], alpn=[b"h2", b"http/1.1"], win=64240, ttl=128),
    "go": dict(grease=False, shuffle_ext=True,
               ciphers=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
               exts=[0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0xff01, 0x0012, 0x0033, 0x002b, 0x0010, 0x0017, 0x002d],
               sig=[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203],
               groups=[0x001d, 0x0017, 0x0018, 0x0019], ks=[0x001d], alpn=[b"h2", b"http/1.1"], win=64240, ttl=64),
    "openssl": dict(grease=False, shuffle_ext=False,
                    ciphers=[0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b, 0xc02f, 0x009e, 0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067, 0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff],
                    exts=[0x0000, 0x000b, 0x000a, 0x0023, 0x0016, 0x0017, 0x000d, 0x002b, 0x002d, 0x0033],
                    sig=[0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
                    groups=[0x001d, 0x0017, 0x001e, 0x0019, 0x0018], ks=[0x001d], alpn=[], win=29200, ttl=64),
    "custom_c2": dict(grease=False, shuffle_ext=False,
                      ciphers=[0x0035, 0x002f, 0x000a, 0x0005, 0x0004, 0xc014, 0xc013],
                      exts=[0x0000, 0x000a, 0x000b, 0xff01],
                      sig=[], groups=[0x0017, 0x0018], ks=[], alpn=[], win=8192, ttl=128),
    "legacy_mal": dict(grease=False, shuffle_ext=False,
                       ciphers=[0xc014, 0xc013, 0x0035, 0x002f, 0x000a, 0x0038, 0x0032, 0x0013, 0x0005, 0x0004],
                       exts=[0x0000, 0x000a, 0x000b, 0x0023, 0xff01, 0x000d],
                       sig=[0x0401, 0x0201, 0x0501, 0x0601, 0x0403], groups=[0x0017, 0x0018, 0x0019], ks=[], alpn=[], win=65535, ttl=128),
}

BENIGN = [("chrome", "browser_chrome", 14), ("firefox", "browser_firefox", 10), ("schannel", "win_apps", 8),
          ("go", "go_tools", 5), ("openssl", "curl_wget", 6), ("chrome", "electron_apps", 6)]
MALICIOUS = [("custom_c2", "FamilyA", 5), ("legacy_mal", "FamilyB", 5), ("go", "FamilyC_go", 4),
             ("schannel", "FamilyD_schannel", 4), ("openssl", "FamilyE_py", 4), ("custom_c2", "FamilyF", 3)]


def mutate(stack, k):
    s = {kk: (list(v) if isinstance(v, list) else v) for kk, v in stack.items()}
    for _ in range(k):
        op = R.random()
        if op < 0.35 and len(s["ciphers"]) > 3:
            s["ciphers"].pop(R.randrange(len(s["ciphers"])))
        elif op < 0.55:
            s["ciphers"].insert(R.randrange(len(s["ciphers"]) + 1), R.choice([0x009f, 0x0039, 0xc028, 0x003c, 0x00ff, 0xc012]))
        elif op < 0.75 and len(s["exts"]) > 3:
            s["exts"].pop(R.randrange(1, len(s["exts"])))
        elif op < 0.9:
            s["exts"].append(R.choice([0x0015, 0x001c, 0x0029, 0x0031, 0x0012, 0x0016]))
        elif s["sig"]:
            s["sig"] = s["sig"][:-1]
    return s


def make_ch(s):
    ch = tp.ClientHello(legacy_version=0x0303, session_id_len=32 if 0x002b in s["exts"] else R.choice([0, 32]))
    ciphers = list(s["ciphers"]); exts = list(dict.fromkeys(s["exts"]))
    if s["shuffle_ext"]:
        R.shuffle(exts)
    if s["grease"]:
        ciphers = [R.choice(G)] + ciphers; exts = [R.choice(G)] + exts + [R.choice(G)]
    ch.ciphers, ch.extensions, ch.sig_algs = ciphers, exts, s["sig"] if 0x000d in exts else []
    ch.alpn = s["alpn"] if 0x0010 in exts else []
    if ch.alpn and 0x0010 not in exts:
        ch.alpn = []
    ch.groups = s["groups"]; ch.key_share_groups = s["ks"] if 0x0033 in exts else []
    ch.supported_versions = [0x0304, 0x0303] if 0x002b in exts else []
    ch.ec_point_formats = [0] if 0x000b in exts else []
    ch.hello_len = 200 + 2 * len(ciphers) + 30 * len(exts) + (1200 if 0x11ec in ch.key_share_groups else 0)
    return ch


def rows_for(stack_name, fam, n_fp, label, source):
    out = []
    for i in range(n_fp):
        s = mutate(STACKS[stack_name], 0 if i == 0 else R.randint(1, 3))
        for rep in range(R.randint(2, 6)):
            ch = make_ch(s)
            if 0x0000 not in ch.extensions:
                pass
            r = {"pcap": f"{label}/{source}/{fam}/cap{i}.pcap", "label": label, "source": source,
                 "family": fam, "kind": "tls", "src_ip": f"10.{hash(fam) % 200}.{i}.{rep}",
                 "ttl": s["ttl"] - R.randint(0, 3), "tcp_window": s["win"], "tcp_mss": 1460,
                 "tcp_wscale": 8, "tcp_options": "2-1-3-1-1-4", "n_conn": R.randint(1, 50)}
            r["ja4t"] = f"{s['win']}_2-1-3-1-1-4_1460_8"
            r.update(tp.ja4_from_ch(ch)); r.update(tp.ch_to_row(ch))
            sh = tp.ServerHello(legacy_version=0x0303, cipher=[c for c in ch.ciphers if not tp.is_grease(c)][0],
                                extensions=R.choice([[0xff01, 0x0017], [0xff01], [0x0017, 0xff01, 0x0023]]),
                                alpn=ch.alpn[0] if ch.alpn else b"")
            r.update(tp.ja4s_from_sh(sh)); r.update(tp.sh_to_row(sh))
            out.append(r)
    return out


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True); a = ap.parse_args()
    rows = []
    for st, fam, n in BENIGN:
        rows += rows_for(st, fam, n, "benign", R.choice(["synthA", "synthB"]))
    for st, fam, n in MALICIOUS:
        rows += rows_for(st, fam, n, "malicious", R.choice(["synthC", "synthD"]))
    import pandas as pd
    df = pd.DataFrame(rows)
    df = df.drop_duplicates(subset=["pcap", "src_ip", "ja4_ro", "ja4s_r", "ja4t"])
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(a.out, index=False)
    print(f"SMOKE data: {len(df)} instances, {df['ja4'].nunique()} unique JA4 -> {a.out}")


if __name__ == "__main__":
    main()
