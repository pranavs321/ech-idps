import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ja4next.extract import ja4_from_raw, ja4s_from_raw, ja4t_from_raw, is_grease  # noqa: E402
from ja4next.labels import parse_ioc_text, refang, ALLOW_RE  # noqa: E402
from ja4next.features import host_relative  # noqa: E402
from ja4next.crawl_mta import classify  # noqa: E402


def test_grease():
    assert is_grease(0x0A0A) and is_grease(0xFAFA) and not is_grease(0x1301)


def test_ja4_chrome_reference():
    # FoxIO tls-handshake.pcapng stream 0
    ja4, _, _ = ja4_from_raw(
        "0x0303", "0x0a0a,0x0304,0x0303",
        "0xaaaa,0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0xc013,0xc014,0x009c,0x009d,0x002f,0x0035",
        "39578,65281,51,45,5,17513,13,16,35,27,43,0,18,10,23,11,27242,21",
        "0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601", "h2,http/1.1")
    assert ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"


def test_ja4_sigalgs_only_from_ext13():
    # delegated_credentials (34) list precedes signature_algorithms (13); only 13 counts
    ja4, raw, _ = ja4_from_raw("0x0303", "0x0304,0x0303", "0x1301", "0,34,13", "0x0403,0x0503,0x0804,0x0805",
                               "", sig_lens="4,4")
    assert raw.endswith("_000d,0022_0804,0805")


def test_ja4s_and_ja4t():
    s, _ = ja4s_from_raw("0x0303", "0x0304", "0x1301", "51,43", "")
    assert s.startswith("t130200_1301_")
    assert ja4t_from_raw("64240", "2,1,3,1,1,4", "1460", "8") == "64240_2-1-3-1-1-4_1460_8"


def test_ioc_parse_refang_and_filters():
    tlds = {"com", "org", "net"}
    txt = "- 78.101.199[.]138 port 995 - hxxps://bad-domain[.]com/x\n- File name: invoice.xls\n- 10.0.0.5 internal\n- rundll32.exe"
    doms, ips = parse_ioc_text(txt, tlds)
    assert "bad-domain.com" in doms and "78.101.199.138" in ips
    assert "10.0.0.5" not in ips and not any(d.endswith(".xls") or d.endswith(".exe") for d in doms)
    assert refang("a[.]b") == "a.b"


def test_allowlist_excludes_abused_hosting():
    assert ALLOW_RE.search("settings-win.data.microsoft.com")
    assert not ALLOW_RE.search("bucket.s3.amazonaws.com")
    assert not ALLOW_RE.search("doc-0s.googleusercontent.com")
    assert not ALLOW_RE.search("evilmicrosoft.com")


def test_crawl_never_lists_samples():
    assert classify("2020-12-15-malware-from-Qakbot-infection.zip") is None
    assert classify("2020-12-15-Qakbot-infection-part-1.pcap.zip") == "pcap"
    assert classify("2020-12-15-Qakbot-with-Cobalt-Strike-IOCs.txt.zip") == "ioc"


def test_host_relative_cancels_host_constant_shift():
    """Adding a constant to one host's sizes (a different MTU/path) must not change its z-ranks."""
    base = dict(capture_id="c", client_ip="10.0.0.1", ja4="t12d", sni="", server_ip="1.1.1.1", ja4s="",
                t_clienthello=0.0, env_c_win=64240, env_c_ws=8, env_c_mss=1460, env_c_iplen=52, env_c_ttl0=128)
    rows = []
    for host, shift in (("10.0.0.1", 0), ("10.0.0.2", 500)):
        for i, v in enumerate([100, 120, 140, 1000]):
            r = dict(base, client_ip=host, t_clienthello=float(i))
            for c in ("b_bytes_up", "b_bytes_down", "b_byte_ratio", "b_up_frac", "b_mean_up", "b_mean_down",
                      "b_dir_changes", "b_med_gap_rtt", "duration", "n_pkts_total", "b_n_up", "b_n_down",
                      "b_splt_0", "b_splt_1", "b_splt_2", "b_splt_3"):
                r[c] = v + shift
            rows.append(r)
    hr = host_relative(pd.DataFrame(rows))
    a = hr["hr_rank_host_b_bytes_up"].values
    assert list(a[:4]) == list(a[4:])
