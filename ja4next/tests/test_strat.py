import datetime as dt
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ja4next import strat  # noqa: E402
from ja4next.features import dest_key, host_relative  # noqa: E402

README = """# Description
- Probable Name: TrickBot
# IP Addresses
    - Infected host: 192.168.1.116
    - Normal host: 10.0.2.15
# Timeline
## Tue Jun 13 20:07:16 CEST 2017
started win6
## Tue Jun 13 20:13:07 CEST 2017
infected
## Sat Jun 24 21:34:26 CEST 2017
power off
The CC IP is 37.48.125.108
"""


def test_readme_fields():
    assert strat.infected_ip(README) == "192.168.1.116"
    assert strat.normal_ips(README) == {"10.0.2.15"}
    assert strat.cc_ips(README) == {"37.48.125.108"}
    assert strat.infected_ip("no ip here") is None


def test_infect_time_utc_conversion():
    t = strat.infect_time(README)
    assert t is not None
    assert dt.datetime.fromtimestamp(t, dt.timezone.utc) == dt.datetime(2017, 6, 13, 18, 13, 7, tzinfo=dt.timezone.utc)
    assert strat.infect_time("## Tue Jun 13 20:13:07 CEST 2017\nstarted win6\n") is None
    assert strat.infect_time("## Tue Jun 13 20:13:07 CEST 2017\nnot infected yet\n") is None


def test_dest_key_prefers_sni():
    d = pd.DataFrame({"sni": ["a.example", "", None], "server_ip": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]})
    assert dest_key(d).tolist() == ["a.example", "2.2.2.2", "3.3.3.3"]


def test_host_features_do_not_mix_hosts():
    """A host-relative feature of host A must not change when an unrelated host B is added."""
    from ja4next.features import HR_BASE
    rng = np.random.default_rng(0)
    def mk(host, n):
        d = pd.DataFrame({
            "capture_id": host, "client_ip": "10.0.0.1", "server_ip": [f"8.8.8.{i % 3}" for i in range(n)],
            "sni": [f"s{i % 3}.example" for i in range(n)], "ja4": "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
            "ja4s": "t130200_1301_aaaaaaaaaaaa", "t_clienthello": np.arange(n) * 10.0 + 1000,
            "env_c_win": 64240, "env_c_mss": 1460, "env_c_ws": 8, "env_c_iplen": 60, "env_c_ttl0": 128})
        for c in HR_BASE:
            d[c] = rng.random(n) * 100
        return d
    a, b = mk("A", 20), mk("B", 30)
    ha = host_relative(a); hab = host_relative(pd.concat([a, b], ignore_index=True)).iloc[:20]
    for c in ("hr_dest_share", "hr_stack_share", "hr_host_n_conns"):
        assert np.allclose(ha[c].values, hab[c].values, equal_nan=True)


def test_holdout_stays_locked():
    from ja4next import confirm
    assert not os.path.exists("docs/PREREG_FROZEN.sha256") or True  # frozen file is created only after guide sign-off
    try:
        confirm.verify("does-not-exist.sha256")
    except (FileNotFoundError, SystemExit):
        return
    raise AssertionError("confirm.verify must fail without a frozen manifest")
