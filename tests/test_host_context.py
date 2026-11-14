"""python3 tests/test_host_context.py"""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from idps.features import INDEX_BY_NAME, N_FEATURES  # noqa: E402
from idps.module2_sensor.extractor import FlowRecord  # noqa: E402
from idps.module2_sensor.host_context import (CONTEXT_NAMES, N_CONTEXT,  # noqa: E402
                                               host_context)


def _rec(src, dst, t, size=500.0, stack="t12_a_b"):
    v = np.zeros(N_FEATURES, dtype=np.float32)
    v[INDEX_BY_NAME["mean_pkt_size"]] = size
    return FlowRecord(features=v, declared="chrome", declared_confidence=1.0,
                      stack=stack, src_ip=src, dst_ip=dst, dst_port=443, start_ts=t)


def _col(name):
    return CONTEXT_NAMES.index(name)


def test_shapes_and_no_addresses():
    recs = [_rec("10.0.0.1", f"1.1.1.{i % 3}", float(i)) for i in range(9)]
    c = host_context(recs)
    assert c.shape == (9, N_CONTEXT) and np.isfinite(c).all()
    assert not any("ip" in n or "port" in n for n in CONTEXT_NAMES)


def test_dest_share_and_beacon():
    recs = [_rec("10.0.0.1", "9.9.9.9", 60.0 * i) for i in range(8)]        # beacon
    recs += [_rec("10.0.0.1", f"1.1.1.{i}", 7.0 * i * i) for i in range(4)]  # browsing
    c = host_context(recs)
    assert abs(c[0, _col("dest_share")] - 8 / 12) < 1e-6
    assert c[0, _col("beacon_periodicity")] == 1.0
    assert c[8, _col("beacon_periodicity")] == 0.0


def test_host_constant_scale_cancels():
    """A different MTU/path scales one host's sizes; its relative features must not move."""
    sizes = [100, 120, 140, 900, 110, 130]
    a = [_rec("10.0.0.1", f"1.1.1.{i}", float(i), s) for i, s in enumerate(sizes)]
    b = [_rec("10.0.0.2", f"1.1.1.{i}", float(i), s * 1.4) for i, s in enumerate(sizes)]
    c = host_context(a + b)
    j = _col("z_host_mean_pkt_size")
    assert np.allclose(c[:6, j], c[6:, j], atol=0.05)
    assert c[3, j] > 5          # the outlier stands out on both hosts


def test_causal_uses_only_the_past():
    recs = [_rec("10.0.0.1", "9.9.9.9", 60.0 * i) for i in range(6)]
    full = host_context(recs, causal=True)
    part = host_context(recs[:3], causal=True)
    assert np.allclose(full[:3], part)       # later connections change nothing earlier
    assert full[0, _col("beacon_periodicity")] == 0.0 and full[5, _col("beacon_periodicity")] == 1.0


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print("PASS", name)
            except Exception as e:  # noqa: BLE001
                fails += 1; print("FAIL", name, repr(e))
    sys.exit(1 if fails else 0)
