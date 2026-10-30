"""Core tests. Run: .venv/bin/python tests/run_tests.py  (no pytest needed)."""
import numpy as np
import pandas as pd

from ja4bench.features import FeatureBuilder
from ja4bench.ja4parse import decompose
from ja4bench.metrics import bootstrap_ci, capture_table, flow_metrics
from ja4bench.models import LookupBaseline
from ja4bench.protocols import Fold, Skip, generate


def _toy(n_caps=40, rows=10, seed=0):
    rng = np.random.default_rng(seed)
    recs = []
    for c in range(n_caps):
        lab = c % 2
        env = "envA" if c < n_caps // 2 else "envB"
        if c >= 3 * n_caps // 4:
            env = "envC_only_mal" if lab else "envD_only_ben"
        fam = f"fam{c % 7}" if lab else f"app{c % 5}"
        for r in range(rows):
            j = f"t13d15{rng.integers(10, 17)}h2_{'aaaa' if lab else 'bbbb'}{rng.integers(0, 4)}cccccccc_dddd{rng.integers(0,6)}eeeeeeee"
            recs.append(dict(capture_id=f"cap{c}", label=lab, env_group=env, family=fam, ja4=j,
                             platform="desktop" if c % 4 < 2 else "mobile", source="toy",
                             year=2023 + (c % 3), proto="tcp", src_ip=f"10.0.{c % 3}.5"))
    return pd.DataFrame(recs)


def test_parse_known_fingerprint():
    d = decompose(pd.Series(["t13d1516h2_8daaf6152771_02713d6af862", "garbage"]))
    r = d.iloc[0]
    assert r.a_ok == 1 and r.a_proto == "t" and r.a_ver == 1.3 and r.a_sni == 1.0
    assert r.a_nciph == 15 and r.a_next == 16 and r.a_alpn == "h2"
    assert r.ja4_b == "8daaf6152771" and r.ja4_c == "02713d6af862"
    assert d.iloc[1].a_ok == 0


def test_capture_disjoint():
    df = _toy()
    for f in generate(df, "P2_capture"):
        assert isinstance(f, Fold)
        assert not set(df.capture_id.iloc[f.train]) & set(df.capture_id.iloc[f.test])


def test_ja4_disjoint():
    df = _toy()
    folds = [f for f in generate(df, "P3_ja4") if isinstance(f, Fold)]
    assert folds
    for f in folds:
        assert not set(df.ja4.iloc[f.train]) & set(df.ja4.iloc[f.test])


def test_family_disjoint():
    df = _toy()
    for f in generate(df, "P4_family"):
        if isinstance(f, Fold):
            assert not set(df.family.iloc[f.train]) & set(df.family.iloc[f.test])


def test_env_matched_only_uses_mixed_envs():
    df = _toy()
    used = set()
    for f in generate(df, "P8_env_matched"):
        assert isinstance(f, Fold)
        used |= set(df.env_group.iloc[np.r_[f.train, f.test]])
    assert used == {"envA", "envB"}


def test_skip_when_single_class():
    df = _toy()
    df = df[df.label == 1]
    out = list(generate(df.reset_index(drop=True), "P2_capture"))
    assert out and all(isinstance(f, Skip) for f in out)


def test_vocab_is_train_only():
    df = _toy()
    tr, te = df.iloc[:200], df.iloc[200:].copy()
    te["ja4"] = "t13d1516h2_ffffffffffff_ffffffffffff"
    X = FeatureBuilder("ja4_components").fit(tr).transform(te)
    assert X["ja4_b=__other__"].eq(1).all() and X["ja4_c=__other__"].eq(1).all()
    assert not any("ffffffffffff" in c for c in X.columns)


def test_lookup_unseen_gets_prior():
    lk = LookupBaseline().fit(pd.Series(["a", "a", "b"]), np.array([1, 1, 0]))
    p, seen = lk.predict_proba(pd.Series(["a", "zzz"]))
    assert p[0] == 1.0 and abs(p[1] - 2 / 3) < 1e-9 and list(seen) == [True, False]


def test_metrics_and_bootstrap():
    y = np.array([0, 0, 1, 1, 0, 1]); p = np.array([.1, .6, .8, .9, .2, .4])
    m = flow_metrics(y, p)
    assert 0 <= m["roc_auc"] <= 1 and abs(m["fpr"] - 1 / 3) < 1e-9
    ci = bootstrap_ci(y, p, np.array(list("aabbcc")), n_boot=50)
    assert ci["boot_ok"] > 0
    ct = capture_table(pd.DataFrame({"capture_id": list("aabbcc"), "label": y, "score": p}))
    assert ct.set_index("capture_id").loc["a", "any_flagged"]
