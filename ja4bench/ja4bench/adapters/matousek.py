"""Adapter: Matousek, Rysavy, Burgetova (CNSM 2024) JA4+ corpus -> canonical table.

Source: https://github.com/matousp/malware-analysis  (datasets/*.csv, ';'-separated)
Provenance facts recorded from the dataset README (not guessed):
  - desktop malware: run in the Tria.ge sandbox (samples from MalwareBazaar)
  - desktop apps:    Windows applications captured with tshark on a lab machine
  - mobile apps + mobile malware: run on Android Virtual Devices by the HashApp tool
  - Type column: 0 = normal application, M = malware, A = advertising/analytics server

Labels are copied as published (label_basis=source_asserted). We do NOT relabel. Rows whose SNI is
an operating-system / browser background domain get flag_os_background=1 so that the effect of the
host-level labelling can be measured as a separate, pre-registered variant.
"""
from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd

SOURCE = "matousek2024"

FILES = {
    "desktop-malware.csv": dict(platform="desktop", os="windows", env_group="triage_sandbox_windows",
                                vantage="sandbox_gateway"),
    "desktop-apps.csv": dict(platform="desktop", os="windows", env_group="but_lab_windows",
                             vantage="host"),
    "mobile-malware.csv": dict(platform="mobile", os="android", env_group="hashapp_avd_android",
                               vantage="host"),
    "mobile-apps.csv": dict(platform="mobile", os="android", env_group="hashapp_avd_android",
                            vantage="host"),
}

# Background domains contacted by Windows/Edge/Chrome/Android themselves, independent of any sample.
# Kept short and explicit on purpose; extend only with a commit message explaining why.
OS_BACKGROUND_SUFFIXES = (
    "bing.com", "bing.net", "microsoft.com", "windowsupdate.com", "msftconnecttest.com",
    "msftncsi.com", "live.com", "office.net", "office.com", "msn.com", "windows.com",
    "microsoftonline.com", "skype.com", "digicert.com", "gvt1.com", "gvt2.com",
    "googleapis.com", "gstatic.com", "android.com", "connectivitycheck.gstatic.com",
)

_TRIAGE_ID = re.compile(r"/(\d{2})(\d{2})(\d{2})-[0-9a-z]+\.behavioral", re.I)


def _norm_cols(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [c.replace(" ", "").replace("_", "_") for c in df.columns]
    return df


def _year_from_filename(fn: str) -> tuple[int, str]:
    m = _TRIAGE_ID.search(str(fn))
    if m:
        return 2000 + int(m.group(1)), "triage_task_id"
    return 2024, "paper_year_assumed"


def _is_bg(sni: str) -> int:
    s = str(sni).lower().strip(".")
    if not s or s == "nan":
        return 0
    return int(any(s == suf or s.endswith("." + suf) for suf in OS_BACKGROUND_SUFFIXES))


def load(folder: str | Path) -> pd.DataFrame:
    folder = Path(folder)
    frames = []
    for fname, meta in FILES.items():
        path = folder / fname
        if not path.exists():
            raise FileNotFoundError(f"{path} not found; run scripts/00_fetch_matousek.sh first")
        raw = _norm_cols(pd.read_csv(path, sep=";", low_memory=False, dtype=str))
        out = pd.DataFrame(index=raw.index)
        out["source"] = SOURCE
        out["file"] = fname
        # 1,713 published rows have no Filename, so their capture is unknown. They cannot be split
        # capture-disjointly; we keep them (labels untouched) but flag them so runs can drop them.
        no_fn = raw["Filename"].isna()
        fn = raw["Filename"].fillna("NO_FILENAME").str.replace("-extracted.csv", "", regex=False)
        out["capture_id"] = SOURCE + ":" + fname + ":" + fn
        out["flag_no_capture_id"] = no_fn.astype("int64")
        for k, v in meta.items():
            out[k] = v
        yb = fn.map(_year_from_filename)
        out["year"] = yb.map(lambda t: t[0]).astype("int64")
        out["year_basis"] = yb.map(lambda t: t[1])
        out["family"] = raw["AppName"].fillna("unknown").str.strip().str.lower()
        t = raw["Type"].fillna("").str.strip()
        out["label"] = np.select([t.eq("M"), t.eq("0")], [1, 0], default=-1).astype("int64")
        out["label_basis"] = np.select([t.isin(["M", "0"]), t.eq("A")],
                                       ["source_asserted", "ads"], default="unknown")
        out["ja4"] = raw["JA4hash"].str.strip()
        out["proto"] = out["ja4"].str[0].map({"t": "tcp", "q": "quic", "d": "dtls"}).fillna("unknown")
        out["sni"] = raw.get("SNI")
        out["src_ip"] = raw.get("SrcIP")
        out["dst_ip"] = raw.get("DstIP")
        out["src_port"] = pd.to_numeric(raw.get("SrcPort"), errors="coerce")
        out["dst_port"] = pd.to_numeric(raw.get("DstPort"), errors="coerce")
        out["ja3"] = raw.get("JA3hash")
        out["ja4s"] = raw.get("JA4Shash")
        out["ja4_r"] = raw.get("JA4_raw")
        out["cipher_list"] = raw.get("ClientCipherSuite")
        out["ext_list"] = raw.get("ClientExtensions")
        out["flag_os_background"] = out["sni"].map(_is_bg).astype("int64")
        frames.append(out)
    df = pd.concat(frames, ignore_index=True)
    df = df[df["ja4"].notna() & (df["ja4"] != "")].reset_index(drop=True)
    df.insert(0, "row_id", np.arange(len(df)))
    return df
