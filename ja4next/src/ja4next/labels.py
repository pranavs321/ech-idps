"""Connection labels from independent, handshake-free evidence.

Tiers (column `label_tier`):
  gold_mal   analyst IOC file of the SAME capture's blog post (domain or IP),
             or abuse.ch SSLBL certificate SHA1, or Feodo Tracker C2 IP
  weak_mal   Maltrail static trail only (malware/malicious categories)
  benign     SNI under a vendor/CDN/CA allowlist AND on no IOC list
  conflict   allowlisted and on an IOC list (dropped)
  unknown    everything else (never trained on, but kept as host context)

`y` = 1 for gold_mal/weak_mal, 0 for benign, NaN otherwise.
Labels never read handshake fields (JA4, ciphers, extensions, timing).
"""
from __future__ import annotations

import csv
import gzip
import ipaddress
import os
import re

import pandas as pd

# Vendor / CDN / CA suffixes for benign-likely labels. Deliberately excludes
# cloud hosting and file-sharing suffixes that malware abuses (amazonaws.com,
# googleusercontent.com, azurewebsites.net, cloudfront.net, github*, dropbox,
# discord*, 1drv.ms, onedrive, pastebin, telegram, ipify, etc.).
ALLOW_SUFFIXES = [
    "microsoft.com", "windowsupdate.com", "update.microsoft.com", "msftconnecttest.com", "msftncsi.com",
    "live.com", "live.net", "office.com", "office.net", "office365.com", "outlook.com", "bing.com",
    "msn.com", "msedge.net", "skype.com", "microsoftonline.com", "windows.com", "windows.net",
    "msocsp.com", "msauth.net", "msftauth.net", "s-microsoft.com", "aria.microsoft.com", "xboxlive.com",
    "google.com", "gstatic.com", "googleapis.com", "google-analytics.com", "googletagmanager.com",
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "youtube.com", "ytimg.com",
    "gvt1.com", "gvt2.com", "ggpht.com",
    "mozilla.com", "mozilla.org", "mozilla.net", "firefox.com",
    "apple.com", "icloud.com", "mzstatic.com",
    "adobe.com", "adobe.io", "adobelogin.com",
    "digicert.com", "globalsign.com", "globalsign.net", "sectigo.com", "comodoca.com", "usertrust.com",
    "letsencrypt.org", "lencr.org", "identrust.com", "verisign.com", "symcd.com", "symcb.com",
    "entrust.net", "godaddy.com", "pki.goog",
    "akamaihd.net", "akamaized.net", "akamaiedge.net", "edgekey.net", "edgesuite.net",
    "facebook.com", "fbcdn.net", "twitter.com", "twimg.com", "linkedin.com", "licdn.com",
    "yahoo.com", "yimg.com", "wikipedia.org", "wikimedia.org", "avast.com", "avg.com",
]
ALLOW_RE = re.compile(r"(^|\.)(" + "|".join(re.escape(s) for s in ALLOW_SUFFIXES) + r")$", re.I)

DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
FILE_EXT = {"exe", "dll", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "zip", "rar", "js", "vbs", "jar",
            "txt", "pdf", "png", "jpg", "gif", "dat", "bin", "ps1", "hta", "lnk", "iso", "img", "msi",
            "bat", "cmd", "html", "htm", "php", "eml", "pcap", "gz", "7z", "tmp", "log", "one", "wsf",
            "chm", "cab", "scr", "rtf", "svg", "xll", "zip", "aspx", "asp", "cgi", "jsp"}


def refang(s: str) -> str:
    return (s.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace("hxxp", "http")
             .replace("[:]", ":").replace("[://]", "://"))


def load_tlds(path: str) -> set[str]:
    tlds = set()
    for line in open(path, encoding="utf-8", errors="ignore"):
        line = line.strip().lower()
        if line and not line.startswith("//"):
            tlds.add(line.rsplit(".", 1)[-1].lstrip("*!."))
    return tlds


def parse_ioc_text(text: str, tlds: set[str]) -> tuple[set[str], set[str]]:
    text = refang(text)
    doms, ips = set(), set()
    for ip in IP_RE.findall(text):
        try:
            a = ipaddress.ip_address(ip)
            if a.is_global:
                ips.add(ip)
        except ValueError:
            pass
    for d in DOMAIN_RE.findall(text):
        d = d.lower().strip(".")
        tld = d.rsplit(".", 1)[-1]
        if tld in FILE_EXT or tld not in tlds or IP_RE.fullmatch(d):
            continue
        if d.endswith("malware-traffic-analysis.net") or d.endswith("virustotal.com"):
            continue
        doms.add(d)
    return doms, ips


class Feeds:
    def __init__(self, labels_dir: str):
        self.tlds = load_tlds(os.path.join(labels_dir, "maltrail/data/public_suffix_icann.txt"))
        self.trail_dom: dict[str, str] = {}
        self.trail_ip: dict[str, str] = {}
        with gzip.open(os.path.join(labels_dir, "trails.csv.gz"), "rt", errors="ignore") as f:
            for row in csv.reader(l for l in f if not l.startswith("#")):
                if len(row) < 2:
                    continue
                trail, info = row[0].strip().lower(), row[1]
                if not ("(malware)" in info or "(malicious)" in info):
                    continue
                if "/" in trail.rstrip("/"):
                    continue  # URL trails need HTTP paths, not available for TLS
                trail = trail.rstrip("/")
                host = trail.split(":")[0]
                if IP_RE.fullmatch(host):
                    self.trail_ip[host] = info
                elif "." in host:
                    self.trail_dom[host] = info
        # shared CDN address space: an IP trail there says nothing about one connection
        self.cdn_nets = []
        cdn = os.path.join(labels_dir, "maltrail/data/cdn_ranges.txt")
        if os.path.exists(cdn):
            for line in open(cdn, errors="ignore"):
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        self.cdn_nets.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        pass
        wl = os.path.join(labels_dir, "maltrail/data/whitelist.txt")
        self.mt_whitelist = {l.strip().lower() for l in open(wl, errors="ignore")
                             if l.strip() and not l.startswith("#")} if os.path.exists(wl) else set()
        self.sslbl_sha1 = {}
        p = os.path.join(labels_dir, "sslbl.abuse.ch_blacklist_sslblacklist.csv")
        for line in open(p, errors="ignore"):
            if line.startswith("#"):
                continue
            parts = line.strip().split(",")
            if len(parts) >= 3:
                self.sslbl_sha1[parts[1].lower()] = parts[2]
        self.feodo = {}
        p = os.path.join(labels_dir, "feodotracker.abuse.ch_downloads_ipblocklist_aggressive.csv")
        for line in open(p, errors="ignore"):
            if line.startswith("#") or not line.strip():
                continue
            parts = [x.strip('"') for x in line.strip().split(",")]
            if len(parts) >= 2 and IP_RE.fullmatch(parts[1]):
                self.feodo[parts[1]] = parts[-1] if len(parts) > 4 else "feodo"

    def is_cdn(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.cdn_nets if n.version == a.version)

    def trail_domain_hit(self, sni: str) -> str | None:
        if not sni:
            return None
        parts = sni.lower().split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in self.mt_whitelist:
                return None
            if cand in self.trail_dom:
                return self.trail_dom[cand]
        return None


def _dom_match(sni: str, doms: set[str]) -> bool:
    if not sni:
        return False
    s = sni.lower()
    return any(s == d or s.endswith("." + d) for d in doms)


def label_frame(df: pd.DataFrame, feeds: Feeds, ioc_by_capture: dict[str, tuple[set, set]],
                page_by_capture: dict[str, tuple[set, set]] | None = None) -> pd.DataFrame:
    """ioc_by_capture: analyst IOC *files*; page_by_capture: IOCs named on the blog post page."""
    page_by_capture = page_by_capture or {}
    tiers, why = [], []
    for cap, sni, sip, sha1 in zip(df["capture_id"], df["sni"].fillna(""), df["server_ip"],
                                   df.get("cert_sha1", pd.Series([""] * len(df))).fillna("")):
        doms, ips = ioc_by_capture.get(cap, (set(), set()))
        gold = []
        if _dom_match(sni, doms):
            gold.append("mta_ioc_domain")
        if sip in ips:
            gold.append("mta_ioc_ip")
        pdoms, pips = page_by_capture.get(cap, (set(), set()))
        if _dom_match(sni, pdoms) or sip in pips:
            gold.append("mta_page")
        if sha1 and sha1 in feeds.sslbl_sha1:
            gold.append("sslbl_cert:" + feeds.sslbl_sha1[sha1])
        if sip in feeds.feodo:
            gold.append("feodo_ip")
        weak = []
        t = feeds.trail_domain_hit(sni)
        if t:
            weak.append("maltrail_dom:" + t)
        if sip in feeds.trail_ip and not feeds.is_cdn(sip):
            weak.append("maltrail_ip:" + feeds.trail_ip[sip])
        allow = bool(sni) and bool(ALLOW_RE.search(sni))
        if allow and (gold or weak):
            tiers.append("conflict")
        elif gold:
            tiers.append("gold_mal")
        elif weak:
            tiers.append("weak_mal")
        elif allow:
            tiers.append("benign")
        else:
            tiers.append("unknown")
        why.append(";".join(gold + weak) or ("allowlist" if allow else ""))
    df = df.copy()
    df["label_tier"] = tiers
    df["label_evidence"] = why
    df["y"] = df["label_tier"].map({"gold_mal": 1.0, "weak_mal": 1.0, "benign": 0.0})
    return df
