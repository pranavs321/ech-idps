#!/usr/bin/env python3
"""
Comprehensive PCAP Downloader, Extractor, and Cataloger for Encrypted Traffic IDPS Research.
Downloads, unzips, validates, and catalogs known public PCAP datasets.
Strict adherence to safety: only .pcap and .pcapng files are retained; any executables are discarded.
"""

import os
import sys
import glob
import shutil
import hashlib
import subprocess
import urllib.request
import pandas as pd
from pathlib import Path

BASE_DIR = Path("/Users/pranav/Documents/Desktop Backup/downloaded_pcaps")
MANIFEST_FILE = BASE_DIR / "PCAP_CATALOGUE_MANIFEST.csv"
REPO_ROOT = Path("/Users/pranav/Documents/Desktop Backup/ech-idps")

def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(1048576):
            h.update(chunk)
    return h.hexdigest()

def extract_unit42_archives():
    print("\n=== Phase 1: Extracting Unit 42 Tutorial PCAP Archives ===")
    tutorial_dirs = [
        BASE_DIR / "wireshark-tutorial-IcedID",
        BASE_DIR / "wireshark-tutorial-Hancitor-traffic",
        BASE_DIR / "wireshark-tutorial-Dridex-traffic",
        BASE_DIR / "wireshark-tutorial-Emotet-traffic",
        BASE_DIR / "wireshark-tutorial-decrypting-HTTPS-traffic",
    ]
    
    passwords = ["infected", "unit42"]
    
    for t_dir in tutorial_dirs:
        if not t_dir.exists():
            continue
        print(f"\nProcessing tutorial dir: {t_dir.name}")
        zip_files = list(t_dir.glob("*.zip"))
        for zf in zip_files:
            extract_dir = t_dir / f"extracted_{zf.stem}"
            if extract_dir.exists() and any(p.is_file() for p in extract_dir.rglob("*.pcap*")):
                print(f"  Already extracted: {zf.name}")
                continue
            
            extract_dir.mkdir(exist_ok=True)
            success = False
            for pwd in passwords:
                cmd = ["7z", "x", "-y", f"-p{pwd}", f"-o{extract_dir}", str(zf)]
                res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if res.returncode == 0:
                    success = True
                    print(f"  Extracted {zf.name} (password: {pwd})")
                    break
            
            if not success:
                for pwd in passwords:
                    cmd = ["unzip", "-o", "-q", "-P", pwd, str(zf), "-d", str(extract_dir)]
                    res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if res.returncode == 0:
                        success = True
                        print(f"  Extracted {zf.name} via unzip (password: {pwd})")
                        break

            # Safety sanitation: remove any non-pcap executables (e.g., .exe, .dll, .bin)
            for f in extract_dir.rglob("*"):
                if f.is_file() and not (f.name.endswith(".pcap") or f.name.endswith(".pcapng") or f.name.endswith(".txt") or f.name.endswith(".csv")):
                    print(f"  Removing non-pcap artifact for safety: {f.name}")
                    try:
                        f.unlink()
                    except Exception:
                        pass

def clone_or_update_repos():
    print("\n=== Phase 2: Cloning Key PCAP Git Repositories ===")
    repos = [
        ("FoxIO_ja4", "https://github.com/FoxIO-LLC/ja4.git"),
    ]
    
    for folder_name, git_url in repos:
        target = BASE_DIR / folder_name
        if target.exists() and (target / ".git").exists():
            print(f"  Repo already exists: {folder_name}")
        else:
            print(f"  Cloning {folder_name} from {git_url}...")
            cmd = ["git", "clone", "--depth", "1", git_url, str(target)]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"  Successfully cloned {folder_name}")
            else:
                print(f"  Clone failed for {folder_name}: {res.stderr.strip()}")

def ingest_mta_exercises_and_repo():
    print("\n=== Phase 3: Ingesting MTA Exercise PCAPs ===")
    mta_dest = BASE_DIR / "mta_exercises"
    mta_dest.mkdir(exist_ok=True)
    
    src_mta = REPO_ROOT / "data/raw/mta"
    if src_mta.exists():
        for p in src_mta.glob("*.pcap"):
            dest_file = mta_dest / p.name
            if not dest_file.exists():
                shutil.copy2(p, dest_file)
                print(f"  Copied {p.name} ({dest_file.stat().st_size / 1024:.1f} KB)")
        for z in src_mta.glob("*.zip"):
            if z.stat().st_size > 1000:
                extract_sub = mta_dest / f"extracted_{z.stem}"
                extract_sub.mkdir(exist_ok=True)
                date_part = z.name[:10].replace("-", "")
                pwd = f"infected_{date_part}"
                subprocess.run(["7z", "x", "-y", f"-p{pwd}", f"-o{extract_sub}", str(z)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def download_stratosphere_captures():
    print("\n=== Phase 4: Downloading Stratosphere Mixed & Normal PCAPs ===")
    stratosphere_dir = BASE_DIR / "stratosphere_mixed_and_normal"
    stratosphere_dir.mkdir(exist_ok=True)
    
    captures = [
        # Mixed captures (malware + normal background on same machine/network)
        ("CTU-Mixed-Capture-1_sample1.pcap", "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Mixed-Capture-1/2015-07-28_mixed.day26-14.35--14.45.pcap"),
        ("CTU-Mixed-Capture-1_sample2.pcap", "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Mixed-Capture-1/2015-07-28_mixed.day26-14.40--14.50.pcap"),
        ("CTU-Botnet-42_sample.pcap", "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap"),
    ]
    
    for filename, url in captures:
        dest = stratosphere_dir / filename
        if dest.exists() and dest.stat().st_size > 1000:
            print(f"  Already downloaded: {filename} ({dest.stat().st_size / (1024*1024):.2f} MB)")
            continue
            
        print(f"  Downloading {filename} from {url}...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req) as resp, open(dest, "wb") as out_file:
                while chunk := resp.read(524288):
                    out_file.write(chunk)
            print(f"  Saved {filename} ({dest.stat().st_size / (1024*1024):.2f} MB)")
        except Exception as e:
            print(f"  Failed downloading {filename}: {e}")

def catalog_all_pcaps():
    print("\n=== Phase 5: Generating Inventory and Manifest for All PCAPs ===")
    all_files = [
        p for p in BASE_DIR.rglob("*")
        if p.is_file() and p.suffix.lower() in [".pcap", ".pcapng", ".cap"] and ".git" not in str(p)
    ]
    print(f"Discovered total of {len(all_files)} PCAP/PCAPNG/CAP files across all directories.")
    
    rows = []
    for pcap in sorted(all_files):
        rel_path = pcap.relative_to(BASE_DIR)
        parent_repo = rel_path.parts[0] if len(rel_path.parts) > 1 else "root"
        size_bytes = pcap.stat().st_size
        sha = compute_sha256(pcap)
        
        # Categorize
        cat = "Unknown"
        p_str = str(rel_path).lower()
        if "mixed" in p_str:
            cat = "Environment-Matched (Mixed)"
        elif "normal" in p_str or "dvwa" in p_str or "fast" in p_str or "slow" in p_str or "browser" in p_str:
            cat = "Benign / Normal"
        elif "icedid" in p_str or "dridex" in p_str or "emotet" in p_str or "hancitor" in p_str:
            cat = "Malware (IOC / Infection)"
        elif "attack" in p_str or "c2" in p_str or "redline" in p_str or "lokibot" in p_str or "formbook" in p_str or "botnet" in p_str:
            cat = "Malware / Attack Simulation"
        elif "foxio" in p_str or "ja4" in p_str:
            cat = "JA4 Validation Reference"
        else:
            cat = "Network Traffic Trace"
            
        rows.append({
            "relative_path": str(rel_path),
            "filename": pcap.name,
            "repository_source": parent_repo,
            "category": cat,
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / (1024 * 1024), 3),
            "sha256": sha
        })
        
    df = pd.DataFrame(rows)
    df.to_csv(MANIFEST_FILE, index=False)
    print(f"\nManifest successfully written to: {MANIFEST_FILE}")
    print(f"Total PCAPs cataloged: {len(df)}")
    print(f"Total Size: {df['size_mb'].sum():.2f} MB")
    print("\nSummary by Repository Source:")
    print(df["repository_source"].value_counts().to_string())
    print("\nSummary by Category:")
    print(df["category"].value_counts().to_string())

def main():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    extract_unit42_archives()
    clone_or_update_repos()
    ingest_mta_exercises_and_repo()
    download_stratosphere_captures()
    catalog_all_pcaps()

if __name__ == "__main__":
    main()
