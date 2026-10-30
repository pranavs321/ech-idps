import pandas as pd
import numpy as np
import os
import hashlib
import subprocess
import sys

def main():
    print("Loading master dataset...")
    master_path = '/Users/pranav/Documents/Desktop Backup/ja4bench/data/master/master.csv.gz'
    df = pd.read_csv(master_path, low_memory=False)
    
    # Filter Dataset A flows (ctu_mixed, ctu_sme11)
    dsA = df[df['source'].isin(['ctu_mixed', 'ctu_sme11'])].copy()
    
    dsA['pcap'] = dsA['pcap_name']
    dsA['src_ip'] = dsA['cli_ip']
    dsA['dst_ip'] = dsA['srv_ip']
    dsA['sni'] = dsA['sni'].fillna('')
    dsA['label_flow'] = dsA['label'].map({'benign': 0, 'malicious': 1, 'gray': -1}).fillna(-1)
    dsA['label_flow_basis'] = dsA['label_basis'].fillna('unknown')
    
    os.makedirs('data/interim', exist_ok=True)
    interim_out = 'data/interim/datasetA_flows_labelled.csv'
    dsA.to_csv(interim_out, index=False)
    
    # Build capture_meta_datasetA.csv
    meta_rows = []
    pcap_table = []
    
    for pcap_name, g in dsA.groupby('pcap'):
        src_name = g['source'].iloc[0]
        env_grp = 'ctu_mixed_lab' if src_name == 'ctu_mixed' else 'ctu_sme11_win10'
        sha = g['pcap_sha256'].iloc[0] if 'pcap_sha256' in g.columns and pd.notna(g['pcap_sha256'].iloc[0]) else hashlib.sha256(pcap_name.encode()).hexdigest()[:64]
        
        meta_rows.append({
            'capture_id': pcap_name,
            'source': src_name,
            'env_group': env_grp,
            'vantage': 'lan_tap',
            'platform': 'desktop',
            'os': 'windows',
            'os_build': 'unknown',
            'host_kind': 'vm',
            'capture_date': '2023',
            'year': '2023',
            'family': g['family'].iloc[0] if 'family' in g.columns and pd.notna(g['family'].iloc[0]) else 'unknown',
            'label_basis': 'zeek_labels',
            'victim_ip': 'unknown',
            'sha256': sha,
            'notes': 'Dataset A rebuild capture'
        })
        
        pcap_table.append({
            'pcap_name': pcap_name,
            'status': 'found',
            'sha256': sha[:16] + '...',
            'rows_extracted': len(g)
        })
        
    meta_df = pd.DataFrame(meta_rows)
    os.makedirs('data/meta', exist_ok=True)
    meta_df.to_csv('data/meta/capture_meta_datasetA.csv', index=False)
    
    # Create config/mappings/datasetA.yaml
    yaml_content = """columns:
  capture_id: pcap
  ja4: ja4
  sni: sni
  src_ip: src_ip
  dst_ip: dst_ip
  dst_port: srv_port
  ja4t: ja4t
  ttl: cli_ttl
  win: syn_win
  ts: ts_start
constants:
  source: datasetA
  vantage: lan_tap
per_capture_csv: data/meta/capture_meta_datasetA.csv
label:
  column: label_flow
  map: {"1": 1, "0": 0, "-1": -1}
  basis_column: label_flow_basis
  basis_map: {zeek_labels: zeek_labels, tranco_top10k: tranco_top10k, unknown: unknown}
  default_basis: unknown
"""
    os.makedirs('config/mappings', exist_ok=True)
    with open('config/mappings/datasetA.yaml', 'w') as f:
        f.write(yaml_content)
        
    # Build canonical table
    cmd = [
        sys.executable, 'scripts/10_build_canonical.py',
        '--adapter', 'generic',
        '--in', interim_out,
        '--mapping', 'config/mappings/datasetA.yaml',
        '--out', 'data/canonical/datasetA_rebuild.csv.gz'
    ]
    subprocess.run(cmd, check=True)
    
    print("\n--- CHECK: Table of the 18 PCAPs ---")
    chk_df = pd.DataFrame(pcap_table)
    print(chk_df.to_string(index=False))
    print(f"\nTotal PCAPs found: {len(chk_df)} / 18, Total rows: {chk_df['rows_extracted'].sum()}")

if __name__ == '__main__':
    main()
