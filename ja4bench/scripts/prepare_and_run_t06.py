import pandas as pd
import numpy as np
import os
import glob
import re
import subprocess
import sys

sys.path.insert(0, '.')
from ja4bench.adapters.matousek import OS_BACKGROUND_SUFFIXES

def main():
    print("Loading master dataset...")
    master_path = '/Users/pranav/Documents/Desktop Backup/ja4bench/data/master/master.csv.gz'
    df = pd.read_csv(master_path, low_memory=False)
    
    # Filter for 2023-2024 MTA flows
    mta = df[df['source'].isin(['mta', 'mta_blog']) & df['capture_year'].isin([2023, 2024])].copy()
    print(f"Total MTA 2023-2024 flows: {len(mta)} across {mta['capture_id'].nunique()} captures.")
    
    # Prepare connections.csv
    conn = mta.copy()
    conn['pcap'] = conn['capture_id']
    conn['src_ip'] = conn['cli_ip']
    conn['dst_ip'] = conn['srv_ip']
    conn['sni'] = conn['sni'].fillna('')
    
    os.makedirs('data/interim', exist_ok=True)
    conn_out = 'data/interim/connections.csv'
    conn.to_csv(conn_out, index=False)
    print(f"Wrote {conn_out} with {len(conn)} rows.")
    
    # Prepare infected_hosts.csv
    hosts_rows = []
    
    for cap, g in conn.groupby('pcap'):
        local_ips = [ip for ip in g['src_ip'].unique() if isinstance(ip, str) and (ip.startswith('10.') or ip.startswith('172.16.') or ip.startswith('192.168.'))]
        victim_ip = local_ips[0] if local_ips else g['src_ip'].mode()[0]
        
        mal_g = g[g['label'] == 'malicious']
        c2_ips = set(mal_g['dst_ip'].dropna().unique())
        c2_snis = set(mal_g['sni'].dropna().unique())
        
        if not c2_ips and not c2_snis:
            for _, row in g.iterrows():
                sni = str(row['sni']).lower()
                dst = str(row['dst_ip'])
                if sni and not any(sni.endswith(bg) for bg in OS_BACKGROUND_SUFFIXES):
                    c2_snis.add(sni)
                elif not sni and dst != victim_ip and not dst.startswith('10.') and not dst.startswith('172.16.'):
                    c2_ips.add(dst)
                    
        c2_matched = ";".join(list(c2_ips) + list(c2_snis))
        
        hosts_rows.append({
            'path': cap,
            'ioc_victim_ip': victim_ip,
            'ioc_c2_matched': c2_matched if c2_matched else 'none'
        })
        
    hosts_df = pd.DataFrame(hosts_rows)
    os.makedirs('data/meta', exist_ok=True)
    hosts_out = 'data/meta/infected_hosts.csv'
    hosts_df.to_csv(hosts_out, index=False)
    print(f"Wrote {hosts_out} with {len(hosts_df)} hosts.")
    
    # Run 15_flow_labels_from_iocs.py
    cmd = [
        sys.executable, 'scripts/15_flow_labels_from_iocs.py',
        '--flows', conn_out,
        '--capture-col', 'pcap',
        '--src-col', 'src_ip',
        '--dst-col', 'dst_ip',
        '--sni-col', 'sni',
        '--hosts', hosts_out,
        '--hosts-capture-col', 'path',
        '--victim-col', 'ioc_victim_ip',
        '--c2-col', 'ioc_c2_matched',
        '--out', 'data/interim/mta2024_flows_labelled.csv'
    ]
    print("Running labeling script...")
    res = subprocess.run(cmd, capture_output=True, text=True)
    print(res.stdout)
    if res.stderr:
        print("STDERR:", res.stderr)

if __name__ == '__main__':
    main()
