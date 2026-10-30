import pandas as pd
import os

def build_mta2024_meta():
    labelled_path = 'data/interim/mta2024_flows_labelled.csv'
    df = pd.read_csv(labelled_path, low_memory=False)
    
    unique_caps = df['pcap'].unique()
    
    rows = []
    for cap in unique_caps:
        cap_str = str(cap)
        year = '2024'
        if cap_str.startswith('2023'):
            year = '2023'
        elif cap_str.startswith('2025'):
            year = '2025'
            
        rows.append({
            'capture_id': cap_str,
            'source': 'mta2024',
            'env_group': 'mta_ad_lab_win10_2024',
            'vantage': 'lan_tap',
            'platform': 'desktop',
            'os': 'windows',
            'os_build': 'unknown',
            'host_kind': 'vm',
            'capture_date': cap_str[:10] if len(cap_str) >= 10 else year,
            'year': year,
            'family': 'unknown',
            'label_basis': 'mta_ioc',
            'victim_ip': 'unknown',
            'sha256': 'unknown',
            'notes': 'MTA capture'
        })
        
    meta_df = pd.DataFrame(rows)
    os.makedirs('data/meta', exist_ok=True)
    out_path = 'data/meta/capture_meta_mta2024.csv'
    meta_df.to_csv(out_path, index=False)
    print(f"Created {out_path} with {len(meta_df)} captures.")

if __name__ == '__main__':
    build_mta2024_meta()
