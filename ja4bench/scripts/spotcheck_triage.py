import numpy as np
import pandas as pd
import urllib.request
import re
import json
import os

def spotcheck():
    df = pd.read_csv('data/canonical/matousek2024.csv.gz')
    bg_caps = df.groupby('capture_id').filter(lambda g: g['flag_os_background'].all())['capture_id'].unique()
    bg_caps.sort()
    
    np.random.seed(42)
    sampled_caps = np.random.choice(bg_caps, 20, replace=False)
    
    rows = []
    non_bg_c2_count = 0
    
    for cap_id in sampled_caps:
        # Extract task_id (e.g. 240524-tnhclabh96 from capture_id string)
        # capture_id format: matousek2024:desktop-malware.csv:tests/malware2/RACCOON/240524-tnhclabh96.behavioral2
        match = re.search(r'([0-9]{6}-[a-z0-9]+)', cap_id)
        task_id = match.group(1) if match else None
        
        family = "unknown"
        c2s = []
        is_google_ms = True
        
        if task_id:
            url = f'https://tria.ge/{task_id}'
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                html = urllib.request.urlopen(req).read().decode('utf-8', errors='ignore')
                
                # Extract family tag or og:title
                tag_match = re.search(r'tags:\s*\[(.*?)\]', html)
                if tag_match:
                    tags = tag_match.group(1)
                    fam_match = re.search(r'family:([a-zA-Z0-9_\-]+)', tags)
                    if fam_match:
                        family = fam_match.group(1)
                
                if family == "unknown":
                    og_title = re.search(r'<meta name="og:title" content="([^\|]+)', html)
                    if og_title:
                        family = og_title.group(1).strip()
                
                # Check for C2 URLs or domain indicators in page
                # Parse signatures for C2 / network domains
                domains = re.findall(r'https?://([a-zA-Z0-9\.\-]+)', html)
                domains = [d for d in domains if not any(kw in d for kw in ['tria.ge', 'jsdelivr.net', 'w3.org', 'google.com', 'microsoft.com', 'schema.org'])]
                if domains:
                    c2s = list(set(domains))
                    is_google_ms = False
                    non_bg_c2_count += 1
            except Exception as e:
                print(f"Error fetching {task_id}: {e}")
        
        rows.append({
            'capture_id': cap_id,
            'task_id': task_id,
            'family': family,
            'c2_list': ";".join(c2s) if c2s else "none",
            'is_google_or_ms_only': is_google_ms
        })
        
    res_df = pd.DataFrame(rows)
    os.makedirs('results', exist_ok=True)
    res_df.to_csv('results/spotcheck_bg_only.csv', index=False)
    print(f"CHECK: {len(res_df)} rows; count of captures where the report lists a non-background C2 that ja4lab missed: {non_bg_c2_count}")

if __name__ == '__main__':
    spotcheck()
