import pandas as pd
import os

df1 = pd.read_csv('data/canonical/matousek2024.csv.gz')
df2 = pd.read_csv('data/interim/matousek_ja4lab.csv', low_memory=False)

# df1 basename
df1['basename'] = df1['capture_id'].str.split('/').str[-1]

# df2 basename
df2['basename'] = df2['pcap'].apply(lambda x: os.path.splitext(os.path.basename(x))[0])
# matousek canonical strips .exe and .apk for some reason, or rather, the pcap has them appended sometimes.
# Actually, the best way is to match what we have. Let's try matching exactly what df1 has by trying variations.
def get_pcap_base(pcap_path):
    base = os.path.basename(pcap_path)
    if base.endswith('.pcapng'):
        base = base[:-7]
    elif base.endswith('.pcap'):
        base = base[:-5]
    return base

df2['basename'] = df2['pcap'].apply(get_pcap_base)
df2['basename_noext'] = df2['basename'].str.replace('\.exe$', '', regex=True).str.replace('\.apk$', '', regex=True)

# Merge on (basename, src_port, dst_ip, dst_port)
# df1 uses src_ip, dst_ip, src_port, dst_port
# wait, df1 might have basename without .exe or .apk. So we can coalesce.
merge_cols1 = ['basename', 'src_port', 'dst_ip', 'dst_port']

merged1 = pd.merge(df1, df2, on=merge_cols1, how='left', suffixes=('', '_y'))

# For fallback: df1 might have 'AMPLibraryAgent' and df2 has 'AMPLibraryAgent.exe' (mapped to basename)
df1['basename_fallback'] = df1['basename'].str.replace('\.exe$', '', regex=True).str.replace('\.apk$', '', regex=True)
df2['basename_fallback'] = df2['basename'].str.replace('\.exe$', '', regex=True).str.replace('\.apk$', '', regex=True)

merge_cols_fallback = ['basename_fallback', 'src_port', 'dst_ip', 'dst_port']
merged2 = pd.merge(df1, df2, on=merge_cols_fallback, how='left', suffixes=('', '_y'))

merged = merged1.combine_first(merged2)

# rename columns as required: ttl, win, mss, wscale, ja4t
rename_dict = {
    'tcp_window': 'win',
    'tcp_mss': 'mss',
    'tcp_wscale': 'wscale'
}
merged = merged.rename(columns=rename_dict)
cols_to_add = ['ttl', 'win', 'mss', 'wscale', 'ja4t']

for col in cols_to_add:
    if col in merged.columns and f"{col}_x" not in df1.columns:
        df1[col] = merged[col]

join_rate = merged['ttl'].notna().mean()
print(f"Join rate: {join_rate:.2%}")

if join_rate < 0.9:
    print("Unjoined rows example:")
    print(df1[merged['ttl'].isna()].head())

df1.drop(columns=['basename'], inplace=True, errors='ignore')
df1.to_csv('data/canonical/matousek2024_tcp.csv.gz', index=False)
print("Wrote data/canonical/matousek2024_tcp.csv.gz")
