"""Label MCFP (Stratosphere lab) TLS connections from each capture's README.
Rule: infected host = README 'Infected host' IP. Only that host is labelled.
 gold/weak malicious = IOC feeds (SSLBL cert, Feodo, Maltrail) -- same evidence as MTA, no ML labels
 benign = vendor allowlist SNI on the infected host (benign-likely background)
 everything else unknown. Writes data/interim/mcfp_labelled.parquet. Second independent lab/era for transfer tests."""
import glob, os, re, sys, warnings, datetime as dt
warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import pandas as pd
from ja4next.labels import Feeds, label_frame
from ja4next import strat
feeds = Feeds("data/labels")
frames = []
for f in glob.glob("data/interim/mcfp/*.parquet") + glob.glob("data/interim/mcfp3/*.parquet"):
    d = pd.read_parquet(f)
    if len(d): frames.append(d)
df = pd.concat(frames, ignore_index=True)
df["capture_id"] = df["mcfp_dir"] + "/" + df["pcap_name"]
inf = {d: strat.infected_ip(strat.readme(d)) for d in df["mcfp_dir"].unique()}
df["infected_ip"] = df["mcfp_dir"].map(inf)
df["is_infected_host"] = df["client_ip"] == df["infected_ip"]
lab = label_frame(df[df["is_infected_host"]], feeds, {})
df = df.merge(lab[["capture_id", "stream", "label_tier", "label_evidence", "y"]], on=["capture_id", "stream"], how="left")
df["label_tier"] = df["label_tier"].fillna("not_infected_host")
print(df.groupby("label_tier").size())
print("captures with infected ip:", df.loc[df.infected_ip.notna(), "capture_id"].nunique(), "of", df.capture_id.nunique())
print("captures with both classes:", df.dropna(subset=["y"]).groupby("capture_id")["y"].nunique().eq(2).sum())
print("by class:", df["y"].value_counts().to_dict())
df["t_infect"]=df["mcfp_dir"].map({d:strat.infect_time(strat.readme(d)) for d in df["mcfp_dir"].unique()})
after=df["t_infect"].isna() | (df["t_clienthello"]>=df["t_infect"])
allow_ = df["label_tier"]=="unknown"
weak_host = df["is_infected_host"] & after & allow_ & (df["sni"].fillna("")!="")
df["y_weak"]=df["y"]; df.loc[weak_host,"y_weak"]=1.0
df["label_tier_weak"]=df["label_tier"].where(~weak_host,"host_mal")
print("weak-host extra positives:",int(weak_host.sum()),"captures with t_infect:",df.loc[df.t_infect.notna(),"capture_id"].nunique())
print("weak classes:",df["y_weak"].value_counts().to_dict(),"mal captures",df[df.y_weak==1].capture_id.nunique(),"ben captures",df[df.y_weak==0].capture_id.nunique())
df.to_parquet("data/interim/mcfp_labelled.parquet", index=False)
