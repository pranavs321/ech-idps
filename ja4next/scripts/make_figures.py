"""Figures for README / PDF, generated only from results/*.csv (no hand-typed numbers).
Writes docs/figures/*.png. Colour-blind-safe (Okabe-Ito) palette."""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker
import pandas as pd

OUT = "docs/figures"; os.makedirs(OUT, exist_ok=True)
C = {"ENV": "#999999", "TLS": "#E69F00", "BEH": "#56B4E9", "TLS+BEH": "#0072B2", "HR+TLS+BEH": "#D55E00"}
plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False, "figure.dpi": 150})

# Fig 1: detection at 1% false alarms across split difficulty
s = pd.read_csv("results/hostname_only/summary.csv")
splits = [("capture", "Unseen captures"), ("ja4", "Unseen\nfingerprints"), ("year", "Unseen years"),
          ("time", "Train 2013-18,\ntest 2019-21"), ("source", "Unseen source\n(hardest)")]
sets = ["ENV", "TLS", "BEH", "TLS+BEH", "HR+TLS+BEH"]
fig, ax = plt.subplots(figsize=(9, 4.2))
w = 0.16
for i, st in enumerate(sets):
    v = [float(s[(s.split == sp) & (s.set == st)]["tpr_at_1pct"].iloc[0]) for sp, _ in splits]
    ax.bar([x + (i - 2) * w for x in range(len(splits))], v, w, label=st, color=C[st])
ax.set_xticks(range(len(splits))); ax.set_xticklabels([l for _, l in splits])
ax.set_ylabel("Malware found at 1% false alarms"); ax.set_ylim(0, 1.05)
ax.set_title("Host-relative features keep working when the test gets harder")
ax.legend(ncol=5, loc="upper center", bbox_to_anchor=(0.5, -0.2), frameon=False)
fig.tight_layout(); fig.savefig(f"{OUT}/fig1_split_ladder.png"); plt.close(fig)

# Fig 2: clean foreign benign traffic flagged
f = pd.read_csv("results/foreign_benign/flag_rates.csv"); f = f[f.group.isin(["normal_host", "pre_infection"])]
order = ["ENV", "TLS", "BEH", "TLS+BEH", "HRb+TLS+BEH", "HR+TLS+BEH"]
fig, ax = plt.subplots(figsize=(8, 3.8))
nc = lambda g: int(f[(f.group == g)]["captures"].iloc[0])
for j, (g, lab, col) in enumerate((("normal_host", f"Clean normal hosts ({nc('normal_host')} captures)", "#0072B2"),
                                    ("pre_infection", f"Real user before infection ({nc('pre_infection')} captures)", "#D55E00"))):
    v = [float(f[(f.set == k) & (f.group == g)]["flagged_conn"].iloc[0]) * 100 for k in order]
    ax.bar([x + (j - 0.5) * 0.38 for x in range(len(order))], v, 0.38, label=lab, color=col)
ax.set_xticks(range(len(order))); ax.set_xticklabels(order, rotation=15)
ax.set_ylabel("Benign connections flagged (%)")
ax.set_title("False alarms on clean traffic from another lab (threshold set at 1% on training lab)")
ax.legend(frameon=False); fig.tight_layout(); fig.savefig(f"{OUT}/fig2_clean_benign.png"); plt.close(fig)

# Fig 3: second lab, two labelings
a = pd.read_csv("results/second_lab/transfer_metrics.csv"); b = pd.read_csv("results/second_lab_weak/transfer_metrics.csv")
sets3 = ["ENV", "TLS+BEH", "HRb+TLS+BEH", "HR+TLS+BEH"]
fig, ax = plt.subplots(figsize=(7.5, 3.8))
mc = lambda d: int(d[d.train == "MTA"]["n_test_mal_caps"].iloc[0])
for j, (d, lab, col) in enumerate(((a, f"Strict labels ({mc(a)} malware captures)", "#0072B2"),
                                    (b, f"Broad labels ({mc(b)} malware captures)", "#D55E00"))):
    d = d[d.train == "MTA"]
    v = [float(d[d.set == k]["roc_auc"].iloc[0]) for k in sets3]
    ax.bar([x + (j - 0.5) * 0.38 for x in range(len(sets3))], v, 0.38, label=lab, color=col)
ax.axhline(0.5, color="#555", lw=0.8, ls="--"); ax.text(-0.45, 0.51, "chance", ha="left", fontsize=8)
ax.set_xticks(range(len(sets3))); ax.set_xticklabels(sets3); ax.set_ylim(0, 1.05); ax.set_ylabel("ROC-AUC")
ax.set_title("Second lab: the answer depends on how malware is labelled")
ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2); fig.tight_layout(); fig.savefig(f"{OUT}/fig3_second_lab.png"); plt.close(fig)
print("figures written:", sorted(os.listdir(OUT)))

# Fig 0: pipeline diagram (no data; plain boxes)
from matplotlib.patches import FancyBboxPatch
steps = [("1  Collect", "public\nrecordings of\nnetwork traffic"), ("2  Read", "each connection's\nfirst message\n(the handshake)"),
         ("3  Label", "malware or normal\nfrom independent\nevidence"), ("4  Describe", "handshake, behaviour\n+ the computer's\nown habits"),
         ("5  Test hard", "unseen recordings,\nyears, labs and\nfingerprints"), ("6  Check", "shortcuts, false\nalarms, second\nlab"),
         ("7  Lock", "final test on\n2022-26 (not\nyet run)")]
fig, ax = plt.subplots(figsize=(13, 3.2)); ax.set_xlim(0, 7.4); ax.set_ylim(0, 1); ax.axis("off")
cols = ["#56B4E9"] * 2 + ["#E69F00"] * 1 + ["#0072B2"] * 1 + ["#009E73"] * 2 + ["#999999"]
for i, ((t, s_), c) in enumerate(zip(steps, cols)):
    x = i * 1.06 + 0.02
    ax.add_patch(FancyBboxPatch((x, 0.18), 0.96, 0.62, boxstyle="round,pad=0.02", fc=c, ec="none", alpha=0.9))
    ax.text(x + 0.48, 0.66, t, ha="center", va="center", fontsize=10.5, fontweight="bold", color="white")
    ax.text(x + 0.48, 0.36, s_, ha="center", va="center", fontsize=7.2, color="white", linespacing=1.3)
    if i < len(steps) - 1: ax.annotate("", xy=(x + 1.06, 0.49), xytext=(x + 0.99, 0.49), arrowprops=dict(arrowstyle="->", color="#444"))
ax.text(3.7, 0.04, "The 2022-2026 recordings stay locked until the guide signs the plan: they are our one clean, final exam.",
        ha="center", fontsize=8.5, color="#444")
fig.savefig(f"{OUT}/fig0_pipeline.png", bbox_inches="tight"); plt.close(fig)

# Fig 4: how much data each group contributed (read from audit files)
import json
dq = json.load(open("results/data_quality.json"))["tables"]
groups = [("MTA infection recordings\n2013-2021 (main data)", dq["MTA 2013-2021 (processed)"]),
          ("Stratosphere botnet", dq["Stratosphere mcfp"]), ("Stratosphere Mixed/Normal", dq["Stratosphere mcfp2"]),
          ("Stratosphere trojans", dq["Stratosphere mcfp3"])]
fig, axs = plt.subplots(1, 2, figsize=(10, 3.4))
for ax, key, ttl in ((axs[0], "captures", "Recordings with encrypted traffic"), (axs[1], "rows", "Encrypted connections read")):
    vals = [g[1][key] for g in groups]
    ax.barh(range(len(groups)), vals, color=["#0072B2", "#E69F00", "#E69F00", "#E69F00"])
    ax.set_yticks(range(len(groups))); ax.set_yticklabels([g[0] for g in groups] if ax is axs[0] else [""] * 4, fontsize=8.5)
    ax.invert_yaxis(); ax.set_title(ttl, fontsize=10)
    for i, v in enumerate(vals): ax.text(v, i, f" {v:,}", va="center", fontsize=8.5)
    ax.set_xlim(0, max(vals) * 1.25)
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{int(v):,}"))
    if key == "rows": ax.set_xticks([0, 250000, 500000, 750000]); ax.tick_params(axis="x", labelsize=8)
fig.tight_layout(); fig.savefig(f"{OUT}/fig4_data_overview.png"); plt.close(fig)
print("figures written:", sorted(os.listdir(OUT)))
