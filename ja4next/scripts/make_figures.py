"""Figures for README / PDF, generated only from results/*.csv (no hand-typed numbers).
Writes docs/figures/*.png. Colour-blind-safe (Okabe-Ito) palette."""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
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
