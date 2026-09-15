#!/usr/bin/env python3
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# Data from 5-seed sweep
phi = np.array([0.00, 0.15, 0.30, 0.45, 0.60, 0.75, 0.90, 0.95, 1.00])
mean_recall = np.array([1.0000, 1.0000, 0.9889, 0.9687, 0.8983, 0.5627, 0.0747, 0.0295, 0.0307])
sd_recall = np.array([0.0000, 0.0000, 0.0086, 0.0080, 0.0311, 0.0881, 0.0218, 0.0093, 0.0074])
mean_overhead = np.array([10.73, 14.26, 18.94, 22.44, 27.66, 31.67, 35.16, 36.90, 37.39])
sd_overhead = np.array([0.36, 0.70, 0.68, 0.54, 1.31, 0.44, 1.97, 1.14, 1.73])

fig, ax = plt.subplots(figsize=(9, 6))

ax.errorbar(mean_overhead, mean_recall, 
            xerr=sd_overhead, yerr=sd_recall, 
            fmt='o-', color='#1f3a68', ecolor='#8fa3bf', 
            capsize=4, lw=2, markersize=6, zorder=3)

# Shading the infeasible region
# The infeasible region is the area below and to the left of the curve.
# We can shade between y=0 and the curve.
ax.fill_between(mean_overhead, 0, mean_recall, color='#a4391f', alpha=0.2, zorder=1)
ax.text(25, 0.25, "INFEASIBLE\n(Attacker cannot reach this region)", 
        color='#a4391f', fontsize=12, fontweight='bold', ha='center', va='center', zorder=4)

# Annotate points with phi values
for i, p in enumerate(phi):
    # Adjust annotation position to avoid overlapping with line/error bars
    xytext = (5, 5) if p < 0.9 else (-25, 5)
    ax.annotate(f"$\\varphi$={p:.2f}", (mean_overhead[i], mean_recall[i]), 
                fontsize=9, xytext=xytext, textcoords="offset points", zorder=4)

ax.set_xlabel("Attacker Bandwidth Overhead (measured ratio to cover)")
ax.set_ylabel("Detection Recall @ 0.5% FPR")
ax.set_title("The Cover-Rate Frontier: no attacker can reach the shaded region")
ax.grid(True, linestyle='--', alpha=0.5, zorder=0)

out = Path("results")
out.mkdir(exist_ok=True)
path = out / "frontier.png"
fig.savefig(path, bbox_inches="tight", dpi=150)
print(f"Saved {path}")
