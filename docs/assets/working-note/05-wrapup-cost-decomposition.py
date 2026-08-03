"""Generate §7.5 cost-decomposition figure for the Working Note.

Stacked per-candidate replay cost on the gpt_oss row = scored exfil generation(s)
+ ONE fixed wrap-up generation. The wrap-up band is the same height across all
bars (it is fixed), so multi-post amortizes it. Numbers from hops-calibration:
exfil gen ~= 11.05s, wrap-up gen ~= 11.25s.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

# Palette harmonized with the Note's existing Excalidraw figures
NAVY   = "#1e2a4a"   # text
GREEN  = "#8ed08f"   # scored exfil fill
GREEN_E= "#3f9142"   # scored exfil edge
GRAY   = "#c9c7c0"   # wasted wrap-up fill
GRAY_E = "#8a877f"   # wasted wrap-up edge
SUB    = "#52514e"   # subtitle/secondary ink
SURF   = "#fcfcfb"   # surface

EXFIL_UNIT = 11.05
WRAPUP     = 11.25

configs = [
    ("Single-post\n(N=1)", 1, 18),
    ("Multi-post\n(N=5)",   5, 82),
    ("Multi-post\n(N=7)",   7, 114),
]

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "text.color": NAVY,
    "axes.edgecolor": "#d9d7d0",
    "axes.labelcolor": NAVY,
    "xtick.color": NAVY,
    "ytick.color": SUB,
    "figure.facecolor": SURF,
    "axes.facecolor": SURF,
})

fig, ax = plt.subplots(figsize=(11.6, 6.2), dpi=110)
fig.subplots_adjust(left=0.085, right=0.975, top=0.78, bottom=0.12)

x = list(range(len(configs)))
width = 0.52

for i, (label, n, score) in enumerate(configs):
    exfil = n * EXFIL_UNIT
    # scored exfil (green)
    ax.bar(i, exfil, width, color=GREEN, edgecolor=GREEN_E, linewidth=1.6, zorder=3)
    # wasted wrap-up (gray, hatched) stacked on top, 2px surface gap
    ax.bar(i, WRAPUP, width, bottom=exfil + 0.6, color=GRAY, edgecolor=GRAY_E,
           linewidth=1.6, hatch="////", zorder=3)
    total = exfil + WRAPUP
    share = 100 * WRAPUP / total
    # wrap-up share label centered ON the gray band, white halo so it reads over hatch
    ax.text(i, exfil + 0.6 + WRAPUP/2, f"{share:.0f}%", ha="center", va="center",
            fontsize=10.5, fontweight="bold", color=NAVY, zorder=6,
            bbox=dict(boxstyle="round,pad=0.18", fc="white", ec="none", alpha=0.9))
    # raw score on top of the bar
    ax.text(i, total + 2.6, f"scores {score} raw", ha="center", va="bottom",
            fontsize=11.5, color=NAVY, fontweight="bold", zorder=6)
    # exfil count inside the green
    ax.text(i, exfil/2, f"{n}× scored\nexfil gen", ha="center", va="center",
            fontsize=10.5, color="#1c3d1e", zorder=6)

ax.set_xticks(x)
ax.set_xticklabels([c[0] for c in configs], fontsize=11.5)
ax.set_ylabel("per-candidate replay cost  (seconds, gpt_oss row)", fontsize=11)
ax.set_ylim(0, 108)
ax.set_xlim(-0.62, 2.55)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
ax.spines["left"].set_color("#d9d7d0")
ax.spines["bottom"].set_color("#d9d7d0")
ax.tick_params(length=0)
ax.set_axisbelow(True)
ax.yaxis.grid(True, color="#ecebe6", linewidth=1)

# Title + subtitle in the Note's diagram voice
fig.text(0.085, 0.94, "The wrap-up generation is a fixed tax the reasoning row pays once",
         fontsize=16.5, fontweight="bold", color=NAVY, ha="left")
fig.text(0.085, 0.885,
         "On the gpt_oss row a forced post-tool-call generation costs about as much as a scored exfil, yet scores\n"
         "nothing. Its height is the same on every bar — packing more scored posts into one candidate amortizes it.",
         fontsize=10.8, color=SUB, ha="left")

legend = [
    Patch(facecolor=GREEN, edgecolor=GREEN_E, label="Scored exfil generation  (+16 raw each)"),
    Patch(facecolor=GRAY, edgecolor=GRAY_E, hatch="////", label="Wasted wrap-up generation  (fixed, +0 raw)"),
]
ax.legend(handles=legend, loc="upper left", bbox_to_anchor=(0.015, 0.99),
          frameon=True, framealpha=0.95, edgecolor="#e3e1da", fontsize=10.3,
          handlelength=1.7, labelspacing=0.7, borderpad=0.8)

out = "docs/assets/working-note/05-wrapup-cost-decomposition.png"
fig.savefig(out, dpi=110, facecolor=SURF)
print("wrote", out)
