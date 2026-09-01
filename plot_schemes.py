import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path


# ============================================================
# Paths
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parent
DATA_FILE = PROJECT_DIR / "scheme_benchmark.csv"
FIGURE_DIR = PROJECT_DIR / "figures"

FIGURE_DIR.mkdir(
    exist_ok=True
)


# ============================================================
# Paper-quality plotting settings
# ============================================================

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.labelsize": 12,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
    "axes.linewidth": 0.8,
    "hatch.linewidth": 1.0,
    "hatch.color": "white",
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})


# ============================================================
# Load benchmark data
# ============================================================

df = pd.read_csv(
    DATA_FILE
)


# ============================================================
# Validate columns
# ============================================================

required_columns = [
    "scheme",
    "presign_us",
    "prevrfy_us",
    "adapt_us",
    "extract_us",
    "vrfy_us",
    "total_us",
    "presig_bytes",
    "signature_bytes",
    "ek_bytes",
    "signer_storage_bytes",
    "adaptor_storage_bytes",
    "blockchain_storage_bytes",
]

missing = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing:
    raise RuntimeError(
        f"Missing columns in {DATA_FILE}: {missing}"
    )


# ============================================================
# Scheme order
# ============================================================

# Scheme 1 = Schnorr AS
# Scheme 2 = Trivial solution
# Scheme 3 = ASSET
# Scheme 4 = BBS+ AS
#
# Presentation order:
# Schnorr AS, BBS+ AS, Trivial solution, ASSET

scheme_order = [
    "Scheme 1",
    "Scheme 4",
    "Scheme 2",
    "Scheme 3",
]

df["scheme"] = pd.Categorical(
    df["scheme"],
    categories=scheme_order,
    ordered=True,
)

df = (
    df
    .sort_values("scheme")
    .reset_index(drop=True)
)


# ============================================================
# Display names
# ============================================================

display_names = {
    "Scheme 1": "Schnorr AS",
    "Scheme 4": r"BBS$^{+}$ AS",
    "Scheme 2": "Trivial solution",
    "Scheme 3": "ASSET",
}


# ============================================================
# Colors
# ============================================================

colors = {
    "Scheme 1": "#246BCE",  # blue
    "Scheme 4": "#00843D",  # green
    "Scheme 2": "#D9A300",  # yellow-orange
    "Scheme 3": "#C62828",  # red
}


# ============================================================
# White hatch patterns
# ============================================================

hatches = {
    "Scheme 1": ".",
    "Scheme 4": "-",
    "Scheme 2": "/",
    "Scheme 3": "\\",
}


# ============================================================
# Figure 1: Runtime comparison
# ============================================================

operations = [
    "pSign",
    "pVrfy",
    "Adapt",
    "(Sec)Ext",
    "Vrfy",
]

runtime_columns = [
    "presign_us",
    "prevrfy_us",
    "adapt_us",
    "extract_us",
    "vrfy_us",
]

x = np.arange(
    len(operations)
)

width = 0.18

fig, ax = plt.subplots(
    figsize=(7.2, 3.7)
)

num_schemes = len(df)

for i, (_, row) in enumerate(
    df.iterrows()
):
    scheme = str(
        row["scheme"]
    )

    values = [
        row[column]
        for column in runtime_columns
    ]

    offset = (
        i - (num_schemes - 1) / 2
    ) * width

    ax.bar(
        x + offset,
        values,
        width,
        label=display_names[scheme],
        color=colors[scheme],
        edgecolor="white",
        linewidth=1.0,
        hatch=hatches[scheme],
    )


# X axis

ax.set_xticks(
    x
)

ax.set_xticklabels(
    operations
)


# Y axis

ax.set_ylabel(
    r"Runtime ($\mu$s)"
)

ax.set_yscale(
    "log"
)


# Automatic Y-axis range

runtime_values = (
    df[runtime_columns]
    .to_numpy(dtype=float)
)

positive_values = runtime_values[
    runtime_values > 0
]

if positive_values.size == 0:
    raise RuntimeError(
        "No positive runtime values were found."
    )

max_runtime = positive_values.max()
min_runtime = positive_values.min()

ax.set_ylim(
    bottom=min_runtime / 2,
    top=max_runtime * 7,
)


# Grid

ax.grid(
    axis="y",
    linestyle="--",
    linewidth=0.6,
    alpha=0.30,
)

ax.set_axisbelow(
    True
)


# Legend inside the plot

ax.legend(
    frameon=False,
    ncol=4,
    loc="upper center",
    columnspacing=1.2,
    handlelength=1.8,
    handletextpad=0.5,
)


# Layout and save

fig.tight_layout()

fig.savefig(
    FIGURE_DIR / "runtime_comparison.pdf",
    bbox_inches="tight",
)

fig.savefig(
    FIGURE_DIR / "runtime_comparison.png",
    dpi=600,
    bbox_inches="tight",
)

plt.close(
    fig
)


# ============================================================
# Figure 2: Communication and storage comparison
# ============================================================

cost_categories = [
    "Pre-sig.",
    "Sig.",
    "Signer",
    "Adaptor",
    "On-chain",
]

cost_columns = [
    "presig_bytes",
    "signature_bytes",
    "signer_storage_bytes",
    "adaptor_storage_bytes",
    "blockchain_storage_bytes",
]

cost_x = np.arange(
    len(cost_categories)
)

cost_width = 0.18

fig_cost, ax_cost = plt.subplots(
    figsize=(7.2, 3.7)
)


# ============================================================
# Draw grouped bars
# ============================================================

for i, (_, row) in enumerate(
    df.iterrows()
):
    scheme = str(
        row["scheme"]
    )

    values = [
        row[column]
        for column in cost_columns
    ]

    offset = (
        i - (num_schemes - 1) / 2
    ) * cost_width

    bars = ax_cost.bar(
        cost_x + offset,
        values,
        cost_width,
        label=display_names[scheme],
        color=colors[scheme],
        edgecolor="white",
        linewidth=1.0,
        hatch=hatches[scheme],
    )

    # Concrete byte values above each bar

    ax_cost.bar_label(
        bars,
        fmt="%.0f",
        padding=2,
        fontsize=8.0,
    )


# ============================================================
# X axis
# ============================================================

ax_cost.set_xticks(
    cost_x
)

ax_cost.set_xticklabels(
    cost_categories
)


# ============================================================
# Y axis
# ============================================================

ax_cost.set_ylabel(
    "Cost (bytes)"
)

cost_values = (
    df[cost_columns]
    .to_numpy(dtype=float)
)

max_cost = cost_values.max()

ax_cost.set_ylim(
    bottom=0,
    top=max_cost * 1.30,
)


# ============================================================
# Separator between communication and storage
# ============================================================

# Communication:
# Pre-sig., Sig.
#
# Storage:
# Signer, Adaptor, On-chain

ax_cost.axvline(
    x=1.5,
    color="0.75",
    linestyle="--",
    linewidth=0.6,
    alpha=0.5,
)


# ============================================================
# Grid
# ============================================================

ax_cost.grid(
    axis="y",
    linestyle="--",
    linewidth=0.6,
    alpha=0.30,
)

ax_cost.set_axisbelow(
    True
)


# ============================================================
# Legend inside the plot
# ============================================================

ax_cost.legend(
    frameon=False,
    ncol=4,
    loc="upper center",
    columnspacing=1.2,
    handlelength=1.8,
    handletextpad=0.5,
)


# ============================================================
# Layout and save
# ============================================================

fig_cost.tight_layout()

fig_cost.savefig(
    FIGURE_DIR / "communication_storage_comparison.pdf",
    bbox_inches="tight",
)

fig_cost.savefig(
    FIGURE_DIR / "communication_storage_comparison.png",
    dpi=600,
    bbox_inches="tight",
)

plt.close(
    fig_cost
)


# ============================================================
# Done
# ============================================================

print(
    "\nFigures generated:"
)

print(
    f"  {FIGURE_DIR / 'runtime_comparison.pdf'}"
)

print(
    f"  {FIGURE_DIR / 'runtime_comparison.png'}"
)

print(
    f"  {FIGURE_DIR / 'communication_storage_comparison.pdf'}"
)

print(
    f"  {FIGURE_DIR / 'communication_storage_comparison.png'}"
)