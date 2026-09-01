import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path


# ============================================================
# Paths
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parent

SCALING_DATA_FILE = (
    PROJECT_DIR / "scheme_scaling_benchmark.csv"
)

BASE_DATA_FILE = (
    PROJECT_DIR / "scheme_benchmark.csv"
)

FIGURE_DIR = PROJECT_DIR / "figures"

FIGURE_DIR.mkdir(
    exist_ok=True
)


# ============================================================
# Plot configuration
# ============================================================

# The scaling CSV may still contain N = 500.
# It is intentionally omitted from the figures.
PLOT_BATCH_SIZES = [
    1,
    10,
    100,
    1000,
]

# Keep exactly the same figure size as the previous
# role-based plotting code.
FIGSIZE = (
    3.6,
    3.0,
)

# Set to True if you want titles inside each figure.
# Keep False if titles/captions will be handled in LaTeX.
SHOW_TITLES = True


# ============================================================
# Paper-quality plotting settings
# ============================================================

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 9,
    "axes.labelsize": 9,
    "axes.titlesize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 8,
    "axes.linewidth": 0.8,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})


# ============================================================
# Scheme order and display names
# ============================================================

scheme_order = [
    "Scheme 1",
    "Scheme 4",
    "Scheme 2",
    "Scheme 3",
]

display_names = {
    "Scheme 1": "Schnorr AS",
    "Scheme 4": r"BBS$^{+}$ AS",
    "Scheme 2": "Trivial solution",
    "Scheme 3": "ASSET",
}


# ============================================================
# Visual encoding
# ============================================================

colors = {
    "Scheme 1": "#246BCE",  # blue
    "Scheme 4": "#00843D",  # green
    "Scheme 2": "#D9A300",  # yellow-orange
    "Scheme 3": "#C62828",  # red
}

markers = {
    "Scheme 1": "o",
    "Scheme 4": "s",
    "Scheme 2": "^",
    "Scheme 3": "D",
}

linestyles = {
    "Scheme 1": "-",
    "Scheme 4": "--",
    "Scheme 2": "-.",
    "Scheme 3": ":",
}


# ============================================================
# Load data
# ============================================================

scaling_df = pd.read_csv(
    SCALING_DATA_FILE
)

base_df = pd.read_csv(
    BASE_DATA_FILE
)


# ============================================================
# Validate scaling CSV
# ============================================================

required_scaling_columns = [
    "scheme",
    "operation",
    "batch_size",
    "lower_us",
    "runtime_us",
    "upper_us",
]

missing = [
    column
    for column in required_scaling_columns
    if column not in scaling_df.columns
]

if missing:
    raise RuntimeError(
        f"Missing columns in {SCALING_DATA_FILE}: {missing}"
    )


# ============================================================
# Validate base CSV
# ============================================================

required_base_columns = [
    "scheme",
    "presig_bytes",
    "signature_bytes",
    "ek_bytes",
    "signer_storage_bytes",
    "adaptor_storage_bytes",
]

missing = [
    column
    for column in required_base_columns
    if column not in base_df.columns
]

if missing:
    raise RuntimeError(
        f"Missing columns in {BASE_DATA_FILE}: {missing}"
    )


# ============================================================
# Keep only N = 1, 10, 100, 1000
# ============================================================

scaling_df = scaling_df[
    scaling_df["batch_size"].isin(
        PLOT_BATCH_SIZES
    )
].copy()


# ============================================================
# Categorical scheme order
# ============================================================

scaling_df["scheme"] = pd.Categorical(
    scaling_df["scheme"],
    categories=scheme_order,
    ordered=True,
)

base_df["scheme"] = pd.Categorical(
    base_df["scheme"],
    categories=scheme_order,
    ordered=True,
)

base_df = (
    base_df
    .sort_values("scheme")
    .reset_index(drop=True)
)


# ============================================================
# Helper: obtain one operation for one scheme
# ============================================================

def get_operation_data(
    scheme,
    operation,
):
    operation_df = (
        scaling_df[
            (scaling_df["scheme"] == scheme)
            & (scaling_df["operation"] == operation)
        ]
        .sort_values("batch_size")
    )

    if operation_df.empty:
        raise RuntimeError(
            f"No data found for {scheme}, {operation}"
        )

    actual_batch_sizes = (
        operation_df["batch_size"]
        .astype(int)
        .tolist()
    )

    if actual_batch_sizes != PLOT_BATCH_SIZES:
        raise RuntimeError(
            f"Unexpected batch sizes for {scheme}, {operation}. "
            f"Expected {PLOT_BATCH_SIZES}, "
            f"found {actual_batch_sizes}."
        )

    return operation_df


# ============================================================
# Build role-based runtime data
# ============================================================

# Signer runtime:
#   pSign + (Sec)Ext
#
# Adaptor runtime:
#   pVrfy + Adapt
#
# Vrfy is excluded because it is public/full-signature verification,
# rather than a local signer/adaptor operation.
#
# We sum only Criterion point estimates. The confidence intervals of
# separately measured operations are not added because that would not
# generally produce a statistically valid confidence interval for the
# sum.

runtime_rows = []

for scheme in scheme_order:
    psign_df = get_operation_data(
        scheme,
        "pSign",
    )

    extract_df = get_operation_data(
        scheme,
        "(Sec)Ext",
    )

    prevrfy_df = get_operation_data(
        scheme,
        "pVrfy",
    )

    adapt_df = get_operation_data(
        scheme,
        "Adapt",
    )

    for i, batch_size in enumerate(
        PLOT_BATCH_SIZES
    ):
        signer_runtime = (
            float(
                psign_df.iloc[i]["runtime_us"]
            )
            +
            float(
                extract_df.iloc[i]["runtime_us"]
            )
        )

        adaptor_runtime = (
            float(
                prevrfy_df.iloc[i]["runtime_us"]
            )
            +
            float(
                adapt_df.iloc[i]["runtime_us"]
            )
        )

        runtime_rows.append({
            "scheme": scheme,
            "batch_size": batch_size,
            "signer_runtime_us":
                signer_runtime,
            "adaptor_runtime_us":
                adaptor_runtime,
        })

role_runtime_df = pd.DataFrame(
    runtime_rows
)


# ============================================================
# Build storage and communication data
# ============================================================

# Storage model for N concurrent independent instances:
#
# Long-term keys are counted once, while session-specific state
# scales with N.
#
# fixed signer storage
#   = signer_storage_bytes
#     - presig_bytes
#     - ek_bytes
#
# fixed adaptor storage
#   = adaptor_storage_bytes
#     - presig_bytes
#
# Hence:
#
# signer storage(N)
#   = fixed signer storage
#     + N * (presig_bytes + ek_bytes)
#
# adaptor storage(N)
#   = fixed adaptor storage
#     + N * presig_bytes
#
# Communication:
#
# pre-signature communication(N)
#   = N * presig_bytes
#
# signature communication(N)
#   = N * signature_bytes

cost_rows = []

for _, row in base_df.iterrows():
    scheme = str(
        row["scheme"]
    )

    presig_bytes = float(
        row["presig_bytes"]
    )

    signature_bytes = float(
        row["signature_bytes"]
    )

    ek_bytes = float(
        row["ek_bytes"]
    )

    signer_storage_bytes = float(
        row["signer_storage_bytes"]
    )

    adaptor_storage_bytes = float(
        row["adaptor_storage_bytes"]
    )

    fixed_signer_storage = (
        signer_storage_bytes
        - presig_bytes
        - ek_bytes
    )

    fixed_adaptor_storage = (
        adaptor_storage_bytes
        - presig_bytes
    )

    if fixed_signer_storage < 0:
        raise RuntimeError(
            f"Negative fixed signer storage for {scheme}."
        )

    if fixed_adaptor_storage < 0:
        raise RuntimeError(
            f"Negative fixed adaptor storage for {scheme}."
        )

    for batch_size in PLOT_BATCH_SIZES:
        cost_rows.append({
            "scheme": scheme,
            "batch_size": batch_size,

            "signer_storage_bytes":
                fixed_signer_storage
                + batch_size
                * (
                    presig_bytes
                    + ek_bytes
                ),

            "adaptor_storage_bytes":
                fixed_adaptor_storage
                + batch_size
                * presig_bytes,

            "presig_communication_bytes":
                batch_size
                * presig_bytes,

            "signature_communication_bytes":
                batch_size
                * signature_bytes,
        })

role_cost_df = pd.DataFrame(
    cost_rows
)


# ============================================================
# Figure definitions
# ============================================================

figure_specs = [
    {
        "data": role_runtime_df,
        "y_column": "signer_runtime_us",
        "ylabel": r"Total runtime ($\mu$s)",
        "title": "(a) Signer runtime",
        "file_stem": "signer_runtime_scaling",
    },
    {
        "data": role_runtime_df,
        "y_column": "adaptor_runtime_us",
        "ylabel": r"Total runtime ($\mu$s)",
        "title": "(b) Adaptor runtime",
        "file_stem": "adaptor_runtime_scaling",
    },
    {
        "data": role_cost_df,
        "y_column": "signer_storage_bytes",
        "ylabel": "Total storage (bytes)",
        "title": "(a) Signer storage",
        "file_stem": "signer_storage_scaling",
    },
    {
        "data": role_cost_df,
        "y_column": "adaptor_storage_bytes",
        "ylabel": "Total storage (bytes)",
        "title": "(b) Adaptor storage",
        "file_stem": "adaptor_storage_scaling",
    },
    {
        "data": role_cost_df,
        "y_column": "presig_communication_bytes",
        "ylabel": "Total communication (bytes)",
        "title": "(a) Pre-signature",
        "file_stem": "presig_communication_scaling",
    },
    {
        "data": role_cost_df,
        "y_column": "signature_communication_bytes",
        "ylabel": "Total communication (bytes)",
        "title": "(b) Signature",
        "file_stem": "signature_communication_scaling",
    },
]


# ============================================================
# Shared plotting helper
# ============================================================

def draw_figure(
    data,
    y_column,
    ylabel,
    title,
    file_stem,
):
    fig, ax = plt.subplots(
        figsize=FIGSIZE
    )

    for scheme in scheme_order:
        scheme_df = (
            data[
                data["scheme"] == scheme
            ]
            .sort_values("batch_size")
        )

        if scheme_df.empty:
            raise RuntimeError(
                f"No data found for {scheme} in {file_stem}."
            )

        x = (
            scheme_df["batch_size"]
            .to_numpy(dtype=float)
        )

        y = (
            scheme_df[y_column]
            .to_numpy(dtype=float)
        )

        if np.any(y <= 0):
            raise RuntimeError(
                f"Non-positive values found for "
                f"{scheme} in {file_stem}."
            )

        ax.plot(
            x,
            y,
            label=display_names[scheme],
            color=colors[scheme],
            linestyle=linestyles[scheme],
            marker=markers[scheme],
            markersize=4.8,
            linewidth=1.45,
            markeredgecolor="white",
            markeredgewidth=0.65,
        )

    ax.set_xscale(
        "log"
    )

    ax.set_yscale(
        "log"
    )
    


    ax.set_xticks(
        PLOT_BATCH_SIZES
    )

    ax.set_xticklabels(
        [
            str(n)
            for n in PLOT_BATCH_SIZES
        ]
    )

    ax.set_xlabel(
        "Batch size"
    )

    ax.set_ylabel(
        ylabel
    )

    if SHOW_TITLES:
        ax.set_title(
            title,
            pad=6,
        )

    ax.grid(
        axis="both",
        which="major",
        linestyle="--",
        linewidth=0.55,
        alpha=0.28,
    )

    ax.set_axisbelow(
        True
    )

    ax.legend(
        frameon=False,
        ncol=2,
        loc="upper left",
        columnspacing=1.0,
        handlelength=2.0,
        handletextpad=0.45,
    )

    fig.tight_layout()

    pdf_file = (
        FIGURE_DIR
        / f"{file_stem}.pdf"
    )

    png_file = (
        FIGURE_DIR
        / f"{file_stem}.png"
    )

    fig.savefig(
        pdf_file,
        bbox_inches="tight",
    )

    fig.savefig(
        png_file,
        dpi=600,
        bbox_inches="tight",
    )

    plt.close(
        fig
    )

    return (
        pdf_file,
        png_file,
    )


# ============================================================
# Generate six independent figures
# ============================================================

generated_files = []

for spec in figure_specs:
    generated_files.extend(
        draw_figure(
            data=spec["data"],
            y_column=spec["y_column"],
            ylabel=spec["ylabel"],
            title=spec["title"],
            file_stem=spec["file_stem"],
        )
    )


# ============================================================
# Done
# ============================================================

print(
    "\nFigures generated:"
)

for file in generated_files:
    print(
        f"  {file}"
    )