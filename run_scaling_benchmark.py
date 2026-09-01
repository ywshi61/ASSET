import csv
import re
import subprocess
import sys
from pathlib import Path


# ============================================================
# Paths
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parent
OUTPUT_CSV = PROJECT_DIR / "scheme_scaling_benchmark.csv"
RAW_OUTPUT = PROJECT_DIR / "scaling_benchmark_output.txt"
PLOT_SCRIPT = PROJECT_DIR / "plot_scaling.py"


# ============================================================
# Experiment configuration
# ============================================================

BATCH_SIZES = [
    1,
    10,
    100,
    500,
    1000,
]

OPERATIONS = [
    "PreSign",
    "PreVrfy",
    "Adapt",
    "Extract",
    "Vrfy",
]


# ============================================================
# Unit conversion
# ============================================================

def to_microseconds(value: float, unit: str) -> float:
    """Convert Criterion runtime units to microseconds."""

    unit = unit.strip()

    if unit == "ns":
        return value / 1000.0

    if unit in ("us", "µs", "μs"):
        return value

    if unit == "ms":
        return value * 1000.0

    if unit == "s":
        return value * 1_000_000.0

    raise ValueError(
        f"Unknown time unit: {unit}"
    )


# ============================================================
# Parse Criterion scaling results
# ============================================================

def parse_scaling_runtime(output: str):
    """
    Parse Criterion benchmark names of the form:

        Scaling/Scheme1/PreSign/100
            time: [lower estimate upper]

    The Rust benchmark performs N distinct protocol instances inside
    each b.iter() iteration, so Criterion reports total batch runtime.

    The tempered section between the benchmark name and `time:` prevents
    one failed/missing benchmark block from accidentally consuming the
    timing result of the next `Scaling/...` benchmark.
    """

    pattern = re.compile(
        r"Scaling/(Scheme[1234])/"
        r"(PreSign|PreVrfy|Adapt|Extract|Vrfy)/"
        r"(\d+)"
        r"(?:(?!Scaling/).)*?"
        r"time:\s*\[\s*"
        r"([0-9.eE+-]+)\s*(ns|us|µs|μs|ms|s)\s+"
        r"([0-9.eE+-]+)\s*(ns|us|µs|μs|ms|s)\s+"
        r"([0-9.eE+-]+)\s*(ns|us|µs|μs|ms|s)"
        r"\s*\]",
        re.DOTALL,
    )

    rows = []

    for match in pattern.finditer(output):
        scheme = match.group(1)
        operation = match.group(2)
        batch_size = int(
            match.group(3)
        )

        lower_us = to_microseconds(
            float(match.group(4)),
            match.group(5),
        )

        estimate_us = to_microseconds(
            float(match.group(6)),
            match.group(7),
        )

        upper_us = to_microseconds(
            float(match.group(8)),
            match.group(9),
        )

        rows.append({
            "scheme": scheme,
            "operation": operation,
            "batch_size": batch_size,
            "lower_us": lower_us,
            "runtime_us": estimate_us,
            "upper_us": upper_us,
        })

    return rows


# ============================================================
# Validation
# ============================================================

def validate(rows):
    found = {
        (
            row["scheme"],
            row["operation"],
            row["batch_size"],
        )
        for row in rows
    }

    expected = {
        (
            f"Scheme{i}",
            operation,
            batch_size,
        )
        for i in range(1, 5)
        for operation in OPERATIONS
        for batch_size in BATCH_SIZES
    }

    missing = sorted(
        expected - found
    )

    unexpected = sorted(
        found - expected
    )

    if missing:
        print(
            "\nERROR: Some scaling benchmark results "
            "were not found:"
        )

        for scheme, operation, batch_size in missing:
            print(
                f"  - {scheme}/{operation}/{batch_size}"
            )

        print(
            "\nRaw benchmark output has been saved to:"
            f"\n{RAW_OUTPUT}"
        )

        sys.exit(1)

    if unexpected:
        print(
            "\nWARNING: Unexpected scaling benchmark "
            "results were found:"
        )

        for scheme, operation, batch_size in unexpected:
            print(
                f"  - {scheme}/{operation}/{batch_size}"
            )

    if len(rows) != len(found):
        print(
            "\nWARNING: Duplicate scaling benchmark "
            "records were parsed."
        )


# ============================================================
# Write CSV
# ============================================================

def write_csv(rows):
    scheme_names = {
        "Scheme1": "Scheme 1",
        "Scheme2": "Scheme 2",
        "Scheme3": "Scheme 3",
        "Scheme4": "Scheme 4",
    }

    operation_names = {
        "PreSign": "pSign",
        "PreVrfy": "pVrfy",
        "Adapt": "Adapt",
        "Extract": "(Sec)Ext",
        "Vrfy": "Vrfy",
    }

    rows = sorted(
        rows,
        key=lambda row: (
            int(
                row["scheme"]
                .replace("Scheme", "")
            ),
            OPERATIONS.index(
                row["operation"]
            ),
            row["batch_size"],
        ),
    )

    with open(
        OUTPUT_CSV,
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        fieldnames = [
            "scheme",
            "operation",
            "batch_size",
            "lower_us",
            "runtime_us",
            "upper_us",
        ]

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for row in rows:
            writer.writerow({
                "scheme":
                    scheme_names[
                        row["scheme"]
                    ],
                "operation":
                    operation_names[
                        row["operation"]
                    ],
                "batch_size":
                    row["batch_size"],
                "lower_us":
                    f"{row['lower_us']:.6f}",
                "runtime_us":
                    f"{row['runtime_us']:.6f}",
                "upper_us":
                    f"{row['upper_us']:.6f}",
            })


# ============================================================
# Main
# ============================================================

def main():
    print(
        "Running Criterion scaling benchmarks...\n"
    )

    command = [
        "cargo",
        "bench",
        "--bench",
        "benchmark_scaling",
        "--",
        "--color",
        "never",
    ]

    process = subprocess.Popen(
        command,
        cwd=PROJECT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    output_lines = []

    assert process.stdout is not None

    for line in process.stdout:
        print(
            line,
            end="",
            flush=True,
        )

        output_lines.append(
            line
        )

    process.wait()

    output = "".join(
        output_lines
    )

    RAW_OUTPUT.write_text(
        output,
        encoding="utf-8",
    )

    if process.returncode != 0:
        print(
            "\nERROR: cargo bench failed."
            f"\nSee: {RAW_OUTPUT}"
        )

        sys.exit(
            process.returncode
        )

    rows = parse_scaling_runtime(
        output
    )

    validate(
        rows
    )

    write_csv(
        rows
    )

    print(
        f"\nCSV written to:\n{OUTPUT_CSV}"
    )

    print(
        "\nGenerating scaling figure...\n"
    )

    plot_process = subprocess.run(
        [
            sys.executable,
            str(PLOT_SCRIPT),
        ],
        cwd=PROJECT_DIR,
    )

    if plot_process.returncode != 0:
        print(
            "\nERROR: Failed to generate scaling figure."
        )

        sys.exit(
            plot_process.returncode
        )

    print(
        "\nScaling figure generated successfully."
    )


if __name__ == "__main__":
    main()
