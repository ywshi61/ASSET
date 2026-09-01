import csv
import re
import subprocess
import sys
from pathlib import Path


# ============================================================
# Paths
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parent

OUTPUT_CSV = PROJECT_DIR / "scheme_benchmark.csv"
RAW_OUTPUT = PROJECT_DIR / "benchmark_output.txt"


# ============================================================
# Unit conversion
# ============================================================

def to_microseconds(value: float, unit: str) -> float:
    """
    Convert Criterion runtime units to microseconds.
    """

    unit = unit.strip()

    if unit == "ns":
        return value / 1000.0

    if unit in ("us", "µs", "μs"):
        return value

    if unit == "ms":
        return value * 1000.0

    if unit == "s":
        return value * 1_000_000.0

    raise ValueError(f"Unknown time unit: {unit}")


# ============================================================
# Parse Criterion runtime
# ============================================================

def parse_runtime(output: str):
    """
    Extract the middle estimate from Criterion output.

    Example:

        Scheme1/PreSign
            time: [lower estimate upper]

        Scheme1/Vrfy
            time: [lower estimate upper]

    All results are converted to microseconds.
    """

    results = {}

    pattern = re.compile(
        r"(Scheme[1234])/"
        r"(PreSign|PreVrfy|Adapt|Extract|Vrfy)"
        r".*?"
        r"time:\s*\[\s*"
        r"([0-9.eE+-]+)\s*(ns|us|µs|μs|ms|s)\s+"
        r"([0-9.eE+-]+)\s*(ns|us|µs|μs|ms|s)\s+"
        r"([0-9.eE+-]+)\s*(ns|us|µs|μs|ms|s)"
        r"\s*\]",
        re.DOTALL,
    )

    for match in pattern.finditer(output):
        scheme = match.group(1)
        operation = match.group(2)

        # Criterion interval:
        # [lower, estimate, upper]
        estimate_value = float(match.group(5))
        estimate_unit = match.group(6)

        estimate_us = to_microseconds(
            estimate_value,
            estimate_unit,
        )

        results[(scheme, operation)] = estimate_us

    return results


# ============================================================
# Parse storage
# ============================================================

def parse_storage(output: str):
    """
    Extract storage values printed by benchmark.rs.
    """

    storage = {
        "Scheme1": {
            "presig_bytes": None,
            "signature_bytes": None,
            "ek_bytes": 0,
            "signer_storage_bytes": None,
            "adaptor_storage_bytes": None,
            "blockchain_storage_bytes": None,
        },

        "Scheme2": {
            "presig_bytes": None,
            "signature_bytes": None,
            "ek_bytes": None,
            "signer_storage_bytes": None,
            "adaptor_storage_bytes": None,
            "blockchain_storage_bytes": None,
        },

        "Scheme3": {
            "presig_bytes": None,
            "signature_bytes": None,
            "ek_bytes": None,
            "signer_storage_bytes": None,
            "adaptor_storage_bytes": None,
            "blockchain_storage_bytes": None,
        },

        "Scheme4": {
            "presig_bytes": None,
            "signature_bytes": None,
            "ek_bytes": 0,
            "signer_storage_bytes": None,
            "adaptor_storage_bytes": None,
            "blockchain_storage_bytes": None,
        },
    }


    # --------------------------------------------------------
    # Pre-signature
    # --------------------------------------------------------

    pattern = re.compile(
        r"Scheme\s*([1234])\s+"
        r"pre-signature size:\s*"
        r"(\d+)\s*bytes",
        re.IGNORECASE,
    )

    for match in pattern.finditer(output):
        scheme = f"Scheme{match.group(1)}"
        storage[scheme]["presig_bytes"] = int(
            match.group(2)
        )


    # --------------------------------------------------------
    # Full signature
    # --------------------------------------------------------

    pattern = re.compile(
        r"Scheme\s*([1234])\s+"
        r"full signature size:\s*"
        r"(\d+)\s*bytes",
        re.IGNORECASE,
    )

    for match in pattern.finditer(output):
        scheme = f"Scheme{match.group(1)}"
        storage[scheme]["signature_bytes"] = int(
            match.group(2)
        )


    # --------------------------------------------------------
    # Extraction key
    # --------------------------------------------------------

    pattern = re.compile(
        r"Scheme\s*([1234])\s+"
        r"extraction key size:\s*"
        r"(\d+)\s*bytes",
        re.IGNORECASE,
    )

    for match in pattern.finditer(output):
        scheme = f"Scheme{match.group(1)}"
        storage[scheme]["ek_bytes"] = int(
            match.group(2)
        )


    # --------------------------------------------------------
    # Signer storage
    # --------------------------------------------------------

    pattern = re.compile(
        r"Scheme\s*([1234])\s+"
        r"signer storage size:\s*"
        r"(\d+)\s*bytes",
        re.IGNORECASE,
    )

    for match in pattern.finditer(output):
        scheme = f"Scheme{match.group(1)}"
        storage[scheme]["signer_storage_bytes"] = int(
            match.group(2)
        )


    # --------------------------------------------------------
    # Adaptor storage
    # --------------------------------------------------------

    pattern = re.compile(
        r"Scheme\s*([1234])\s+"
        r"adaptor storage size:\s*"
        r"(\d+)\s*bytes",
        re.IGNORECASE,
    )

    for match in pattern.finditer(output):
        scheme = f"Scheme{match.group(1)}"
        storage[scheme]["adaptor_storage_bytes"] = int(
            match.group(2)
        )


    # --------------------------------------------------------
    # Blockchain storage
    # --------------------------------------------------------

    pattern = re.compile(
        r"Scheme\s*([1234])\s+"
        r"blockchain storage size:\s*"
        r"(\d+)\s*bytes",
        re.IGNORECASE,
    )

    for match in pattern.finditer(output):
        scheme = f"Scheme{match.group(1)}"
        storage[scheme]["blockchain_storage_bytes"] = int(
            match.group(2)
        )

    return storage


# ============================================================
# Validation
# ============================================================

def validate(runtime, storage):
    """
    Make sure all required benchmark results were found.
    """

    operations = [
        "PreSign",
        "PreVrfy",
        "Adapt",
        "Extract",
        "Vrfy",
    ]

    missing = []

    for scheme in [
        "Scheme1",
        "Scheme2",
        "Scheme3",
        "Scheme4",
    ]:

        # Runtime
        for operation in operations:
            if (scheme, operation) not in runtime:
                missing.append(
                    f"{scheme}/{operation}"
                )

        # Storage
        if storage[scheme]["presig_bytes"] is None:
            missing.append(
                f"{scheme} pre-signature size"
            )

        if storage[scheme]["signature_bytes"] is None:
            missing.append(
                f"{scheme} full signature size"
            )

        if storage[scheme]["ek_bytes"] is None:
            missing.append(
                f"{scheme} extraction key size"
            )

        if storage[scheme]["signer_storage_bytes"] is None:
            missing.append(
                f"{scheme} signer storage size"
            )

        if storage[scheme]["adaptor_storage_bytes"] is None:
            missing.append(
                f"{scheme} adaptor storage size"
            )

        if storage[scheme]["blockchain_storage_bytes"] is None:
            missing.append(
                f"{scheme} blockchain storage size"
            )

    if missing:
        print(
            "\nERROR: Some benchmark results "
            "were not found:"
        )

        for item in missing:
            print(f"  - {item}")

        print(
            "\nRaw benchmark output has been saved to:"
            f"\n{RAW_OUTPUT}"
        )

        sys.exit(1)


# ============================================================
# Write CSV
# ============================================================

def write_csv(runtime, storage):

    fieldnames = [
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

    with open(
        OUTPUT_CSV,
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for i in range(1, 5):

            scheme_key = f"Scheme{i}"
            scheme_name = f"Scheme {i}"

            presign = runtime[
                (scheme_key, "PreSign")
            ]

            prevrfy = runtime[
                (scheme_key, "PreVrfy")
            ]

            adapt = runtime[
                (scheme_key, "Adapt")
            ]

            extract = runtime[
                (scheme_key, "Extract")
            ]

            vrfy = runtime[
                (scheme_key, "Vrfy")
            ]

            # ------------------------------------------------
            # Keep the original four-algorithm total:
            #
            # Total =
            # PreSign + PreVrfy + Adapt + Extract
            #
            # Vrfy is reported separately.
            # ------------------------------------------------

            total = (
                presign
                + prevrfy
                + adapt
                + extract
            )

            writer.writerow({
                "scheme": scheme_name,

                "presign_us":
                    f"{presign:.6f}",

                "prevrfy_us":
                    f"{prevrfy:.6f}",

                "adapt_us":
                    f"{adapt:.6f}",

                "extract_us":
                    f"{extract:.6f}",

                "vrfy_us":
                    f"{vrfy:.6f}",

                "total_us":
                    f"{total:.6f}",

                "presig_bytes":
                    storage[
                        scheme_key
                    ]["presig_bytes"],

                "signature_bytes":
                    storage[
                        scheme_key
                    ]["signature_bytes"],

                "ek_bytes":
                    storage[
                        scheme_key
                    ]["ek_bytes"],

                "signer_storage_bytes":
                    storage[
                        scheme_key
                    ]["signer_storage_bytes"],

                "adaptor_storage_bytes":
                    storage[
                        scheme_key
                    ]["adaptor_storage_bytes"],

                "blockchain_storage_bytes":
                    storage[
                        scheme_key
                    ]["blockchain_storage_bytes"],
            })


# ============================================================
# Print summary
# ============================================================

def print_summary(runtime, storage):

    print("\n" + "=" * 72)
    print("Benchmark summary")
    print("=" * 72)

    for i in range(1, 5):

        scheme = f"Scheme{i}"

        presign = runtime[
            (scheme, "PreSign")
        ]

        prevrfy = runtime[
            (scheme, "PreVrfy")
        ]

        adapt = runtime[
            (scheme, "Adapt")
        ]

        extract = runtime[
            (scheme, "Extract")
        ]

        vrfy = runtime[
            (scheme, "Vrfy")
        ]

        total = (
            presign
            + prevrfy
            + adapt
            + extract
        )

        print(f"\nScheme {i}")

        print(
            f"  PreSign : "
            f"{presign:.6f} us"
        )

        print(
            f"  PreVrfy : "
            f"{prevrfy:.6f} us"
        )

        print(
            f"  Adapt   : "
            f"{adapt:.6f} us"
        )

        print(
            f"  Extract : "
            f"{extract:.6f} us"
        )

        print(
            f"  Vrfy    : "
            f"{vrfy:.6f} us"
        )

        print(
            f"  Total   : "
            f"{total:.6f} us"
        )

        print(
            "  Object sizes : "
            f"pre-signature = "
            f"{storage[scheme]['presig_bytes']} B, "
            f"signature = "
            f"{storage[scheme]['signature_bytes']} B, "
            f"ek = "
            f"{storage[scheme]['ek_bytes']} B"
        )

        print(
            "  Storage      : "
            f"signer = "
            f"{storage[scheme]['signer_storage_bytes']} B, "
            f"adaptor = "
            f"{storage[scheme]['adaptor_storage_bytes']} B, "
            f"blockchain = "
            f"{storage[scheme]['blockchain_storage_bytes']} B"
        )

    print("\n" + "=" * 72)


# ============================================================
# Main
# ============================================================

def main():

    print("Running Criterion benchmarks...\n")


    # --------------------------------------------------------
    # Run Criterion
    # --------------------------------------------------------

    command = [
        "cargo",
        "bench",
        "--bench",
        "benchmark",
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


    # --------------------------------------------------------
    # Print benchmark output and save it
    # --------------------------------------------------------

    for line in process.stdout:
        print(
            line,
            end="",
            flush=True,
        )

        output_lines.append(line)


    process.wait()

    output = "".join(output_lines)


    # --------------------------------------------------------
    # Save raw output
    # --------------------------------------------------------

    RAW_OUTPUT.write_text(
        output,
        encoding="utf-8",
    )


    # --------------------------------------------------------
    # Check cargo bench
    # --------------------------------------------------------

    if process.returncode != 0:
        print(
            "\nERROR: cargo bench failed."
            f"\nSee: {RAW_OUTPUT}"
        )

        sys.exit(
            process.returncode
        )


    # --------------------------------------------------------
    # Parse
    # --------------------------------------------------------

    runtime = parse_runtime(output)

    storage = parse_storage(output)


    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    validate(
        runtime,
        storage,
    )


    # --------------------------------------------------------
    # Write CSV
    # --------------------------------------------------------

    write_csv(
        runtime,
        storage,
    )


    # ========================================================
    # Generate figures
    # ========================================================

    print("\nGenerating figures...\n")

    plot_script = PROJECT_DIR / "plot_schemes.py"

    plot_process = subprocess.run(
        [
            sys.executable,
            str(plot_script),
        ],
        cwd=PROJECT_DIR,
    )


    if plot_process.returncode != 0:
        print(
            "\nERROR: Failed to generate figures."
        )

        sys.exit(
            plot_process.returncode
        )


    print(
        "\nFigures generated successfully."
    )


    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print_summary(
        runtime,
        storage,
    )


    # --------------------------------------------------------
    # Output paths
    # --------------------------------------------------------

    print(
        f"\nCSV written to:"
        f"\n{OUTPUT_CSV}"
    )

    print(
        f"\nRaw Criterion output written to:"
        f"\n{RAW_OUTPUT}"
    )


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    main()