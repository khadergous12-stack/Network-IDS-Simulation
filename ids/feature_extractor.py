"""
Network IDS - Feature Extraction Engine
---------------------------------------

Converts raw synthetic network-flow records into
security-oriented numerical features.

This module does NOT perform intrusion detection.

Its responsibility is only:

Raw Flow
   ↓
Feature Extraction
   ↓
Enriched Flow

The resulting features will later be consumed by:
- Signature Detection
- Anomaly Detection
- Machine Learning
- Risk Scoring
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "network_traffic.csv"
OUTPUT_FILE = BASE_DIR / "data" / "network_features.csv"


# ============================================================
# REQUIRED RAW COLUMNS
# ============================================================

REQUIRED_COLUMNS = [
    "flow_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "packet_count",
    "byte_count",
    "duration_seconds",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
    "average_packet_size",
    "label",
    "scenario_type",
]


# ============================================================
# VALIDATION
# ============================================================

def validate_input_dataframe(dataframe: pd.DataFrame) -> None:
    """
    Validate that the input dataset contains all
    fields required for feature extraction.
    """

    missing_columns = [
        column
        for column in REQUIRED_COLUMNS
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise ValueError(
            "Missing required columns:\n"
            + "\n".join(
                f"  - {column}"
                for column in missing_columns
            )
        )

    if dataframe.empty:
        raise ValueError(
            "Input dataset is empty."
        )


# ============================================================
# SAFE DIVISION
# ============================================================

def safe_divide(
    numerator: pd.Series,
    denominator: pd.Series,
) -> pd.Series:
    """
    Perform element-wise division while preventing
    division-by-zero errors.
    """

    denominator = denominator.replace(0, np.nan)

    result = numerator / denominator

    return result.replace(
        [np.inf, -np.inf],
        np.nan,
    ).fillna(0.0)


# ============================================================
# INDIVIDUAL FEATURE CALCULATIONS
# ============================================================

def calculate_packets_per_second(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Calculate packets transmitted per second.
    """

    return safe_divide(
        dataframe["packet_count"],
        dataframe["duration_seconds"],
    )


def calculate_bytes_per_second(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Calculate bytes transmitted per second.
    """

    return safe_divide(
        dataframe["byte_count"],
        dataframe["duration_seconds"],
    )


def calculate_average_packet_size(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Calculate average packet size from raw packet
    and byte counts.
    """

    calculated = safe_divide(
        dataframe["byte_count"],
        dataframe["packet_count"],
    )

    return calculated


def calculate_connection_rate(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Calculate network connections per second.
    """

    return safe_divide(
        dataframe["connection_count"],
        dataframe["duration_seconds"],
    )


def calculate_failed_connection_ratio(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Calculate the percentage of connections that failed.
    """

    return safe_divide(
        dataframe["failed_connection_count"],
        dataframe["connection_count"],
    )


def calculate_syn_ratio(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Calculate SYN packets relative to total packets.
    """

    return safe_divide(
        dataframe["syn_count"],
        dataframe["packet_count"],
    )


def calculate_rst_ratio(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Calculate RST packets relative to total packets.
    """

    return safe_divide(
        dataframe["rst_count"],
        dataframe["packet_count"],
    )


# ============================================================
# PORT / IP DIVERSITY
# ============================================================

def calculate_destination_port_diversity(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Estimate destination-port diversity at the source-IP level.

    For each source IP, count the number of unique
    destination ports observed in the dataset.
    """

    diversity = dataframe.groupby(
        "source_ip"
    )["destination_port"].transform(
        "nunique"
    )

    return diversity.astype(int)


def calculate_destination_ip_diversity(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Estimate destination-IP diversity at the source-IP level.
    """

    diversity = dataframe.groupby(
        "source_ip"
    )["destination_ip"].transform(
        "nunique"
    )

    return diversity.astype(int)


def calculate_source_port_diversity(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Calculate unique source-port diversity per source IP.
    """

    diversity = dataframe.groupby(
        "source_ip"
    )["source_port"].transform(
        "nunique"
    )

    return diversity.astype(int)


# ============================================================
# FLOW STATISTICS
# ============================================================

def calculate_source_flow_count(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Number of flows observed for each source IP.
    """

    return dataframe.groupby(
        "source_ip"
    )["flow_id"].transform(
        "count"
    ).astype(int)


def calculate_source_failed_flow_count(
    dataframe: pd.DataFrame,
) -> pd.Series:
    """
    Total failed connections associated with each source IP.
    """

    return dataframe.groupby(
        "source_ip"
    )["failed_connection_count"].transform(
        "sum"
    ).astype(int)


# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

def extract_features(
    dataframe: pd.DataFrame,
) -> pd.DataFrame:
    """
    Create an enriched feature dataframe.

    The original raw fields are preserved.
    """

    validate_input_dataframe(dataframe)

    features = dataframe.copy()

    # --------------------------------------------------------
    # Basic rate features
    # --------------------------------------------------------

    features["packets_per_second"] = (
        calculate_packets_per_second(features)
    )

    features["bytes_per_second"] = (
        calculate_bytes_per_second(features)
    )

    # --------------------------------------------------------
    # Packet statistics
    # --------------------------------------------------------

    features["calculated_average_packet_size"] = (
        calculate_average_packet_size(features)
    )

    # --------------------------------------------------------
    # Connection statistics
    # --------------------------------------------------------

    features["connection_rate"] = (
        calculate_connection_rate(features)
    )

    features["failed_connection_ratio"] = (
        calculate_failed_connection_ratio(features)
    )

    # --------------------------------------------------------
    # TCP behavior
    # --------------------------------------------------------

    features["syn_ratio"] = (
        calculate_syn_ratio(features)
    )

    features["rst_ratio"] = (
        calculate_rst_ratio(features)
    )

    # --------------------------------------------------------
    # Diversity features
    # --------------------------------------------------------

    features["unique_destination_ports"] = (
        calculate_destination_port_diversity(features)
    )

    features["unique_destination_ips"] = (
        calculate_destination_ip_diversity(features)
    )

    features["unique_source_ports"] = (
        calculate_source_port_diversity(features)
    )

    # --------------------------------------------------------
    # Source-level context
    # --------------------------------------------------------

    features["source_flow_count"] = (
        calculate_source_flow_count(features)
    )

    features["source_failed_flow_count"] = (
        calculate_source_failed_flow_count(features)
    )

    # --------------------------------------------------------
    # Numeric cleanup
    # --------------------------------------------------------

    numeric_columns = features.select_dtypes(
        include=["number"]
    ).columns

    features[numeric_columns] = (
        features[numeric_columns]
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0)
    )

    # --------------------------------------------------------
    # Round calculated floating-point features
    # --------------------------------------------------------

    floating_features = [
        "packets_per_second",
        "bytes_per_second",
        "calculated_average_packet_size",
        "connection_rate",
        "failed_connection_ratio",
        "syn_ratio",
        "rst_ratio",
    ]

    for column in floating_features:
        features[column] = features[column].round(4)

    return features


# ============================================================
# FEATURE VALIDATION
# ============================================================

def validate_features(
    dataframe: pd.DataFrame,
) -> None:
    """
    Validate that the expected security features
    were successfully created.
    """

    required_features = [
        "packets_per_second",
        "bytes_per_second",
        "calculated_average_packet_size",
        "connection_rate",
        "failed_connection_ratio",
        "syn_ratio",
        "rst_ratio",
        "unique_destination_ports",
        "unique_destination_ips",
        "unique_source_ports",
        "source_flow_count",
        "source_failed_flow_count",
    ]

    missing = [
        feature
        for feature in required_features
        if feature not in dataframe.columns
    ]

    if missing:
        raise ValueError(
            "Feature extraction failed. "
            f"Missing features: {missing}"
        )

    for feature in required_features:

        if dataframe[feature].isna().any():
            raise ValueError(
                f"Feature '{feature}' contains NaN values."
            )

        if np.isinf(
            dataframe[feature].to_numpy()
        ).any():
            raise ValueError(
                f"Feature '{feature}' contains infinite values."
            )


# ============================================================
# SUMMARY
# ============================================================

def print_feature_summary(
    dataframe: pd.DataFrame,
) -> None:
    """
    Print a human-readable feature summary.
    """

    feature_columns = [
        "packets_per_second",
        "bytes_per_second",
        "calculated_average_packet_size",
        "connection_rate",
        "failed_connection_ratio",
        "syn_ratio",
        "rst_ratio",
        "unique_destination_ports",
        "unique_destination_ips",
        "unique_source_ports",
        "source_flow_count",
        "source_failed_flow_count",
    ]

    print("\n" + "=" * 80)
    print("FEATURE EXTRACTION SUMMARY")
    print("=" * 80)

    print(
        f"\nTotal records: {len(dataframe):,}"
    )

    print("\nGenerated features:")

    for feature in feature_columns:
        print(f"  ✓ {feature}")

    print("\nFeature statistics:")

    print(
        dataframe[feature_columns]
        .describe()
        .round(4)
        .to_string()
    )


# ============================================================
# FILE PROCESSING
# ============================================================

def load_input_data() -> pd.DataFrame:
    """
    Load the synthetic traffic dataset.
    """

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"\nInput dataset not found:\n{INPUT_FILE}\n\n"
            "Run:\n"
            "python simulator\\generate_dataset.py"
        )

    return pd.read_csv(INPUT_FILE)


def save_features(
    dataframe: pd.DataFrame,
) -> None:
    """
    Save extracted features.
    """

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    dataframe.to_csv(
        OUTPUT_FILE,
        index=False,
    )


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """
    Execute the complete feature-extraction pipeline.
    """

    print("=" * 80)
    print("NETWORK IDS — FEATURE EXTRACTION")
    print("=" * 80)

    print(
        f"\nInput file:\n{INPUT_FILE}"
    )

    dataframe = load_input_data()

    print(
        f"\nLoaded records: {len(dataframe):,}"
    )

    print("\nExtracting security features...")

    features = extract_features(
        dataframe
    )

    print("Validating extracted features...")

    validate_features(
        features
    )

    print("\nSaving feature dataset...")

    save_features(
        features
    )

    print_feature_summary(
        features
    )

    print("\n" + "=" * 80)
    print("FEATURE EXTRACTION COMPLETED SUCCESSFULLY")
    print("=" * 80)

    print(
        f"\nOutput file:\n{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()