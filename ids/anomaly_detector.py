"""
Network IDS - Statistical Anomaly Detection Engine
--------------------------------------------------

This module detects flows that significantly deviate from
the learned NORMAL traffic baseline.

Method:
    1. Learn baseline statistics from NORMAL traffic.
    2. Calculate robust statistical deviation.
    3. Calculate feature-level anomaly scores.
    4. Combine deviations into an overall 0-100 score.
    5. Classify the flow as NORMAL / ANOMALOUS.

IMPORTANT:
An anomaly does NOT automatically mean an attack.

It means that the observed behavior differs significantly
from the learned normal baseline and deserves investigation.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

FEATURE_FILE = BASE_DIR / "data" / "network_features.csv"

BASELINE_FILE = (
    BASE_DIR / "data" / "normal_traffic_baseline.json"
)

OUTPUT_FILE = (
    BASE_DIR / "data" / "anomaly_detection_results.csv"
)


# ============================================================
# FEATURES USED FOR ANOMALY DETECTION
# ============================================================

ANOMALY_FEATURES = [
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
]


# ============================================================
# CONFIGURATION
# ============================================================

MIN_NORMAL_RECORDS = 10

ANOMALY_THRESHOLD = 60.0

EPSILON = 1e-9


# ============================================================
# VALIDATION
# ============================================================

def validate_dataset(
    dataframe: pd.DataFrame,
) -> None:
    """Validate the feature dataset."""

    required = [
        "flow_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "label",
        "scenario_type",
    ] + ANOMALY_FEATURES

    missing = [
        column
        for column in required
        if column not in dataframe.columns
    ]

    if missing:
        raise ValueError(
            "Missing required columns:\n"
            + "\n".join(
                f"  - {column}"
                for column in missing
            )
        )

    if dataframe.empty:
        raise ValueError(
            "Feature dataset is empty."
        )


# ============================================================
# BASELINE LEARNING
# ============================================================

def build_baseline(
    dataframe: pd.DataFrame,
) -> dict:
    """
    Learn statistical baseline from NORMAL traffic only.

    For every feature we store:
        count
        mean
        standard deviation
        median
        Q1
        Q3
        IQR
    """

    normal = dataframe[
        dataframe["label"].astype(str).str.upper()
        == "NORMAL"
    ].copy()

    if len(normal) < MIN_NORMAL_RECORDS:

        raise ValueError(
            f"At least {MIN_NORMAL_RECORDS} normal records "
            f"are required to build the baseline. "
            f"Only {len(normal)} found."
        )

    baseline = {
        "metadata": {
            "method": "Z-score + IQR",
            "normal_record_count": int(
                len(normal)
            ),
            "features": ANOMALY_FEATURES,
        },
        "features": {},
    }

    for feature in ANOMALY_FEATURES:

        values = pd.to_numeric(
            normal[feature],
            errors="coerce",
        ).dropna()

        if values.empty:
            raise ValueError(
                f"No valid values for feature: {feature}"
            )

        q1 = float(
            values.quantile(0.25)
        )

        q3 = float(
            values.quantile(0.75)
        )

        iqr = q3 - q1

        std = float(
            values.std(
                ddof=1
            )
        )

        baseline["features"][feature] = {
            "count": int(values.count()),
            "mean": float(values.mean()),
            "std": std,
            "median": float(values.median()),
            "q1": q1,
            "q3": q3,
            "iqr": float(iqr),
            "minimum": float(values.min()),
            "maximum": float(values.max()),
        }

    return baseline


# ============================================================
# SAVE BASELINE
# ============================================================

def save_baseline(
    baseline: dict,
) -> None:
    """Save learned baseline to JSON."""

    BASELINE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with BASELINE_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            baseline,
            file,
            indent=4,
        )


# ============================================================
# LOAD BASELINE
# ============================================================

def load_baseline() -> dict:
    """Load previously saved baseline."""

    if not BASELINE_FILE.exists():

        raise FileNotFoundError(
            f"Baseline file not found:\n"
            f"{BASELINE_FILE}"
        )

    with BASELINE_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:

        return json.load(file)


# ============================================================
# Z-SCORE
# ============================================================

def calculate_z_score(
    value: float,
    mean: float,
    std: float,
) -> float:
    """
    Calculate absolute Z-score.

    If standard deviation is zero, fall back to
    a zero deviation when the value equals the mean.
    """

    if std <= EPSILON:

        if abs(value - mean) <= EPSILON:
            return 0.0

        return 10.0

    return abs(
        (value - mean) / std
    )


# ============================================================
# IQR SCORE
# ============================================================

def calculate_iqr_score(
    value: float,
    q1: float,
    q3: float,
    iqr: float,
) -> float:
    """
    Calculate a normalized IQR-based deviation.

    Values inside the normal IQR receive zero deviation.

    Values outside the IQR are measured relative to
    the IQR boundaries.
    """

    if iqr <= EPSILON:

        if q1 <= value <= q3:
            return 0.0

        return 10.0

    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr

    if lower_bound <= value <= upper_bound:
        return 0.0

    if value < lower_bound:

        return (
            lower_bound - value
        ) / (
            iqr + EPSILON
        )

    return (
        value - upper_bound
    ) / (
        iqr + EPSILON
    )


# ============================================================
# NORMALIZE Z-SCORE
# ============================================================

def normalize_z_score(
    z_score: float,
) -> float:
    """
    Convert Z-score to 0-100 anomaly contribution.

    Approximation:
        Z <= 1  -> low
        Z = 3    -> moderate/high
        Z >= 6   -> maximum
    """

    normalized = (
        (z_score - 1.0)
        / 5.0
    ) * 100.0

    return float(
        np.clip(
            normalized,
            0.0,
            100.0,
        )
    )


# ============================================================
# NORMALIZE IQR
# ============================================================

def normalize_iqr_score(
    iqr_score: float,
) -> float:
    """
    Convert IQR deviation into a 0-100 score.
    """

    normalized = (
        iqr_score
        / 5.0
    ) * 100.0

    return float(
        np.clip(
            normalized,
            0.0,
            100.0,
        )
    )


# ============================================================
# FEATURE ANOMALY SCORE
# ============================================================

def calculate_feature_anomaly(
    value: float,
    statistics: dict,
) -> dict:
    """
    Calculate combined Z-score and IQR anomaly
    for one feature.
    """

    mean = float(
        statistics["mean"]
    )

    std = float(
        statistics["std"]
    )

    q1 = float(
        statistics["q1"]
    )

    q3 = float(
        statistics["q3"]
    )

    iqr = float(
        statistics["iqr"]
    )

    z_score = calculate_z_score(
        value,
        mean,
        std,
    )

    iqr_score = calculate_iqr_score(
        value,
        q1,
        q3,
        iqr,
    )

    z_normalized = normalize_z_score(
        z_score
    )

    iqr_normalized = normalize_iqr_score(
        iqr_score
    )

    combined_score = (
        0.6 * z_normalized
        + 0.4 * iqr_normalized
    )

    return {
        "value": float(value),
        "z_score": round(
            z_score,
            4,
        ),
        "iqr_deviation": round(
            iqr_score,
            4,
        ),
        "feature_score": round(
            float(
                np.clip(
                    combined_score,
                    0.0,
                    100.0,
                )
            ),
            4,
        ),
    }


# ============================================================
# FLOW ANOMALY
# ============================================================

def calculate_flow_anomaly(
    flow: pd.Series,
    baseline: dict,
) -> dict:
    """
    Calculate anomaly score for one flow.

    The final score is a weighted average of
    feature-level anomaly scores.

    Higher score = greater deviation from normal baseline.
    """

    feature_results = {}

    feature_scores = []

    for feature in ANOMALY_FEATURES:

        value = float(
            flow[feature]
        )

        statistics = baseline[
            "features"
        ][feature]

        result = calculate_feature_anomaly(
            value,
            statistics,
        )

        feature_results[feature] = result

        feature_scores.append(
            result["feature_score"]
        )

    if feature_scores:

        raw_score = float(
            np.mean(
                feature_scores
            )
        )

    else:

        raw_score = 0.0

    anomaly_score = float(
        np.clip(
            raw_score,
            0.0,
            100.0,
        )
    )

    anomalous = (
        anomaly_score
        >= ANOMALY_THRESHOLD
    )

    return {
        "anomaly_score": round(
            anomaly_score,
            2,
        ),
        "anomaly_classification": (
            "ANOMALOUS"
            if anomalous
            else "NORMAL"
        ),
        "feature_results": feature_results,
    }


# ============================================================
# EXPLANATION
# ============================================================

def build_explanation(
    feature_results: dict,
) -> str:
    """
    Identify the most anomalous features and create
    a human-readable explanation.
    """

    ranked = sorted(
        feature_results.items(),
        key=lambda item: item[1][
            "feature_score"
        ],
        reverse=True,
    )

    significant = [
        (
            feature,
            details["feature_score"],
        )
        for feature, details in ranked
        if details["feature_score"] >= 40
    ]

    if not significant:

        return (
            "No feature showed significant "
            "deviation from the learned baseline."
        )

    explanations = []

    for feature, score in significant[:3]:

        explanations.append(
            f"{feature} deviation score "
            f"{score:.1f}"
        )

    return (
        "Significant baseline deviations: "
        + "; ".join(
            explanations
        )
    )


# ============================================================
# DATASET ANALYSIS
# ============================================================

def analyze_dataset(
    dataframe: pd.DataFrame,
    baseline: dict,
) -> pd.DataFrame:
    """
    Calculate anomaly information for every flow.
    """

    results = []

    for _, flow in dataframe.iterrows():

        analysis = calculate_flow_anomaly(
            flow,
            baseline,
        )

        explanation = build_explanation(
            analysis["feature_results"]
        )

        results.append(
            {
                "flow_id": flow["flow_id"],
                "timestamp": flow["timestamp"],
                "source_ip": flow["source_ip"],
                "destination_ip": flow[
                    "destination_ip"
                ],
                "protocol": flow["protocol"],
                "source_port": flow["source_port"],
                "destination_port": flow[
                    "destination_port"
                ],
                "anomaly_score": analysis[
                    "anomaly_score"
                ],
                "anomaly_classification": analysis[
                    "anomaly_classification"
                ],
                "anomaly_explanation": explanation,
                "ground_truth_label": flow[
                    "label"
                ],
                "scenario_type": flow[
                    "scenario_type"
                ],
            }
        )

    return pd.DataFrame(results)


# ============================================================
# FEATURE STATISTICS DISPLAY
# ============================================================

def print_baseline_summary(
    baseline: dict,
) -> None:
    """Print baseline summary."""

    metadata = baseline["metadata"]

    print("\n" + "=" * 80)
    print("NORMAL TRAFFIC BASELINE")
    print("=" * 80)

    print(
        f"\nNormal records used: "
        f"{metadata['normal_record_count']:,}"
    )

    print(
        f"Method: "
        f"{metadata['method']}"
    )

    print("\nFeatures used:")

    for feature in ANOMALY_FEATURES:
        print(
            f"  ✓ {feature}"
        )


# ============================================================
# RESULT SUMMARY
# ============================================================

def print_result_summary(
    results: pd.DataFrame,
) -> None:
    """Print anomaly detection statistics."""

    total = len(results)

    anomalous = results[
        results[
            "anomaly_classification"
        ]
        == "ANOMALOUS"
    ]

    normal = results[
        results[
            "anomaly_classification"
        ]
        == "NORMAL"
    ]

    print("\n" + "=" * 80)
    print("ANOMALY DETECTION SUMMARY")
    print("=" * 80)

    print(
        f"\nTotal flows evaluated : {total:,}"
    )

    print(
        f"Normal                : {len(normal):,}"
    )

    print(
        f"Anomalous             : {len(anomalous):,}"
    )

    if total > 0:

        print(
            f"Anomaly rate          : "
            f"{len(anomalous) / total * 100:.2f}%"
        )

    print(
        f"\nAverage anomaly score : "
        f"{results['anomaly_score'].mean():.2f}"
    )

    print(
        f"Maximum anomaly score : "
        f"{results['anomaly_score'].max():.2f}"
    )


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """Run the complete anomaly-detection pipeline."""

    print("=" * 80)
    print("NETWORK IDS — ANOMALY DETECTION")
    print("=" * 80)

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    if not FEATURE_FILE.exists():

        raise FileNotFoundError(
            f"\nFeature file not found:\n"
            f"{FEATURE_FILE}\n\n"
            "Run first:\n"
            "python ids\\feature_extractor.py"
        )

    print(
        f"\nLoading feature dataset:\n"
        f"{FEATURE_FILE}"
    )

    dataframe = pd.read_csv(
        FEATURE_FILE
    )

    validate_dataset(
        dataframe
    )

    print(
        f"Loaded {len(dataframe):,} flows."
    )

    # --------------------------------------------------------
    # Build baseline
    # --------------------------------------------------------

    print(
        "\nLearning NORMAL traffic baseline..."
    )

    baseline = build_baseline(
        dataframe
    )

    save_baseline(
        baseline
    )

    print_baseline_summary(
        baseline
    )

    print(
        f"\nBaseline saved to:\n"
        f"{BASELINE_FILE}"
    )

    # --------------------------------------------------------
    # Analyze flows
    # --------------------------------------------------------

    print(
        "\nCalculating anomaly scores..."
    )

    results = analyze_dataset(
        dataframe,
        baseline,
    )

    # --------------------------------------------------------
    # Save results
    # --------------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    results.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print_result_summary(
        results
    )

    print(
        f"\nResults saved to:\n"
        f"{OUTPUT_FILE}"
    )

    print("\n" + "=" * 80)
    print(
        "ANOMALY DETECTION COMPLETED SUCCESSFULLY"
    )
    print("=" * 80)


if __name__ == "__main__":
    main()