"""
Network IDS - Evaluation Engine
--------------------------------

Evaluates the hybrid IDS against ground-truth labels.

Input:
    data/hybrid_risk_results.csv

Output:
    data/evaluation_metrics.json
    data/confusion_matrix.csv
    data/scenario_metrics.csv
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    BASE_DIR / "data" / "hybrid_risk_results.csv"
)

METRICS_FILE = (
    BASE_DIR / "data" / "evaluation_metrics.json"
)

CONFUSION_FILE = (
    BASE_DIR / "data" / "confusion_matrix.csv"
)

SCENARIO_FILE = (
    BASE_DIR / "data" / "scenario_metrics.csv"
)


# ============================================================
# LABEL NORMALIZATION
# ============================================================

BENIGN_LABELS = {
    "NORMAL",
    "BENIGN",
}

ATTACK_LABELS = {
    "ATTACK",
    "ANOMALOUS",
    "MALICIOUS",
    "SUSPICIOUS",
}


def normalize_ground_truth(
    value: str,
) -> int:
    """
    Convert dataset labels into binary ground truth.

    0 = benign
    1 = attack/suspicious
    """

    label = str(
        value
    ).strip().upper()

    if label in BENIGN_LABELS:

        return 0

    if label in ATTACK_LABELS:

        return 1

    raise ValueError(
        f"Unknown ground-truth label: {value}"
    )


# ============================================================
# LOAD DATA
# ============================================================

def load_data() -> pd.DataFrame:

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"Evaluation input not found:\n"
            f"{INPUT_FILE}\n\n"
            "Run first:\n"
            "python ids\\risk_engine.py"
        )

    dataframe = pd.read_csv(
        INPUT_FILE
    )

    required = [
        "flow_id",
        "risk_score",
        "severity",
        "decision",
        "ground_truth_label",
        "scenario_type",
    ]

    missing = [
        column
        for column in required
        if column not in dataframe.columns
    ]

    if missing:

        raise ValueError(
            "Evaluation input is missing:\n"
            + "\n".join(
                f"  - {column}"
                for column in missing
            )
        )

    if dataframe.empty:

        raise ValueError(
            "Evaluation dataset is empty."
        )

    return dataframe


# ============================================================
# PREDICTION
# ============================================================

def create_predictions(
    dataframe: pd.DataFrame,
) -> tuple[
    pd.Series,
    pd.Series,
]:
    """
    Create binary ground truth and prediction.

    Ground truth:
        0 = benign
        1 = attack

    Prediction:
        0 = MONITOR
        1 = INVESTIGATE
    """

    y_true = dataframe[
        "ground_truth_label"
    ].apply(
        normalize_ground_truth
    )

    y_pred = (
        dataframe[
            "decision"
        ]
        .astype(str)
        .str.upper()
        .eq("INVESTIGATE")
        .astype(int)
    )

    return (
        y_true,
        y_pred,
    )


# ============================================================
# CONFUSION MATRIX
# ============================================================

def calculate_confusion_matrix(
    y_true: pd.Series,
    y_pred: pd.Series,
) -> pd.DataFrame:

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=[
            0,
            1,
        ],
    )

    return pd.DataFrame(
        matrix,
        index=[
            "Actual_Benign",
            "Actual_Attack",
        ],
        columns=[
            "Predicted_Benign",
            "Predicted_Attack",
        ],
    )


# ============================================================
# METRICS
# ============================================================

def calculate_metrics(
    y_true: pd.Series,
    y_pred: pd.Series,
    dataframe: pd.DataFrame,
) -> dict:

    accuracy = accuracy_score(
        y_true,
        y_pred,
    )

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    # --------------------------------------------------------
    # ROC-AUC
    # --------------------------------------------------------

    try:

        auc = roc_auc_score(
            y_true,
            dataframe[
                "risk_score"
            ],
        )

    except ValueError:

        auc = None

    # --------------------------------------------------------
    # Confusion matrix values
    # --------------------------------------------------------

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=[
            0,
            1,
        ],
    )

    true_negative = int(
        matrix[0, 0]
    )

    false_positive = int(
        matrix[0, 1]
    )

    false_negative = int(
        matrix[1, 0]
    )

    true_positive = int(
        matrix[1, 1]
    )

    total = len(
        dataframe
    )

    attack_count = int(
        y_true.sum()
    )

    benign_count = (
        total
        - attack_count
    )

    detected_attack_count = (
        true_positive
    )

    missed_attack_count = (
        false_negative
    )

    false_alarm_rate = (
        false_positive
        / benign_count
        if benign_count > 0
        else 0.0
    )

    detection_rate = (
        true_positive
        / attack_count
        if attack_count > 0
        else 0.0
    )

    metrics = {
        "dataset": {
            "total_flows": total,
            "benign_flows": benign_count,
            "attack_flows": attack_count,
        },

        "classification": {
            "accuracy": float(
                accuracy
            ),
            "precision": float(
                precision
            ),
            "recall": float(
                recall
            ),
            "f1_score": float(
                f1
            ),
            "roc_auc": (
                float(auc)
                if auc is not None
                else None
            ),
        },

        "confusion_matrix": {
            "true_negative": true_negative,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "true_positive": true_positive,
        },

        "operational": {
            "detected_attacks": (
                detected_attack_count
            ),
            "missed_attacks": (
                missed_attack_count
            ),
            "false_alarms": (
                false_positive
            ),
            "false_alarm_rate": float(
                false_alarm_rate
            ),
            "detection_rate": float(
                detection_rate
            ),
        },
    }

    return metrics


# ============================================================
# SCENARIO METRICS
# ============================================================

def calculate_scenario_metrics(
    dataframe: pd.DataFrame,
    y_true: pd.Series,
    y_pred: pd.Series,
) -> pd.DataFrame:
    """
    Calculate performance separately for every
    traffic scenario.
    """

    working = dataframe.copy()

    working[
        "y_true"
    ] = y_true.values

    working[
        "y_pred"
    ] = y_pred.values

    rows = []

    for scenario, group in (
        working.groupby(
            "scenario_type",
            dropna=False,
        )
    ):

        true_values = group[
            "y_true"
        ]

        pred_values = group[
            "y_pred"
        ]

        rows.append(
            {
                "scenario_type": str(
                    scenario
                ),

                "flows": len(
                    group
                ),

                "attacks": int(
                    true_values.sum()
                ),

                "alerts": int(
                    pred_values.sum()
                ),

                "accuracy": accuracy_score(
                    true_values,
                    pred_values,
                ),

                "precision": precision_score(
                    true_values,
                    pred_values,
                    zero_division=0,
                ),

                "recall": recall_score(
                    true_values,
                    pred_values,
                    zero_division=0,
                ),

                "f1_score": f1_score(
                    true_values,
                    pred_values,
                    zero_division=0,
                ),
            }
        )

    return pd.DataFrame(
        rows
    ).sort_values(
        "scenario_type"
    )


# ============================================================
# REPORT
# ============================================================

def print_report(
    metrics: dict,
    scenario_metrics: pd.DataFrame,
) -> None:

    print("\n" + "=" * 80)
    print("NETWORK IDS — EVALUATION REPORT")
    print("=" * 80)

    dataset = metrics[
        "dataset"
    ]

    classification = metrics[
        "classification"
    ]

    operational = metrics[
        "operational"
    ]

    confusion = metrics[
        "confusion_matrix"
    ]

    print("\nDataset:")
    print(
        f"  Total flows      : "
        f"{dataset['total_flows']:,}"
    )

    print(
        f"  Benign flows     : "
        f"{dataset['benign_flows']:,}"
    )

    print(
        f"  Attack flows     : "
        f"{dataset['attack_flows']:,}"
    )

    print("\nClassification metrics:")

    print(
        f"  Accuracy         : "
        f"{classification['accuracy']:.4f}"
    )

    print(
        f"  Precision        : "
        f"{classification['precision']:.4f}"
    )

    print(
        f"  Recall           : "
        f"{classification['recall']:.4f}"
    )

    print(
        f"  F1-score         : "
        f"{classification['f1_score']:.4f}"
    )

    if classification["roc_auc"] is not None:

        print(
            f"  ROC-AUC          : "
            f"{classification['roc_auc']:.4f}"
        )

    print("\nConfusion matrix:")

    print(
        f"  True Negatives   : "
        f"{confusion['true_negative']:,}"
    )

    print(
        f"  False Positives  : "
        f"{confusion['false_positive']:,}"
    )

    print(
        f"  False Negatives  : "
        f"{confusion['false_negative']:,}"
    )

    print(
        f"  True Positives   : "
        f"{confusion['true_positive']:,}"
    )

    print("\nOperational metrics:")

    print(
        f"  Detected attacks : "
        f"{operational['detected_attacks']:,}"
    )

    print(
        f"  Missed attacks   : "
        f"{operational['missed_attacks']:,}"
    )

    print(
        f"  False alarms     : "
        f"{operational['false_alarms']:,}"
    )

    print(
        f"  Detection rate   : "
        f"{operational['detection_rate']:.4f}"
    )

    print(
        f"  False alarm rate : "
        f"{operational['false_alarm_rate']:.4f}"
    )

    print("\nScenario-level metrics:")

    if scenario_metrics.empty:

        print(
            "  No scenario metrics available."
        )

    else:

        print(
            scenario_metrics.to_string(
                index=False
            )
        )


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    print("=" * 80)
    print("NETWORK IDS — EVALUATION ENGINE")
    print("=" * 80)

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    print(
        "\nLoading hybrid risk results..."
    )

    dataframe = load_data()

    print(
        f"Loaded {len(dataframe):,} flows."
    )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    print(
        "\nPreparing evaluation labels..."
    )

    y_true, y_pred = create_predictions(
        dataframe
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    print(
        "Calculating performance metrics..."
    )

    metrics = calculate_metrics(
        y_true,
        y_pred,
        dataframe,
    )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    confusion = calculate_confusion_matrix(
        y_true,
        y_pred,
    )

    # --------------------------------------------------------
    # Scenario analysis
    # --------------------------------------------------------

    scenario_metrics = (
        calculate_scenario_metrics(
            dataframe,
            y_true,
            y_pred,
        )
    )

    # --------------------------------------------------------
    # Save metrics
    # --------------------------------------------------------

    METRICS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with METRICS_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            metrics,
            file,
            indent=4,
        )

    confusion.to_csv(
        CONFUSION_FILE
    )

    scenario_metrics.to_csv(
        SCENARIO_FILE,
        index=False,
    )

    # --------------------------------------------------------
    # Print
    # --------------------------------------------------------

    print_report(
        metrics,
        scenario_metrics,
    )

    print(
        f"\nMetrics saved to:\n"
        f"{METRICS_FILE}"
    )

    print(
        f"Confusion matrix saved to:\n"
        f"{CONFUSION_FILE}"
    )

    print(
        f"Scenario metrics saved to:\n"
        f"{SCENARIO_FILE}"
    )

    print("\n" + "=" * 80)
    print(
        "IDS EVALUATION COMPLETED SUCCESSFULLY"
    )
    print("=" * 80)


if __name__ == "__main__":
    main()