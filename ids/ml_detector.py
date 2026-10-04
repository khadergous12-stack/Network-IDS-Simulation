"""
Network IDS - Machine Learning Detection Engine
------------------------------------------------

Baseline supervised ML detector using Random Forest.

Responsibilities:
    1. Load engineered network features.
    2. Prepare supervised training data.
    3. Train a Random Forest classifier.
    4. Evaluate the model.
    5. Save the trained model.
    6. Generate predictions and probabilities.
    7. Produce ML detection results for the hybrid risk engine.

Important:
The model is a baseline supervised detector.
Its output is one signal among several IDS detection layers.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

FEATURE_FILE = (
    BASE_DIR / "data" / "network_features.csv"
)

MODEL_DIR = (
    BASE_DIR / "models"
)

MODEL_FILE = (
    MODEL_DIR / "random_forest_ids.joblib"
)

METRICS_FILE = (
    MODEL_DIR / "random_forest_metrics.json"
)

OUTPUT_FILE = (
    BASE_DIR / "data" / "ml_detection_results.csv"
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42

TEST_SIZE = 0.20

N_ESTIMATORS = 200

MAX_DEPTH = 12

MIN_SAMPLES_LEAF = 2


# ============================================================
# ML FEATURES
# ============================================================

ML_FEATURES = [
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


# ============================================================
# LABEL MAPPING
# ============================================================

LABEL_MAP = {
    "NORMAL": 0,
    "BENIGN": 0,

    "ATTACK": 1,
    "ANOMALOUS": 1,
    "MALICIOUS": 1,
    "SUSPICIOUS": 1,
}


# ============================================================
# VALIDATION
# ============================================================

def validate_dataset(
    dataframe: pd.DataFrame,
) -> None:
    """
    Validate the feature dataset before ML processing.
    """

    required_columns = (
        ML_FEATURES
        + [
            "flow_id",
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "label",
            "scenario_type",
        ]
    )

    missing = [
        column
        for column in required_columns
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
# LABEL PREPARATION
# ============================================================

def prepare_labels(
    labels: pd.Series,
) -> pd.Series:
    """
    Convert textual labels into binary ML targets.

    NORMAL -> 0
    ATTACK -> 1
    """

    normalized = (
        labels
        .astype(str)
        .str.strip()
        .str.upper()
    )

    unknown_labels = sorted(
        set(normalized.unique())
        - set(LABEL_MAP.keys())
    )

    if unknown_labels:

        raise ValueError(
            "Unknown labels found: "
            f"{unknown_labels}\n"
            f"Supported labels: "
            f"{sorted(LABEL_MAP.keys())}"
        )

    return normalized.map(
        LABEL_MAP
    ).astype(int)


# ============================================================
# FEATURE PREPARATION
# ============================================================

def prepare_features(
    dataframe: pd.DataFrame,
) -> pd.DataFrame:
    """
    Prepare numerical features for Random Forest.
    """

    features = dataframe[
        ML_FEATURES
    ].copy()

    for column in ML_FEATURES:

        features[column] = pd.to_numeric(
            features[column],
            errors="coerce",
        )

    features = (
        features
        .replace(
            [np.inf, -np.inf],
            np.nan,
        )
        .fillna(0.0)
    )

    return features


# ============================================================
# TRAINING
# ============================================================

def train_model(
    X_train: pd.DataFrame,
    y_train: pd.Series,
) -> RandomForestClassifier:
    """
    Train the Random Forest baseline model.
    """

    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        min_samples_leaf=MIN_SAMPLES_LEAF,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
    )

    model.fit(
        X_train,
        y_train,
    )

    return model


# ============================================================
# METRICS
# ============================================================

def calculate_metrics(
    model: RandomForestClassifier,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> dict[str, Any]:
    """
    Calculate model performance metrics.
    """

    predictions = model.predict(
        X_test
    )

    probabilities = model.predict_proba(
        X_test
    )

    attack_probability = (
        probabilities[:, 1]
        if probabilities.shape[1] > 1
        else np.zeros(
            len(probabilities)
        )
    )

    metrics: dict[str, Any] = {}

    metrics["accuracy"] = float(
        accuracy_score(
            y_test,
            predictions,
        )
    )

    metrics["precision"] = float(
        precision_score(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    metrics["recall"] = float(
        recall_score(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    metrics["f1_score"] = float(
        f1_score(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    try:

        metrics["roc_auc"] = float(
            roc_auc_score(
                y_test,
                attack_probability,
            )
        )

    except ValueError:

        metrics["roc_auc"] = None

    metrics["confusion_matrix"] = (
        confusion_matrix(
            y_test,
            predictions,
        ).tolist()
    )

    metrics["classification_report"] = (
        classification_report(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    return metrics


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

def get_feature_importance(
    model: RandomForestClassifier,
) -> list[dict[str, float]]:
    """
    Return Random Forest feature importance.
    """

    importance = pd.DataFrame(
        {
            "feature": ML_FEATURES,
            "importance": (
                model.feature_importances_
            ),
        }
    )

    importance = importance.sort_values(
        "importance",
        ascending=False,
    )

    return [
        {
            "feature": row["feature"],
            "importance": float(
                row["importance"]
            ),
        }
        for _, row in importance.iterrows()
    ]


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(
    model: RandomForestClassifier,
) -> None:
    """
    Save trained Random Forest model.
    """

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        model,
        MODEL_FILE,
    )


# ============================================================
# SAVE METRICS
# ============================================================

def save_metrics(
    metrics: dict[str, Any],
    feature_importance: list[dict[str, float]],
) -> None:
    """
    Save training and evaluation metadata.
    """

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = {
        "model": {
            "algorithm": "Random Forest",
            "n_estimators": N_ESTIMATORS,
            "max_depth": MAX_DEPTH,
            "min_samples_leaf": MIN_SAMPLES_LEAF,
            "random_state": RANDOM_STATE,
        },
        "features": ML_FEATURES,
        "metrics": metrics,
        "feature_importance": feature_importance,
    }

    with METRICS_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            output,
            file,
            indent=4,
        )


# ============================================================
# PREDICTIONS
# ============================================================

def generate_predictions(
    model: RandomForestClassifier,
    dataframe: pd.DataFrame,
) -> pd.DataFrame:
    """
    Generate ML predictions for every flow.

    ml_attack_probability is converted to a 0-100 scale.
    """

    X = prepare_features(
        dataframe
    )

    predictions = model.predict(
        X
    )

    probabilities = model.predict_proba(
        X
    )

    if probabilities.shape[1] > 1:

        attack_probability = (
            probabilities[:, 1]
        )

    else:

        attack_probability = (
            np.zeros(
                len(dataframe)
            )
        )

    attack_probability = np.clip(
        attack_probability,
        0.0,
        1.0,
    )

    ml_score = (
        attack_probability
        * 100.0
    )

    ml_classification = np.where(
        predictions == 1,
        "SUSPICIOUS",
        "NORMAL",
    )

    results = pd.DataFrame(
        {
            "flow_id": dataframe[
                "flow_id"
            ].values,

            "timestamp": dataframe[
                "timestamp"
            ].values,

            "source_ip": dataframe[
                "source_ip"
            ].values,

            "destination_ip": dataframe[
                "destination_ip"
            ].values,

            "protocol": dataframe[
                "protocol"
            ].values,

            "source_port": dataframe[
                "source_port"
            ].values,

            "destination_port": dataframe[
                "destination_port"
            ].values,

            "ml_prediction": predictions,

            "ml_classification": (
                ml_classification
            ),

            "ml_attack_probability": (
                attack_probability.round(4)
            ),

            "ml_score": (
                ml_score.round(2)
            ),

            "ground_truth_label": dataframe[
                "label"
            ].values,

            "scenario_type": dataframe[
                "scenario_type"
            ].values,
        }
    )

    return results


# ============================================================
# PRINT METRICS
# ============================================================

def print_metrics(
    metrics: dict[str, Any],
) -> None:
    """
    Print evaluation metrics.
    """

    print("\n" + "=" * 80)
    print("RANDOM FOREST EVALUATION")
    print("=" * 80)

    print(
        f"\nAccuracy  : "
        f"{metrics['accuracy']:.4f}"
    )

    print(
        f"Precision : "
        f"{metrics['precision']:.4f}"
    )

    print(
        f"Recall    : "
        f"{metrics['recall']:.4f}"
    )

    print(
        f"F1 Score  : "
        f"{metrics['f1_score']:.4f}"
    )

    if metrics["roc_auc"] is not None:

        print(
            f"ROC-AUC   : "
            f"{metrics['roc_auc']:.4f}"
        )

    print("\nConfusion Matrix:")

    for row in metrics[
        "confusion_matrix"
    ]:

        print(
            f"  {row}"
        )


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """
    Execute complete Random Forest training pipeline.
    """

    print("=" * 80)
    print("NETWORK IDS — MACHINE LEARNING DETECTOR")
    print("=" * 80)

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    if not FEATURE_FILE.exists():

        raise FileNotFoundError(
            f"\nFeature dataset not found:\n"
            f"{FEATURE_FILE}\n\n"
            "Run first:\n"
            "python ids\\feature_extractor.py"
        )

    print(
        f"\nLoading dataset:\n"
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
    # Prepare data
    # --------------------------------------------------------

    X = prepare_features(
        dataframe
    )

    y = prepare_labels(
        dataframe["label"]
    )

    print("\nDataset distribution:")

    distribution = (
        y.value_counts()
        .sort_index()
    )

    print(
        f"  NORMAL : "
        f"{distribution.get(0, 0):,}"
    )

    print(
        f"  ATTACK : "
        f"{distribution.get(1, 0):,}"
    )

    if y.nunique() < 2:

        raise ValueError(
            "The dataset must contain at least "
            "two classes for supervised training."
        )

    # --------------------------------------------------------
    # Train/test split
    # --------------------------------------------------------

    print(
        "\nCreating stratified train/test split..."
    )

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y,
        )
    )

    print(
        f"Training records : {len(X_train):,}"
    )

    print(
        f"Testing records  : {len(X_test):,}"
    )

    # --------------------------------------------------------
    # Train model
    # --------------------------------------------------------

    print(
        "\nTraining Random Forest..."
    )

    model = train_model(
        X_train,
        y_train,
    )

    print(
        "Random Forest training completed."
    )

    # --------------------------------------------------------
    # Evaluate
    # --------------------------------------------------------

    metrics = calculate_metrics(
        model,
        X_test,
        y_test,
    )

    print_metrics(
        metrics
    )

    # --------------------------------------------------------
    # Feature importance
    # --------------------------------------------------------

    feature_importance = (
        get_feature_importance(
            model
        )
    )

    print(
        "\nTop feature importance:"
    )

    for item in feature_importance[:10]:

        print(
            f"  {item['feature']:<35}"
            f"{item['importance']:.4f}"
        )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    save_model(
        model
    )

    print(
        f"\nModel saved to:\n"
        f"{MODEL_FILE}"
    )

    # --------------------------------------------------------
    # Save metrics
    # --------------------------------------------------------

    save_metrics(
        metrics,
        feature_importance,
    )

    print(
        f"Metrics saved to:\n"
        f"{METRICS_FILE}"
    )

    # --------------------------------------------------------
    # Generate predictions
    # --------------------------------------------------------

    print(
        "\nGenerating ML predictions..."
    )

    results = generate_predictions(
        model,
        dataframe,
    )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    results.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    # --------------------------------------------------------
    # Prediction summary
    # --------------------------------------------------------

    suspicious = results[
        results["ml_classification"]
        == "SUSPICIOUS"
    ]

    print(
        f"\nTotal flows evaluated : "
        f"{len(results):,}"
    )

    print(
        f"ML suspicious flows   : "
        f"{len(suspicious):,}"
    )

    print(
        f"Average ML score      : "
        f"{results['ml_score'].mean():.2f}"
    )

    print(
        f"\nPredictions saved to:\n"
        f"{OUTPUT_FILE}"
    )

    print("\n" + "=" * 80)
    print(
        "MACHINE LEARNING DETECTION COMPLETED"
    )
    print("=" * 80)


if __name__ == "__main__":
    main()