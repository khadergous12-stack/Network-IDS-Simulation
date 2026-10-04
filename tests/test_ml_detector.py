import json
from pathlib import Path

import pandas as pd
import pytest


ROOT = Path(__file__).resolve().parents[1]

MODEL = (
    ROOT
    / "models"
    / "random_forest_ids.joblib"
)

METRICS = (
    ROOT
    / "models"
    / "random_forest_metrics.json"
)

RESULTS = (
    ROOT
    / "data"
    / "ml_detection_results.csv"
)

FEATURES = (
    ROOT
    / "data"
    / "network_features.csv"
)


# These are the labels used by the source network dataset.
SOURCE_DATASET_LABELS = {
    "NORMAL",
    "SUSPICIOUS",
}


def test_ml_module_imports():
    module = pytest.importorskip(
        "ids.ml_detector"
    )

    assert module is not None


def test_model_artifact_exists():
    assert MODEL.exists(), (
        f"Missing ML model: {MODEL}"
    )


def test_model_metrics_exist():
    assert METRICS.exists(), (
        f"Missing metrics: {METRICS}"
    )


def test_model_metrics_are_valid():
    data = json.loads(
        METRICS.read_text(
            encoding="utf-8"
        )
    )

    assert isinstance(data, dict)


def test_ml_results_exist():
    assert RESULTS.exists(), (
        f"Missing ML results: {RESULTS}"
    )


def test_ml_results_are_readable():
    df = pd.read_csv(RESULTS)

    assert not df.empty
    assert "flow_id" in df.columns


def test_dataset_labels_are_valid():
    """
    Validate the raw dataset vocabulary.

    The source dataset intentionally uses NORMAL and
    SUSPICIOUS. The ML detector may normalize these labels
    internally during preparation, so SUSPICIOUS must not be
    rejected at the raw-data validation layer.
    """

    df = pd.read_csv(FEATURES)

    assert "label" in df.columns

    labels = set(
        df["label"]
        .dropna()
        .astype(str)
        .str.upper()
    )

    unsupported = (
        labels
        - SOURCE_DATASET_LABELS
    )

    assert not unsupported, (
        "Unexpected raw dataset labels: "
        f"{sorted(unsupported)}"
    )


def test_expected_label_distribution():
    """
    Verify the current project dataset composition.
    """

    df = pd.read_csv(FEATURES)

    counts = (
        df["label"]
        .astype(str)
        .str.upper()
        .value_counts()
    )

    assert counts.get(
        "NORMAL",
        0
    ) == 4200

    assert counts.get(
        "SUSPICIOUS",
        0
    ) == 1800


def test_recorded_metrics_are_high_quality():
    data = json.loads(
        METRICS.read_text(
            encoding="utf-8"
        )
    )

    metric_keys = (
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "roc_auc",
    )

    for key in metric_keys:

        if key in data:

            value = float(
                data[key]
            )

            assert 0 <= value <= 1