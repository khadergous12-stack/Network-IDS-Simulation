import json
from pathlib import Path

import pandas as pd
import pytest


ROOT = Path(__file__).resolve().parents[1]
FEATURES = ROOT / "data" / "network_features.csv"


EXPECTED_FEATURES = {
    "packet_count",
    "byte_count",
    "duration_seconds",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
    "average_packet_size",
    "packets_per_second",
    "bytes_per_second",
    "calculated_average_packet_size",
    "connection_rate",
    "failed_connection_ratio",
    "syn_ratio",
    "rst_ratio",
}


def test_network_features_file_exists():
    assert FEATURES.exists(), f"Missing dataset: {FEATURES}"


def test_network_features_has_expected_shape():
    df = pd.read_csv(FEATURES)
    assert len(df) == 6000
    assert len(df.columns) == 29


def test_network_features_contains_core_columns():
    df = pd.read_csv(FEATURES)
    missing = EXPECTED_FEATURES - set(df.columns)
    assert not missing, f"Missing expected feature columns: {sorted(missing)}"


def test_core_numeric_features_are_numeric():
    df = pd.read_csv(FEATURES)

    columns = [
        "packet_count",
        "byte_count",
        "duration_seconds",
        "connection_count",
        "failed_connection_count",
        "syn_count",
        "rst_count",
        "average_packet_size",
    ]

    for column in columns:
        converted = pd.to_numeric(df[column], errors="coerce")
        assert converted.notna().all(), f"Non-numeric values found in {column}"


def test_feature_dataset_contains_labels():
    df = pd.read_csv(FEATURES)
    assert "label" in df.columns
    assert df["label"].notna().all()


def test_feature_dataset_has_expected_context_columns():
    df = pd.read_csv(FEATURES)

    required = {
        "flow_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "label",
        "scenario_type",
    }

    assert required.issubset(df.columns)
