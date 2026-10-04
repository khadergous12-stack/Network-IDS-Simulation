import json
from pathlib import Path

import pandas as pd
import pytest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "data" / "normal_traffic_baseline.json"
RESULTS = ROOT / "data" / "anomaly_detection_results.csv"


def test_anomaly_baseline_exists():
    assert BASELINE.exists(), f"Missing anomaly baseline: {BASELINE}"


def test_anomaly_baseline_is_valid_json():
    data = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_anomaly_results_exist():
    assert RESULTS.exists(), f"Missing anomaly results: {RESULTS}"


def test_anomaly_results_are_readable():
    df = pd.read_csv(RESULTS)
    assert not df.empty
    assert "flow_id" in df.columns


def test_anomaly_detector_module_imports():
    module = pytest.importorskip("ids.anomaly_detector")
    assert module is not None
