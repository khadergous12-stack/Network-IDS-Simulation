from pathlib import Path

import pandas as pd
import pytest


ROOT = Path(__file__).resolve().parents[1]
ALERTS = ROOT / "data" / "alerts.csv"


def test_alert_generator_module_imports():
    module = pytest.importorskip("ids.alert_generator")
    assert module is not None


def test_alert_artifact_exists():
    assert ALERTS.exists(), f"Missing alerts artifact: {ALERTS}"


def test_alert_artifact_is_readable():
    df = pd.read_csv(ALERTS)
    assert not df.empty


def test_alerts_have_flow_identifier():
    df = pd.read_csv(ALERTS)
    assert "flow_id" in df.columns


def test_alerts_have_severity_when_available():
    df = pd.read_csv(ALERTS)

    if "severity" in df.columns:
        assert df["severity"].notna().all()
