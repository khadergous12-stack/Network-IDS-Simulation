from pathlib import Path

import pandas as pd
import pytest


ROOT = Path(__file__).resolve().parents[1]
INCIDENTS = ROOT / "data" / "incidents.csv"
CONFIG = ROOT / "config" / "incident_config.json"


def test_incident_manager_module_imports():
    module = pytest.importorskip("ids.incident_manager")
    assert module is not None


def test_incident_config_exists():
    assert CONFIG.exists(), f"Missing incident configuration: {CONFIG}"


def test_incident_artifact_exists():
    assert INCIDENTS.exists(), f"Missing incident artifact: {INCIDENTS}"


def test_incident_artifact_is_readable():
    df = pd.read_csv(INCIDENTS)
    assert not df.empty


def test_incident_records_have_identifier():
    df = pd.read_csv(INCIDENTS)

    possible = {"incident_id", "flow_id", "alert_id"}
    assert possible.intersection(df.columns), (
        "Incident data does not contain a recognizable identifier column"
    )
