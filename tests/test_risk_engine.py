import json
from pathlib import Path

import pandas as pd
import pytest


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "risk_config.json"
RESULTS = ROOT / "data" / "hybrid_risk_results.csv"


def test_risk_engine_module_imports():
    module = pytest.importorskip("ids.risk_engine")
    assert module is not None


def test_risk_config_exists():
    assert CONFIG.exists(), f"Missing risk configuration: {CONFIG}"


def test_risk_config_is_valid_json():
    data = json.loads(CONFIG.read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_hybrid_results_exist():
    assert RESULTS.exists(), f"Missing hybrid results: {RESULTS}"


def test_hybrid_results_have_risk_fields():
    df = pd.read_csv(RESULTS)

    required = {
        "flow_id",
        "risk_score",
        "severity",
        "decision",
    }

    assert required.issubset(df.columns)


def test_risk_scores_are_in_expected_range():
    df = pd.read_csv(RESULTS)
    scores = pd.to_numeric(df["risk_score"], errors="coerce").dropna()

    assert not scores.empty
    assert ((scores >= 0) & (scores <= 100)).all()
