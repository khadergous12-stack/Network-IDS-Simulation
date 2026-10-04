import json
from pathlib import Path

import pandas as pd
import pytest


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "detection_rules.json"
RESULTS = ROOT / "data" / "rule_detection_results.csv"


def test_detection_rules_config_exists():
    assert CONFIG.exists(), f"Missing rule configuration: {CONFIG}"


def test_detection_rules_config_is_valid_json():
    data = json.loads(CONFIG.read_text(encoding="utf-8"))
    assert isinstance(data, (dict, list))


def test_rule_results_file_exists():
    assert RESULTS.exists(), f"Missing rule result artifact: {RESULTS}"


def test_rule_results_are_readable():
    df = pd.read_csv(RESULTS)
    assert not df.empty


def test_rule_results_have_flow_identifier():
    df = pd.read_csv(RESULTS)
    assert "flow_id" in df.columns


def test_rule_engine_module_imports():
    module = pytest.importorskip("ids.rule_engine")
    assert module is not None
