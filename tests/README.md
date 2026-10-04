# Network IDS Simulation — Test Suite

This directory contains the automated-test foundation for the Network IDS Simulation.

## Test Philosophy

Tests are designed around the project's existing modules:

```text
ids/
├── feature_extractor.py
├── rule_engine.py
├── anomaly_detector.py
├── ml_detector.py
├── risk_engine.py
├── alert_generator.py
└── incident_manager.py

api/
└── main.py
```

The tests intentionally use defensive imports and inspect available interfaces before making assertions. This reduces the chance that a test file invents an API that is not present in the current implementation.

## Test Areas

| File | Area |
|---|---|
| `test_feature_extractor.py` | Feature/data validation |
| `test_rule_engine.py` | Signature/rule engine |
| `test_anomaly_detector.py` | Anomaly detector |
| `test_ml_detector.py` | ML artifacts and label validation |
| `test_risk_engine.py` | Hybrid risk configuration |
| `test_alert_generator.py` | Alert artifacts |
| `test_incident_manager.py` | Incident artifacts |
| `test_api.py` | FastAPI health/basic integration |

## Running

From the project root:

```powershell
pytest -v
```

For a single module:

```powershell
pytest -v tests/test_feature_extractor.py
```

## Important

The current project implementation is the source of truth for exact function signatures and endpoint schemas. Tests should be extended when new public interfaces are added.

Some tests are artifact/schema tests rather than full behavioural unit tests because they can validate the current project without assuming unverified function names.
