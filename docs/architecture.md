# Network IDS Simulation — System Architecture

## 1. Purpose

This document describes the architecture of the Network IDS Simulation and the relationship between traffic generation, feature extraction, detection engines, risk scoring, alert generation, incident management, backend APIs, and the analyst dashboard.

## 2. High-Level Architecture

```text
Network Traffic / Simulation
          |
          v
Feature Extraction
          |
          +-------------------+
          |                   |
          v                   v
 Signature Detection     Anomaly Detection
          |                   |
          +---------+---------+
                    |
                    v
             ML Detection
                    |
                    v
          Hybrid Risk Engine
                    |
                    v
          Risk / Severity / Decision
                    |
                    v
             Alert Generator
                    |
                    v
          Incident Management
                    |
                    v
              FastAPI API
                    |
                    v
             Web Dashboard
                    |
                    v
             Investigation
                    |
          +---------+---------+
          |                   |
          v                   v
       RESOLVED         FALSE_POSITIVE
```

## 3. Major Components

| Component | Location | Responsibility |
|---|---|---|
| Traffic generation | `simulator/` | Generates controlled network traffic/flow scenarios |
| Feature extraction | `ids/feature_extractor.py` | Produces detection-ready network features |
| Rule engine | `ids/rule_engine.py` | Applies configured signatures/rules |
| Anomaly detector | `ids/anomaly_detector.py` | Identifies behavioural deviations |
| ML detector | `ids/ml_detector.py` | Performs Random Forest classification |
| Risk engine | `ids/risk_engine.py` | Combines detector outputs |
| Alert generator | `ids/alert_generator.py` | Creates security alerts |
| Incident manager | `ids/incident_manager.py` | Manages security incidents |
| API | `api/main.py` | Exposes backend operations |
| Frontend | `frontend/` | Provides analyst-facing dashboard |

## 4. Data Flow

1. Traffic is generated or supplied as network-flow data.
2. Features are extracted from the traffic.
3. The same flow is evaluated by the signature, anomaly, and ML detection layers.
4. Detector outputs are combined by the hybrid risk engine.
5. The resulting risk score determines severity and decision information.
6. Suspicious events are converted into alerts.
7. Alerts can be managed as incidents.
8. FastAPI exposes the resulting information to the dashboard.
9. Analysts investigate events and update their status.

## 5. Detection Layer

### Signature Detection

The signature layer uses configured rules in:

`config/detection_rules.json`

Implementation:

`ids/rule_engine.py`

Its main advantage is deterministic detection of known patterns.

### Anomaly Detection

The anomaly layer compares behavioural characteristics against the project's normal traffic baseline:

`data/normal_traffic_baseline.json`

Implementation:

`ids/anomaly_detector.py`

### Machine Learning

The ML layer uses the trained Random Forest artifact:

`models/random_forest_ids.joblib`

Implementation:

`ids/ml_detector.py`

Recorded configuration:

- 200 estimators
- Maximum depth 12
- Minimum samples leaf 2
- Random state 42

## 6. Hybrid Risk Layer

The project combines:

- Signature: 35%
- Anomaly: 30%
- Machine Learning: 35%

The authoritative configuration is:

`config/risk_config.json`

The output is used to determine risk, severity, decision, and explanation information.

## 7. Application Layer

The FastAPI application in `api/main.py` provides the service boundary between the detection data and the frontend.

The frontend consists of:

- `frontend/index.html`
- `frontend/style.css`
- `frontend/app.js`

The browser retrieves backend data through API calls and renders the analyst-facing dashboard.

## 8. Persistence

Important project artifacts are maintained under `data/`:

- network traffic
- network features
- rule results
- anomaly results
- ML results
- hybrid risk results
- alerts
- incidents
- evaluation metrics

The trained ML artifact is stored under `models/`.

## 9. Architectural Characteristics

The implementation is modular: individual detection mechanisms are separated from risk aggregation, alert generation, incident handling, and presentation.

This separation makes it possible to evaluate and modify individual layers without redesigning the entire application.

## 10. Scope

This is a controlled IDS simulation. It is not a claim of production-grade packet capture, enterprise-scale deployment, or generalization to arbitrary real-world networks.
