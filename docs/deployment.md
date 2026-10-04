# Network IDS Simulation — Deployment & Operations Guide

## 1. Scope

This document describes the local development/deployment procedure for the current Network IDS Simulation.

The project is a controlled simulation and is not presented as a hardened production deployment.

## 2. Prerequisites

Recommended environment:

- Windows
- Python 3.x
- PowerShell
- Git
- Modern web browser

## 3. Create Virtual Environment

From the project root:

```powershell
python -m venv venv
```

Activate:

```powershell
.\venv\Scripts\Activate.ps1
```

## 4. Install Dependencies

```powershell
pip install -r requirements.txt
```

## 5. Start Backend

```powershell
uvicorn api.main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

Swagger:

```text
http://127.0.0.1:8000/docs
```

OpenAPI:

```text
http://127.0.0.1:8000/openapi.json
```

## 6. Start Frontend

Open a second terminal:

```powershell
python -m http.server 5500 --directory frontend
```

Frontend:

```text
http://localhost:5500
```

## 7. Operational Startup

Recommended startup sequence:

```text
1. Activate venv
2. Verify dependencies
3. Start FastAPI
4. Verify /api/health
5. Start frontend server
6. Open dashboard
7. Verify dashboard summary
8. Verify alerts
9. Verify incidents
10. Verify traffic analytics
11. Verify investigation workflow
```

## 8. Configuration

Runtime configuration is maintained under:

```text
config/
├── alert_config.json
├── detection_rules.json
├── incident_config.json
└── risk_config.json
```

Changes to these files can affect detection and risk behaviour. They should therefore be version-controlled and reviewed.

## 9. Data

Generated and evaluated artifacts are stored under:

```text
data/
```

Important categories:

- Traffic
- Features
- Detector outputs
- Hybrid risk
- Alerts
- Incidents
- Evaluation metrics

## 10. ML Model

The trained model is stored under:

```text
models/random_forest_ids.joblib
```

Supporting metrics:

```text
models/random_forest_metrics.json
```

A production deployment should include model versioning, validation, provenance, and controlled retraining procedures.

## 11. Logging

Uvicorn provides application-level request and exception logging during local execution.

For production use, structured logging should be added for:

- Request ID
- Event ID
- Detector execution
- Risk calculation
- Alert generation
- Incident state changes
- Authentication events
- Errors

## 12. Security Hardening for Future Deployment

Before production deployment, consider:

- HTTPS/TLS
- Authentication
- Role-based authorization
- Secret management
- Input validation
- Rate limiting
- Audit logging
- CORS restriction
- Secure headers
- Container isolation
- Network segmentation
- Database-backed persistence
- Centralized monitoring

## 13. Production Architecture — Future

A future production-oriented architecture could be:

```text
Network Sensors
      ↓
Flow / Event Collector
      ↓
Message Queue
      ↓
Feature Processing
      ↓
Detection Workers
      ├── Signature
      ├── Anomaly
      └── ML
      ↓
Risk Engine
      ↓
Event Store / SIEM
      ↓
Alert & Incident Service
      ↓
Analyst Dashboard
```

## 14. Backup

The following should be preserved for reproducibility:

- Source code
- Configuration
- Dataset/version
- Model artifact
- Evaluation results
- Documentation

Secrets must never be included in backups committed to Git.

## 15. Troubleshooting

### Backend does not start

Check:

```powershell
python --version
pip install -r requirements.txt
```

Then inspect the Uvicorn traceback.

### Dashboard cannot reach API

Confirm:

```text
http://127.0.0.1:8000/api/health
```

and check browser developer-console errors.

### Traffic endpoint returns 500

Inspect the backend traceback and verify the required dataset columns exist in:

```text
data/network_features.csv
```

### Model-related errors

Verify:

```text
models/random_forest_ids.joblib
```

exists and that the model's expected feature schema matches the current feature-processing pipeline.

## 16. Deployment Status

Current deployment mode:

```text
Local development / controlled demonstration
```

Production deployment is outside the current project's validated scope.
