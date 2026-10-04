# Network IDS Simulation — Project Report

## 1. Introduction

Network intrusion detection is an important component of defensive cybersecurity because network traffic can contain patterns associated with malicious or abnormal activity.

The Network IDS Simulation implements a modular defensive pipeline that combines signature-based detection, anomaly detection, machine-learning classification, hybrid risk scoring, alert generation, incident management, and analyst investigation.

## 2. Problem Statement

A single detection technique may be insufficient for identifying diverse network behaviour. Known attacks may be detected effectively by signatures, while previously unseen or behaviourally unusual activity may require anomaly or machine-learning approaches.

The project therefore combines multiple detection signals into a unified risk-driven workflow.

## 3. Objectives

- Simulate network traffic.
- Extract network-flow features.
- Detect known suspicious patterns.
- Identify behavioural anomalies.
- Apply machine-learning classification.
- Combine detection signals through a hybrid risk engine.
- Generate security alerts.
- Manage incidents.
- Provide an analyst-facing dashboard.
- Support investigation and status workflows.

## 4. System Architecture

```text
Traffic
  ↓
Feature Extraction
  ↓
┌─────────────┬─────────────┬─────────────┐
│  Signature  │   Anomaly   │     ML      │
│  Detection  │  Detection  │  Detection  │
└─────────────┴─────────────┴─────────────┘
              ↓
       Hybrid Risk Engine
              ↓
      Risk / Severity / Decision
              ↓
        Alert Generation
              ↓
       Incident Management
              ↓
          FastAPI API
              ↓
       Security Dashboard
              ↓
        Investigation
```

## 5. Dataset

The recorded feature dataset contains:

```text
6,000 flows
29 columns
```

The dataset contains traffic measurements and derived behavioural features.

## 6. Detection Methods

### Signature

Configured rules are applied to identify known patterns.

### Anomaly

Behaviour is compared against the project's normal traffic baseline.

### Machine Learning

A Random Forest classifier provides a learned classification signal.

## 7. Hybrid Risk

The configured detector weights are:

```text
Signature = 35%
Anomaly   = 30%
ML        = 35%
```

The resulting score supports severity and alert prioritization.

## 8. Alert and Incident Workflow

```text
Detection → Alert → Incident → Investigation
```

Analyst status workflow:

```text
NEW → INVESTIGATING → RESOLVED
```

with:

```text
FALSE_POSITIVE
```

as an alternative classification outcome.

## 9. Backend and Frontend

The backend uses FastAPI and the frontend is implemented using HTML, CSS, and JavaScript.

The API provides dashboard, alert, incident, risk, network, traffic, and investigation functionality.

## 10. Conclusion

The project demonstrates an end-to-end defensive IDS workflow in which multiple detection mechanisms are combined with risk scoring and analyst investigation.

The modular architecture provides a foundation for future integration with real traffic sources, threat intelligence, SIEM systems, authentication, and production monitoring.
