# ML Module — Network IDS Simulation

## Purpose

This directory documents the machine-learning component of the Network IDS Simulation.

The ML detector is one of three complementary detection layers:

```text
Signature Detection
        +
Anomaly Detection
        +
Machine Learning Detection
        ↓
Hybrid Risk Engine
```

## Implementation

Main detector:

```text
ids/ml_detector.py
```

Model artifact:

```text
models/random_forest_ids.joblib
```

Model metrics:

```text
models/random_forest_metrics.json
```

ML result dataset:

```text
data/ml_detection_results.csv
```

Primary feature dataset:

```text
data/network_features.csv
```

## Model

The implemented classifier is a Random Forest model.

Recorded configuration:

| Parameter | Value |
|---|---:|
| Estimators | 200 |
| Maximum depth | 12 |
| Minimum samples leaf | 2 |
| Random state | 42 |

## Recorded Evaluation

| Metric | Value |
|---|---:|
| Accuracy | 0.99917 |
| Precision | 0.99723 |
| Recall | 1.00000 |
| F1 Score | 0.99861 |
| ROC-AUC | 0.99991 |

These metrics describe the recorded evaluation and must not be treated as proof of equivalent performance on real enterprise traffic.

## Dataset

The current feature dataset contains:

```text
6,000 flows
29 columns
```

Core network features include packet, byte, duration, connection, failed-connection, SYN, RST, and average-packet-size measurements.

Derived behavioural features include packet rate, byte rate, connection rate, failure ratio, SYN ratio, RST ratio, destination/source diversity, and source-level flow counts.

## ML Pipeline

```text
network_features.csv
        ↓
Feature Selection / Preparation
        ↓
Label Preparation
        ↓
Train / Evaluation Processing
        ↓
Random Forest
        ↓
Prediction
        ↓
ML Classification / Score
        ↓
ml_detection_results.csv
        ↓
Hybrid Risk Engine
```

## Important Implementation Note

The ML detector expects the labels supported by the current implementation. During development, an unsupported `SUSPICIOUS` label was encountered. The detector's accepted labels and preprocessing logic in `ids/ml_detector.py` are the authoritative source.

## Reproducibility

For reproducible results, preserve:

- Dataset version.
- Feature schema.
- Model artifact.
- Model configuration.
- Random seed.
- Metrics.
- Detector source code.

## Limitations

- The evaluation dataset is generated/controlled.
- High metrics may reflect the characteristics of the dataset.
- No claim is made about production enterprise-network generalization.
- Model drift and unseen traffic patterns require further evaluation.
