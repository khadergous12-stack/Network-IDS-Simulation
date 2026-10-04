# Model Card — Random Forest Network IDS Classifier

## 1. Model Overview

**Model type:** Random Forest classifier

**Purpose:** Network-flow classification as one detection signal within a hybrid Network IDS.

**Implementation:** `ids/ml_detector.py`

**Artifact:** `models/random_forest_ids.joblib`

The model is not the sole decision-maker. Its output is combined with signature and anomaly detection by the hybrid risk engine.

## 2. Intended Use

The model is intended for:

- Academic IDS demonstration.
- Controlled network-security experimentation.
- Network-flow classification.
- Defensive security analytics.
- Supporting analyst alert prioritization.

## 3. Out-of-Scope Use

The model should not be treated as:

- A standalone production IDS.
- A replacement for network-security analysts.
- A guarantee of attack detection.
- Evidence that the system generalizes to arbitrary real-world traffic.

## 4. Model Configuration

```text
Algorithm: Random Forest
Estimators: 200
Maximum Depth: 12
Minimum Samples Leaf: 2
Random State: 42
```

## 5. Input Characteristics

The model works with engineered network-flow features.

Examples include:

```text
packet_count
byte_count
duration_seconds
connection_count
failed_connection_count
syn_count
rst_count
average_packet_size
packets_per_second
bytes_per_second
connection_rate
failed_connection_ratio
syn_ratio
rst_ratio
unique_destination_ports
unique_destination_ips
unique_source_ports
source_flow_count
source_failed_flow_count
```

The exact feature-processing implementation in `ids/ml_detector.py` is authoritative.

## 6. Recorded Metrics

```text
Accuracy   = 0.99917
Precision  = 0.99723
Recall     = 1.00000
F1         = 0.99861
ROC-AUC    = 0.99991
```

## 7. Evaluation Context

The metrics were obtained from the project's controlled/generated evaluation workflow.

They should therefore be interpreted as project-level benchmark results rather than real-world security guarantees.

## 8. Risks

Potential risks include:

- Dataset bias.
- Synthetic traffic characteristics.
- Distribution shift.
- Unseen attack behaviour.
- Feature drift.
- Label-quality issues.
- Over-optimistic evaluation when train/test distributions are too similar.

## 9. Human Oversight

ML output should be interpreted together with:

- Signature matches.
- Anomaly score.
- Risk score.
- Severity.
- Flow context.
- Analyst investigation.

The dashboard's investigation workflow supports this human-in-the-loop model.

## 10. Recommended Future Validation

Before production use:

1. Evaluate on independent data.
2. Test temporal separation.
3. Evaluate multiple attack families.
4. Measure false-positive rate on realistic benign traffic.
5. Test class imbalance.
6. Monitor feature drift.
7. Version datasets and models.
8. Establish retraining criteria.
