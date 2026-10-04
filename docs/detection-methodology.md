# Network IDS Simulation — Detection Methodology

## 1. Detection Objective

The detection pipeline is designed to identify suspicious network-flow behaviour by combining three complementary approaches:

1. Signature-based detection
2. Anomaly detection
3. Machine-learning detection

The combined output is processed by the hybrid risk engine.

## 2. Input Data

The principal feature dataset is:

`data/network_features.csv`

Recorded dataset size:

- 6,000 flows
- 29 columns

Important features include:

- `packet_count`
- `byte_count`
- `duration_seconds`
- `connection_count`
- `failed_connection_count`
- `syn_count`
- `rst_count`
- `average_packet_size`
- `packets_per_second`
- `bytes_per_second`
- `connection_rate`
- `failed_connection_ratio`
- `syn_ratio`
- `rst_ratio`
- `unique_destination_ports`
- `unique_destination_ips`
- `unique_source_ports`
- `source_flow_count`
- `source_failed_flow_count`

## 3. Feature Extraction

Implementation:

`ids/feature_extractor.py`

The feature layer transforms traffic information into values used by the detection engines. Both raw traffic quantities and derived behavioural rates/ratios are represented.

## 4. Signature Detection

Implementation:

`ids/rule_engine.py`

Configuration:

`config/detection_rules.json`

Signature detection is deterministic and is intended to identify patterns represented by configured rules.

Output:

`data/rule_detection_results.csv`

## 5. Anomaly Detection

Implementation:

`ids/anomaly_detector.py`

Baseline:

`data/normal_traffic_baseline.json`

The anomaly layer evaluates deviations in network behaviour. It is complementary to signatures because unusual behaviour may be detected even when a flow does not match a specific known rule.

Output:

`data/anomaly_detection_results.csv`

## 6. Machine Learning Detection

Implementation:

`ids/ml_detector.py`

Model:

`models/random_forest_ids.joblib`

The model is a Random Forest classifier configured with:

- 200 estimators
- Maximum depth 12
- Minimum samples leaf 2
- Random state 42

Stored model metrics:

- Accuracy: 0.99917
- Precision: 0.99723
- Recall: 1.00000
- F1: 0.99861
- ROC-AUC: 0.99991

These results apply to the stored evaluation data and should not be interpreted as production-network performance.

Output:

`data/ml_detection_results.csv`

## 7. Hybrid Risk

The three detection signals are combined using the configured weighting:

```text
Signature = 35%
Anomaly   = 30%
ML        = 35%
```

Implementation:

`ids/risk_engine.py`

Configuration:

`config/risk_config.json`

## 8. Severity

The configured risk model uses:

| Score | Severity |
|---:|---|
| Below 25 | LOW |
| 25–49 | LOW |
| 50–74 | MEDIUM |
| 75–89 | HIGH |
| 90–100 | CRITICAL |

## 9. Alert Creation

Implementation:

`ids/alert_generator.py`

Alerts preserve detection and risk information so that an analyst can understand why an event was raised.

## 10. Evaluation

Stored IDS evaluation results include:

```text
Total flows: 6000
Benign flows: 4200
Attack flows: 1800
Accuracy: 98.65%
Precision: 100%
Recall: 95.5%
F1 Score: 97.70%
False positives: 0
Detected attacks: 1719
Missed attacks: 81
```

Supporting files:

- `data/evaluation_metrics.json`
- `data/confusion_matrix.csv`
- `data/scenario_metrics.csv`

## 11. Interpretation

The evaluation demonstrates strong performance on the project's generated evaluation data. The missed attacks show that the system is not perfect, while the absence of recorded false positives in this evaluation is specific to the controlled dataset.

For a production evaluation, independent real-world or representative traffic would be required.
