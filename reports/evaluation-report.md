# IDS Evaluation Report

## 1. Evaluation Overview

The project evaluation measures the performance of the implemented IDS pipeline on the available controlled/generated dataset.

## 2. Recorded Dataset

```text
Total flows       : 6000
Benign flows      : 4200
Attack flows      : 1800
```

## 3. Recorded IDS Results

| Metric | Result |
|---|---:|
| Accuracy | 98.65% |
| Precision | 100% |
| Recall | 95.5% |
| F1 Score | 97.70% |
| False Positives | 0 |
| Detected Attacks | 1719 |
| Missed Attacks | 81 |

## 4. Confusion Information

The project retains:

```text
data/confusion_matrix.csv
```

This artifact should be used when generating visual confusion-matrix plots or tables for the final report.

## 5. Scenario Analysis

Scenario-level results are retained in:

```text
data/scenario_metrics.csv
```

This provides a basis for comparing detector behaviour across generated traffic scenarios.

## 6. Interpretation

The recorded accuracy and F1 score indicate strong performance on the evaluated project dataset.

The recall of 95.5% indicates that some attack flows were not detected. Specifically:

```text
1800 total attack flows
1719 detected
81 missed
```

The recorded false-positive count is zero.

## 7. Important Limitation

These results should not be presented as proof that the IDS will achieve the same performance on real enterprise networks.

The evaluation is based on the project's controlled/generated data and therefore may not represent:

- Real traffic diversity.
- Real network noise.
- Unseen attacks.
- Concept drift.
- Production class imbalance.
- Adversarial behaviour.

## 8. Recommended Future Evaluation

Future evaluation should include:

- Independent datasets.
- Temporal holdout data.
- Realistic benign traffic.
- Multiple attack families.
- False-positive-rate analysis.
- Per-class precision/recall.
- Cross-environment validation.
- Drift testing.
