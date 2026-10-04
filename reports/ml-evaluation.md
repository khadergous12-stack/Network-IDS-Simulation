# Machine Learning Evaluation Report

## 1. Model

The ML component uses a Random Forest classifier.

Artifact:

```text
models/random_forest_ids.joblib
```

Implementation:

```text
ids/ml_detector.py
```

## 2. Configuration

| Parameter | Value |
|---|---:|
| Estimators | 200 |
| Maximum Depth | 12 |
| Minimum Samples Leaf | 2 |
| Random State | 42 |

## 3. Recorded Metrics

| Metric | Value |
|---|---:|
| Accuracy | 0.99917 |
| Precision | 0.99723 |
| Recall | 1.00000 |
| F1 Score | 0.99861 |
| ROC-AUC | 0.99991 |

## 4. Interpretation

The recorded results show very strong classification performance on the evaluated project data.

The perfect recorded recall means all evaluated positive examples were identified under the project's evaluation conditions.

The precision of 0.99723 indicates that the evaluated positive predictions were highly accurate.

## 5. Caution

The high scores must be interpreted within the dataset context.

They do not establish that:

- The model is immune to false positives.
- The model will detect every real-world attack.
- The model will generalize to unseen network environments.
- The model can replace human analysts.

## 6. Data Quality

The ML detector requires a supported label vocabulary.

During development, an unsupported:

```text
SUSPICIOUS
```

label caused label-validation failure because the detector expected:

```text
ANOMALOUS
ATTACK
BENIGN
MALICIOUS
NORMAL
```

This demonstrates the importance of explicit label validation in the training/inference pipeline.

## 7. Recommended ML Validation

For future versions:

1. Maintain an independent test set.
2. Validate class balance.
3. Test temporal generalization.
4. Measure per-class metrics.
5. Track feature importance.
6. Test drift.
7. Version model artifacts.
8. Preserve training metadata.
