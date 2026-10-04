# ML Training Notes

## 1. Training Objective

The objective is to train a machine-learning classifier capable of contributing a learned detection signal to the Network IDS.

## 2. Source Data

Training/evaluation data is derived from:

```text
data/network_features.csv
```

The recorded dataset contains 6,000 network flows.

## 3. Preprocessing

The preprocessing and label handling are implemented in:

```text
ids/ml_detector.py
```

The implementation should remain the authoritative source for the exact preprocessing sequence.

## 4. Label Handling

The ML implementation supports its configured label vocabulary.

During development, a flow containing:

```text
SUSPICIOUS
```

caused an `Unknown labels found` error because that label was not included in the detector's supported labels:

```text
ANOMALOUS
ATTACK
BENIGN
MALICIOUS
NORMAL
```

This is an important data-quality constraint: new labels must either be intentionally mapped or explicitly supported by the detector rather than silently entering the training pipeline.

## 5. Model Configuration

```text
Random Forest
n_estimators = 200
max_depth = 12
min_samples_leaf = 2
random_state = 42
```

## 6. Stored Artifact

The trained model is stored at:

```text
models/random_forest_ids.joblib
```

Metrics are stored at:

```text
models/random_forest_metrics.json
```

## 7. Evaluation

Recorded metrics:

```text
Accuracy   : 0.99917
Precision  : 0.99723
Recall     : 1.00000
F1 Score   : 0.99861
ROC-AUC    : 0.99991
```

## 8. Output

ML predictions are stored in:

```text
data/ml_detection_results.csv
```

The ML output subsequently participates in the hybrid risk calculation.

## 9. Re-training Checklist

Before retraining:

```text
[ ] Verify dataset version
[ ] Verify feature schema
[ ] Verify label vocabulary
[ ] Check class distribution
[ ] Check missing values
[ ] Check duplicate flows
[ ] Preserve random seed
[ ] Evaluate on independent data
[ ] Record metrics
[ ] Store model artifact
[ ] Update model documentation
```

## 10. Production Considerations

A production training pipeline should additionally include:

- Data versioning.
- Experiment tracking.
- Independent validation.
- Temporal validation.
- Model registry.
- Drift detection.
- Reproducible preprocessing.
- Model rollback.
- Performance monitoring.
