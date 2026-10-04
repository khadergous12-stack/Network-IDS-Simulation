"""
Network IDS - Hybrid Risk Scoring Engine
-----------------------------------------

Combines three independent detection signals:

    1. Signature-based rule score
    2. Statistical anomaly score
    3. Machine-learning score

Final output:

    Unified Risk Score: 0-100

Severity:

    LOW
    MEDIUM
    HIGH
    CRITICAL

The engine also generates explainable evidence describing
why a flow received its risk score.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

CONFIG_FILE = (
    BASE_DIR / "config" / "risk_config.json"
)

RULE_FILE = (
    BASE_DIR / "data" / "rule_detection_results.csv"
)

ANOMALY_FILE = (
    BASE_DIR / "data" / "anomaly_detection_results.csv"
)

ML_FILE = (
    BASE_DIR / "data" / "ml_detection_results.csv"
)

OUTPUT_FILE = (
    BASE_DIR / "data" / "hybrid_risk_results.csv"
)


# ============================================================
# REQUIRED COLUMNS
# ============================================================

RULE_COLUMNS = [
    "flow_id",
    "rule_score",
    "severity",
    "classification",
    "matched_rule_ids",
    "matched_rule_names",
    "explanation",
]

ANOMALY_COLUMNS = [
    "flow_id",
    "anomaly_score",
    "anomaly_classification",
    "anomaly_explanation",
]

ML_COLUMNS = [
    "flow_id",
    "ml_score",
    "ml_attack_probability",
    "ml_classification",
]


# ============================================================
# CONFIGURATION
# ============================================================

class RiskConfiguration:
    """
    Loads and validates hybrid risk configuration.
    """

    def __init__(
        self,
        config_file: Path = CONFIG_FILE,
    ) -> None:

        self.config_file = config_file

        self.config = self._load()

        self.weights = self.config[
            "weights"
        ]

        self.severity_thresholds = (
            self.config[
                "severity_thresholds"
            ]
        )

        self.decision_threshold = float(
            self.config[
                "decision_threshold"
            ]
        )

        self._validate()

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    def _load(self) -> dict[str, Any]:

        if not self.config_file.exists():

            raise FileNotFoundError(
                f"Risk configuration not found:\n"
                f"{self.config_file}"
            )

        with self.config_file.open(
            "r",
            encoding="utf-8",
        ) as file:

            return json.load(file)

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    def _validate(self) -> None:

        required_weights = {
            "signature",
            "anomaly",
            "machine_learning",
        }

        if set(self.weights.keys()) != (
            required_weights
        ):

            raise ValueError(
                "Risk weights must contain exactly:\n"
                "signature, anomaly, machine_learning"
            )

        weight_sum = sum(
            float(value)
            for value in self.weights.values()
        )

        if not np.isclose(
            weight_sum,
            1.0,
            atol=1e-6,
        ):

            raise ValueError(
                f"Risk weights must sum to 1.0. "
                f"Current sum: {weight_sum}"
            )

        for name, value in self.weights.items():

            if not 0 <= float(value) <= 1:

                raise ValueError(
                    f"Weight '{name}' must be "
                    f"between 0 and 1."
                )

        thresholds = self.severity_thresholds

        required_severities = {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }

        if set(thresholds.keys()) != (
            required_severities
        ):

            raise ValueError(
                "Severity thresholds must contain "
                "LOW, MEDIUM, HIGH and CRITICAL."
            )

        ordered = [
            float(thresholds["LOW"]),
            float(thresholds["MEDIUM"]),
            float(thresholds["HIGH"]),
            float(thresholds["CRITICAL"]),
        ]

        if ordered != sorted(ordered):

            raise ValueError(
                "Severity thresholds must be "
                "in ascending order."
            )

        if not (
            0 <= self.decision_threshold <= 100
        ):

            raise ValueError(
                "Decision threshold must be "
                "between 0 and 100."
            )


# ============================================================
# VALIDATION HELPERS
# ============================================================

def validate_columns(
    dataframe: pd.DataFrame,
    required_columns: list[str],
    source_name: str,
) -> None:

    missing = [
        column
        for column in required_columns
        if column not in dataframe.columns
    ]

    if missing:

        raise ValueError(
            f"{source_name} is missing columns:\n"
            + "\n".join(
                f"  - {column}"
                for column in missing
            )
        )


def validate_score(
    value: Any,
    name: str,
) -> float:

    try:

        score = float(value)

    except (
        TypeError,
        ValueError,
    ) as exc:

        raise ValueError(
            f"{name} is not numeric: {value}"
        ) from exc

    if not 0 <= score <= 100:

        raise ValueError(
            f"{name} must be between 0 and 100. "
            f"Received {score}"
        )

    return score


# ============================================================
# LOAD DATA
# ============================================================

def load_detection_data() -> tuple[
    pd.DataFrame,
    pd.DataFrame,
    pd.DataFrame,
]:
    """
    Load outputs from all three detection engines.
    """

    for file in [
        RULE_FILE,
        ANOMALY_FILE,
        ML_FILE,
    ]:

        if not file.exists():

            raise FileNotFoundError(
                f"\nRequired detection output not found:\n"
                f"{file}"
            )

    rule_data = pd.read_csv(
        RULE_FILE
    )

    anomaly_data = pd.read_csv(
        ANOMALY_FILE
    )

    ml_data = pd.read_csv(
        ML_FILE
    )

    validate_columns(
        rule_data,
        RULE_COLUMNS,
        "Rule detection results",
    )

    validate_columns(
        anomaly_data,
        ANOMALY_COLUMNS,
        "Anomaly detection results",
    )

    validate_columns(
        ml_data,
        ML_COLUMNS,
        "ML detection results",
    )

    return (
        rule_data,
        anomaly_data,
        ml_data,
    )


# ============================================================
# MERGE DETECTION SIGNALS
# ============================================================

def merge_detection_results(
    rule_data: pd.DataFrame,
    anomaly_data: pd.DataFrame,
    ml_data: pd.DataFrame,
) -> pd.DataFrame:
    """
    Merge the three detection-engine outputs by flow_id.
    """

    if rule_data["flow_id"].duplicated().any():

        raise ValueError(
            "Duplicate flow_id values found "
            "in rule results."
        )

    if anomaly_data["flow_id"].duplicated().any():

        raise ValueError(
            "Duplicate flow_id values found "
            "in anomaly results."
        )

    if ml_data["flow_id"].duplicated().any():

        raise ValueError(
            "Duplicate flow_id values found "
            "in ML results."
        )

    merged = rule_data.merge(
        anomaly_data,
        on="flow_id",
        how="inner",
        suffixes=(
            "_rule",
            "_anomaly",
        ),
    )

    merged = merged.merge(
        ml_data,
        on="flow_id",
        how="inner",
    )

    if merged.empty:

        raise ValueError(
            "No common flow IDs found across "
            "the three detection outputs."
        )

    return merged


# ============================================================
# SEVERITY
# ============================================================

def determine_severity(
    risk_score: float,
    thresholds: dict[str, Any],
) -> str:
    """
    Convert 0-100 risk score into severity.
    """

    critical = float(
        thresholds["CRITICAL"]
    )

    high = float(
        thresholds["HIGH"]
    )

    medium = float(
        thresholds["MEDIUM"]
    )

    low = float(
        thresholds["LOW"]
    )

    if risk_score >= critical:
        return "CRITICAL"

    if risk_score >= high:
        return "HIGH"

    if risk_score >= medium:
        return "MEDIUM"

    if risk_score >= low:
        return "LOW"

    return "LOW"


# ============================================================
# EVIDENCE
# ============================================================

def build_evidence(
    rule_score: float,
    anomaly_score: float,
    ml_score: float,
    matched_rule_names: str,
    rule_explanation: str,
    anomaly_explanation: str,
) -> str:
    """
    Build an explainable risk summary.
    """

    evidence = []

    # --------------------------------------------------------
    # Signature evidence
    # --------------------------------------------------------

    if rule_score > 0:

        if (
            matched_rule_names
            and str(matched_rule_names).strip()
        ):

            evidence.append(
                "Signature matches: "
                + str(
                    matched_rule_names
                )
            )

        if (
            rule_explanation
            and str(rule_explanation).strip()
        ):

            evidence.append(
                str(
                    rule_explanation
                )
            )

    # --------------------------------------------------------
    # Anomaly evidence
    # --------------------------------------------------------

    if anomaly_score >= 50:

        evidence.append(
            f"Behavior deviates from normal baseline "
            f"(anomaly score {anomaly_score:.1f}/100)."
        )

        if (
            anomaly_explanation
            and str(anomaly_explanation).strip()
        ):

            evidence.append(
                str(
                    anomaly_explanation
                )
            )

    # --------------------------------------------------------
    # ML evidence
    # --------------------------------------------------------

    if ml_score >= 50:

        evidence.append(
            f"ML model indicates elevated attack "
            f"probability (ML score {ml_score:.1f}/100)."
        )

    if not evidence:

        evidence.append(
            "No strong detection signal was identified."
        )

    return " | ".join(
        evidence
    )


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_risk_score(
    signature_score: float,
    anomaly_score: float,
    ml_score: float,
    weights: dict[str, Any],
) -> float:
    """
    Calculate weighted hybrid risk score.
    """

    signature_score = validate_score(
        signature_score,
        "Signature score",
    )

    anomaly_score = validate_score(
        anomaly_score,
        "Anomaly score",
    )

    ml_score = validate_score(
        ml_score,
        "ML score",
    )

    risk = (
        signature_score
        * float(
            weights["signature"]
        )
        +
        anomaly_score
        * float(
            weights["anomaly"]
        )
        +
        ml_score
        * float(
            weights["machine_learning"]
        )
    )

    return float(
        np.clip(
            risk,
            0.0,
            100.0,
        )
    )


# ============================================================
# PROCESS ALL FLOWS
# ============================================================

def calculate_hybrid_results(
    merged: pd.DataFrame,
    configuration: RiskConfiguration,
) -> pd.DataFrame:
    """
    Calculate final risk information for every flow.
    """

    results = []

    for _, row in merged.iterrows():

        signature_score = validate_score(
            row["rule_score"],
            "Signature score",
        )

        anomaly_score = validate_score(
            row["anomaly_score"],
            "Anomaly score",
        )

        ml_score = validate_score(
            row["ml_score"],
            "ML score",
        )

        risk_score = calculate_risk_score(
            signature_score,
            anomaly_score,
            ml_score,
            configuration.weights,
        )

        severity = determine_severity(
            risk_score,
            configuration.severity_thresholds,
        )

        evidence = build_evidence(
            signature_score,
            anomaly_score,
            ml_score,
            row[
                "matched_rule_names"
            ],
            row[
                "explanation"
            ],
            row[
                "anomaly_explanation"
            ],
        )

        decision = (
            "INVESTIGATE"
            if risk_score
            >= configuration.decision_threshold
            else "MONITOR"
        )

        results.append(
            {
                "flow_id": row[
                    "flow_id"
                ],

                "timestamp": row[
                    "timestamp_rule"
                ],

                "source_ip": row[
                    "source_ip_rule"
                ],

                "destination_ip": row[
                    "destination_ip_rule"
                ],

                "protocol": row[
                    "protocol_rule"
                ],

                "source_port": row[
                    "source_port_rule"
                ],

                "destination_port": row[
                    "destination_port_rule"
                ],

                # Detection signals
                "signature_score": round(
                    signature_score,
                    2,
                ),

                "anomaly_score": round(
                    anomaly_score,
                    2,
                ),

                "ml_score": round(
                    ml_score,
                    2,
                ),

                # Final score
                "risk_score": round(
                    risk_score,
                    2,
                ),

                "severity": severity,

                "decision": decision,

                # Detection evidence
                "matched_rule_ids": row[
                    "matched_rule_ids"
                ],

                "matched_rule_names": row[
                    "matched_rule_names"
                ],

                "anomaly_classification": row[
                    "anomaly_classification"
                ],

                "ml_classification": row[
                    "ml_classification"
                ],

                "risk_explanation": evidence,

                # Ground truth
                "ground_truth_label": row[
                    "ground_truth_label_rule"
                ],

                "scenario_type": row[
                    "scenario_type_rule"
                ],
            }
        )

    return pd.DataFrame(
        results
    )


# ============================================================
# SUMMARY
# ============================================================

def print_summary(
    results: pd.DataFrame,
    configuration: RiskConfiguration,
) -> None:
    """
    Print hybrid risk summary.
    """

    total = len(results)

    investigate = results[
        results["decision"]
        == "INVESTIGATE"
    ]

    print("\n" + "=" * 80)
    print("HYBRID RISK SCORING SUMMARY")
    print("=" * 80)

    print(
        f"\nTotal flows: {total:,}"
    )

    print(
        f"Investigation required: "
        f"{len(investigate):,}"
    )

    print(
        f"Monitor: "
        f"{total - len(investigate):,}"
    )

    if total:

        print(
            f"\nAverage risk score: "
            f"{results['risk_score'].mean():.2f}"
        )

        print(
            f"Maximum risk score: "
            f"{results['risk_score'].max():.2f}"
        )

    print("\nSeverity distribution:")

    severity_counts = (
        results["severity"]
        .value_counts()
    )

    for severity in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]:

        print(
            f"  {severity:<10}"
            f"{severity_counts.get(severity, 0):,}"
        )

    print(
        "\nRisk weights:"
    )

    for name, weight in (
        configuration.weights.items()
    ):

        print(
            f"  {name:<20}"
            f"{float(weight):.2f}"
        )

    print(
        f"\nInvestigation threshold: "
        f"{configuration.decision_threshold:.1f}"
    )


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """
    Execute complete hybrid risk scoring pipeline.
    """

    print("=" * 80)
    print("NETWORK IDS — HYBRID RISK ENGINE")
    print("=" * 80)

    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    print(
        "\nLoading risk configuration..."
    )

    configuration = RiskConfiguration()

    print(
        "Risk configuration validated."
    )

    # --------------------------------------------------------
    # Load detection outputs
    # --------------------------------------------------------

    print(
        "\nLoading detection-engine results..."
    )

    (
        rule_data,
        anomaly_data,
        ml_data,
    ) = load_detection_data()

    print(
        f"Rule results     : "
        f"{len(rule_data):,}"
    )

    print(
        f"Anomaly results  : "
        f"{len(anomaly_data):,}"
    )

    print(
        f"ML results       : "
        f"{len(ml_data):,}"
    )

    # --------------------------------------------------------
    # Merge
    # --------------------------------------------------------

    print(
        "\nMerging detection signals..."
    )

    merged = merge_detection_results(
        rule_data,
        anomaly_data,
        ml_data,
    )

    print(
        f"Common flows: "
        f"{len(merged):,}"
    )

    # --------------------------------------------------------
    # Calculate hybrid score
    # --------------------------------------------------------

    print(
        "\nCalculating unified risk scores..."
    )

    results = calculate_hybrid_results(
        merged,
        configuration,
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    invalid_scores = (
        (results["risk_score"] < 0)
        |
        (results["risk_score"] > 100)
    ).sum()

    if invalid_scores > 0:

        raise ValueError(
            f"Found {invalid_scores} "
            "invalid risk scores."
        )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    results.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print_summary(
        results,
        configuration,
    )

    print(
        f"\nResults saved to:\n"
        f"{OUTPUT_FILE}"
    )

    print("\n" + "=" * 80)
    print(
        "HYBRID RISK ENGINE COMPLETED SUCCESSFULLY"
    )
    print("=" * 80)


if __name__ == "__main__":
    main()