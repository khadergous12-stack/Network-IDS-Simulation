"""
Network IDS - Alert Generation Engine
--------------------------------------

Converts hybrid risk results into structured IDS alerts.

Input:
    data/hybrid_risk_results.csv

Output:
    data/alerts.csv

The alert engine provides:

    - Unique alert IDs
    - Risk score
    - Severity
    - Detection evidence
    - Detection methods
    - Recommended actions
    - Source/destination information
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    BASE_DIR / "data" / "hybrid_risk_results.csv"
)

CONFIG_FILE = (
    BASE_DIR / "config" / "alert_config.json"
)

OUTPUT_FILE = (
    BASE_DIR / "data" / "alerts.csv"
)


# ============================================================
# REQUIRED COLUMNS
# ============================================================

REQUIRED_COLUMNS = [
    "flow_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "signature_score",
    "anomaly_score",
    "ml_score",
    "risk_score",
    "severity",
    "decision",
    "matched_rule_ids",
    "matched_rule_names",
    "anomaly_classification",
    "ml_classification",
    "risk_explanation",
    "ground_truth_label",
    "scenario_type",
]


# ============================================================
# CONFIGURATION
# ============================================================

class AlertConfiguration:
    """
    Loads and validates alert-generation configuration.
    """

    def __init__(
        self,
        config_file: Path = CONFIG_FILE,
    ) -> None:

        self.config_file = config_file
        self.config = self._load()

        self.minimum_alert_score = float(
            self.config[
                "minimum_alert_score"
            ]
        )

        self.alert_severities = set(
            self.config[
                "alert_severities"
            ]
        )

        self.recommended_actions = (
            self.config[
                "recommended_actions"
            ]
        )

        self._validate()

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    def _load(self) -> dict[str, Any]:

        if not self.config_file.exists():

            raise FileNotFoundError(
                f"Alert configuration not found:\n"
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

        if not (
            0
            <= self.minimum_alert_score
            <= 100
        ):

            raise ValueError(
                "minimum_alert_score must be "
                "between 0 and 100."
            )

        if not self.alert_severities:

            raise ValueError(
                "At least one alert severity "
                "must be configured."
            )

        for severity in self.alert_severities:

            if severity not in {
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            }:

                raise ValueError(
                    f"Invalid alert severity: "
                    f"{severity}"
                )

            if severity not in (
                self.recommended_actions
            ):

                raise ValueError(
                    f"Missing recommended action "
                    f"for severity: {severity}"
                )


# ============================================================
# VALIDATION
# ============================================================

def validate_input(
    dataframe: pd.DataFrame,
) -> None:
    """
    Validate hybrid risk output.
    """

    missing = [
        column
        for column in REQUIRED_COLUMNS
        if column not in dataframe.columns
    ]

    if missing:

        raise ValueError(
            "Hybrid risk results are missing:\n"
            + "\n".join(
                f"  - {column}"
                for column in missing
            )
        )

    if dataframe.empty:

        raise ValueError(
            "Hybrid risk results are empty."
        )


# ============================================================
# DETECTION METHOD
# ============================================================

def determine_detection_methods(
    row: pd.Series,
) -> str:
    """
    Determine which detection layers contributed
    meaningful evidence.
    """

    methods = []

    signature_score = float(
        row["signature_score"]
    )

    anomaly_score = float(
        row["anomaly_score"]
    )

    ml_score = float(
        row["ml_score"]
    )

    if signature_score > 0:

        methods.append(
            "SIGNATURE"
        )

    if anomaly_score >= 50:

        methods.append(
            "ANOMALY"
        )

    if ml_score >= 50:

        methods.append(
            "MACHINE_LEARNING"
        )

    if not methods:

        methods.append(
            "HYBRID"
        )

    return ", ".join(
        methods
    )


# ============================================================
# CONFIDENCE
# ============================================================

def calculate_confidence(
    row: pd.Series,
) -> float:
    """
    Calculate a simple confidence indicator.

    The confidence represents the agreement between
    the three detection layers.

    It is NOT a statistical probability.
    """

    signals = [
        float(row["signature_score"]),
        float(row["anomaly_score"]),
        float(row["ml_score"]),
    ]

    active_signals = sum(
        score >= 50
        for score in signals
    )

    if active_signals >= 3:

        confidence = 95.0

    elif active_signals == 2:

        confidence = 80.0

    elif active_signals == 1:

        confidence = 65.0

    else:

        confidence = 40.0

    return confidence


# ============================================================
# ALERT ID
# ============================================================

def generate_alert_id(
    index: int,
) -> str:
    """
    Generate deterministic alert identifier.
    """

    return (
        f"IDS-"
        f"{index + 1:06d}"
    )


# ============================================================
# ALERT GENERATION
# ============================================================

def generate_alerts(
    dataframe: pd.DataFrame,
    configuration: AlertConfiguration,
) -> pd.DataFrame:
    """
    Generate alerts from hybrid risk results.
    """

    alerts = []

    alert_index = 0

    for _, row in dataframe.iterrows():

        risk_score = float(
            row["risk_score"]
        )

        severity = str(
            row["severity"]
        ).upper()

        decision = str(
            row["decision"]
        ).upper()

        # ----------------------------------------------------
        # Alert filter
        # ----------------------------------------------------

        qualifies_by_score = (
            risk_score
            >= configuration.minimum_alert_score
        )

        qualifies_by_severity = (
            severity
            in configuration.alert_severities
        )

        qualifies_by_decision = (
            decision
            == "INVESTIGATE"
        )

        if not (
            qualifies_by_score
            and qualifies_by_severity
            and qualifies_by_decision
        ):

            continue

        alert_index += 1

        detection_methods = (
            determine_detection_methods(
                row
            )
        )

        confidence = calculate_confidence(
            row
        )

        recommended_action = (
            configuration
            .recommended_actions
            .get(
                severity,
                "Review the suspicious activity.",
            )
        )

        alerts.append(
            {
                "alert_id": generate_alert_id(
                    alert_index - 1
                ),

                "flow_id": row[
                    "flow_id"
                ],

                "timestamp": row[
                    "timestamp"
                ],

                "source_ip": row[
                    "source_ip"
                ],

                "destination_ip": row[
                    "destination_ip"
                ],

                "protocol": row[
                    "protocol"
                ],

                "source_port": row[
                    "source_port"
                ],

                "destination_port": row[
                    "destination_port"
                ],

                # ------------------------------------------------
                # Risk
                # ------------------------------------------------

                "risk_score": round(
                    risk_score,
                    2,
                ),

                "severity": severity,

                "confidence": confidence,

                # ------------------------------------------------
                # Detection signals
                # ------------------------------------------------

                "signature_score": round(
                    float(
                        row["signature_score"]
                    ),
                    2,
                ),

                "anomaly_score": round(
                    float(
                        row["anomaly_score"]
                    ),
                    2,
                ),

                "ml_score": round(
                    float(
                        row["ml_score"]
                    ),
                    2,
                ),

                "detection_methods": (
                    detection_methods
                ),

                # ------------------------------------------------
                # Evidence
                # ------------------------------------------------

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

                "explanation": row[
                    "risk_explanation"
                ],

                # ------------------------------------------------
                # Action
                # ------------------------------------------------

                "recommended_action": (
                    recommended_action
                ),

                "status": "OPEN",

                # ------------------------------------------------
                # Context
                # ------------------------------------------------

                "scenario_type": row[
                    "scenario_type"
                ],

                "ground_truth_label": row[
                    "ground_truth_label"
                ],
            }
        )

    return pd.DataFrame(
        alerts
    )


# ============================================================
# SUMMARY
# ============================================================

def print_summary(
    alerts: pd.DataFrame,
) -> None:
    """
    Print alert summary.
    """

    print("\n" + "=" * 80)
    print("ALERT GENERATION SUMMARY")
    print("=" * 80)

    print(
        f"\nTotal alerts generated: "
        f"{len(alerts):,}"
    )

    if alerts.empty:

        print(
            "\nNo flows met the alert criteria."
        )

        return

    print("\nSeverity distribution:")

    counts = (
        alerts["severity"]
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
            f"{counts.get(severity, 0):,}"
        )

    print("\nDetection methods:")

    method_counts = (
        alerts[
            "detection_methods"
        ]
        .str.split(", ")
        .explode()
        .value_counts()
    )

    for method, count in (
        method_counts.items()
    ):

        print(
            f"  {method:<20}"
            f"{count:,}"
        )

    print(
        f"\nAverage alert risk: "
        f"{alerts['risk_score'].mean():.2f}"
    )

    print(
        f"Highest alert risk: "
        f"{alerts['risk_score'].max():.2f}"
    )

    print(
        "\nAlert status:"
    )

    print(
        alerts["status"]
        .value_counts()
        .to_string()
    )


# ============================================================
# PREVIEW
# ============================================================

def print_top_alerts(
    alerts: pd.DataFrame,
) -> None:
    """
    Display highest-risk alerts.
    """

    if alerts.empty:

        return

    print(
        "\nTop 10 alerts by risk:"
    )

    preview_columns = [
        "alert_id",
        "source_ip",
        "destination_ip",
        "risk_score",
        "severity",
        "confidence",
        "detection_methods",
    ]

    preview = (
        alerts
        .sort_values(
            "risk_score",
            ascending=False,
        )
        .head(10)
    )

    print(
        preview[
            preview_columns
        ].to_string(
            index=False
        )
    )


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """
    Execute alert generation pipeline.
    """

    print("=" * 80)
    print("NETWORK IDS — ALERT GENERATION ENGINE")
    print("=" * 80)

    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    print(
        "\nLoading alert configuration..."
    )

    configuration = AlertConfiguration()

    print(
        "Alert configuration validated."
    )

    # --------------------------------------------------------
    # Input
    # --------------------------------------------------------

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"\nHybrid risk file not found:\n"
            f"{INPUT_FILE}\n\n"
            "Run first:\n"
            "python ids\\risk_engine.py"
        )

    print(
        f"\nLoading hybrid risk results:\n"
        f"{INPUT_FILE}"
    )

    dataframe = pd.read_csv(
        INPUT_FILE
    )

    validate_input(
        dataframe
    )

    print(
        f"Loaded {len(dataframe):,} flows."
    )

    # --------------------------------------------------------
    # Generate alerts
    # --------------------------------------------------------

    print(
        "\nGenerating IDS alerts..."
    )

    alerts = generate_alerts(
        dataframe,
        configuration,
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    alerts.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print_summary(
        alerts
    )

    print_top_alerts(
        alerts
    )

    print(
        f"\nAlerts saved to:\n"
        f"{OUTPUT_FILE}"
    )

    print("\n" + "=" * 80)
    print(
        "ALERT GENERATION COMPLETED SUCCESSFULLY"
    )
    print("=" * 80)


if __name__ == "__main__":
    main()