"""
Network IDS - Incident Management Engine
-----------------------------------------

Converts IDS alerts into structured incident records.

Input:
    data/alerts.csv

Output:
    data/incidents.csv

Incident lifecycle:

    OPEN
      ↓
    INVESTIGATING
      ↓
    CONTAINED
      ↓
    RESOLVED

Alternative:
    FALSE_POSITIVE
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
    BASE_DIR / "data" / "alerts.csv"
)

CONFIG_FILE = (
    BASE_DIR / "config" / "incident_config.json"
)

OUTPUT_FILE = (
    BASE_DIR / "data" / "incidents.csv"
)


# ============================================================
# REQUIRED ALERT COLUMNS
# ============================================================

REQUIRED_COLUMNS = [
    "alert_id",
    "flow_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "risk_score",
    "severity",
    "confidence",
    "detection_methods",
    "matched_rule_ids",
    "matched_rule_names",
    "anomaly_classification",
    "ml_classification",
    "explanation",
    "recommended_action",
    "status",
    "scenario_type",
    "ground_truth_label",
]


# ============================================================
# INCIDENT CONFIGURATION
# ============================================================

class IncidentConfiguration:
    """
    Loads and validates incident configuration.
    """

    def __init__(
        self,
        config_file: Path = CONFIG_FILE,
    ) -> None:

        self.config_file = config_file
        self.config = self._load()

        self.default_status = (
            self.config[
                "default_status"
            ]
        )

        self.default_priority = (
            self.config[
                "default_priority"
            ]
        )

        self.auto_create_incidents = bool(
            self.config[
                "auto_create_incidents"
            ]
        )

        self.priority_mapping = (
            self.config[
                "priority_mapping"
            ]
        )

        self.incident_statuses = set(
            self.config[
                "incident_statuses"
            ]
        )

        self._validate()

    # --------------------------------------------------------
    # Load configuration
    # --------------------------------------------------------

    def _load(self) -> dict[str, Any]:

        if not self.config_file.exists():

            raise FileNotFoundError(
                f"Incident configuration not found:\n"
                f"{self.config_file}"
            )

        with self.config_file.open(
            "r",
            encoding="utf-8",
        ) as file:

            return json.load(file)

    # --------------------------------------------------------
    # Validate configuration
    # --------------------------------------------------------

    def _validate(self) -> None:

        allowed_statuses = {
            "OPEN",
            "INVESTIGATING",
            "CONTAINED",
            "RESOLVED",
            "FALSE_POSITIVE",
        }

        if (
            self.default_status
            not in allowed_statuses
        ):

            raise ValueError(
                f"Invalid default status: "
                f"{self.default_status}"
            )

        allowed_priorities = {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }

        if (
            self.default_priority
            not in allowed_priorities
        ):

            raise ValueError(
                f"Invalid default priority: "
                f"{self.default_priority}"
            )

        if not self.incident_statuses:

            raise ValueError(
                "No incident statuses configured."
            )

        for status in self.incident_statuses:

            if status not in allowed_statuses:

                raise ValueError(
                    f"Invalid incident status: "
                    f"{status}"
                )

        for severity, priority in (
            self.priority_mapping.items()
        ):

            if severity not in allowed_priorities:

                raise ValueError(
                    f"Invalid severity in "
                    f"priority_mapping: {severity}"
                )

            if priority not in allowed_priorities:

                raise ValueError(
                    f"Invalid priority mapping: "
                    f"{priority}"
                )


# ============================================================
# VALIDATE ALERT DATA
# ============================================================

def validate_alert_data(
    dataframe: pd.DataFrame,
) -> None:
    """
    Validate alerts before creating incidents.
    """

    missing = [
        column
        for column in REQUIRED_COLUMNS
        if column not in dataframe.columns
    ]

    if missing:

        raise ValueError(
            "Alerts file is missing required columns:\n"
            + "\n".join(
                f"  - {column}"
                for column in missing
            )
        )


# ============================================================
# INCIDENT ID
# ============================================================

def generate_incident_id(
    index: int,
) -> str:
    """
    Generate deterministic incident identifier.
    """

    return (
        f"INC-"
        f"{index + 1:06d}"
    )


# ============================================================
# PRIORITY
# ============================================================

def determine_priority(
    severity: str,
    configuration: IncidentConfiguration,
) -> str:
    """
    Convert alert severity into incident priority.
    """

    severity = str(
        severity
    ).upper()

    return configuration.priority_mapping.get(
        severity,
        configuration.default_priority,
    )


# ============================================================
# INCIDENT TITLE
# ============================================================

def generate_incident_title(
    row: pd.Series,
) -> str:
    """
    Generate a concise incident title.
    """

    severity = str(
        row["severity"]
    ).upper()

    scenario = str(
        row["scenario_type"]
    ).strip()

    if not scenario:

        scenario = "Suspicious Network Activity"

    return (
        f"{severity} - "
        f"{scenario}"
    )


# ============================================================
# INCIDENT DESCRIPTION
# ============================================================

def generate_incident_description(
    row: pd.Series,
) -> str:
    """
    Build an investigation-oriented description.
    """

    return (
        f"Suspicious network activity detected "
        f"from {row['source_ip']} to "
        f"{row['destination_ip']} using "
        f"{row['protocol']}. "
        f"The hybrid risk engine assigned a "
        f"risk score of {float(row['risk_score']):.2f}/100. "
        f"Detection methods: "
        f"{row['detection_methods']}. "
        f"Evidence: {row['explanation']}"
    )


# ============================================================
# CREATE INCIDENTS
# ============================================================

def create_incidents(
    alerts: pd.DataFrame,
    configuration: IncidentConfiguration,
) -> pd.DataFrame:
    """
    Convert alerts into incident records.
    """

    incidents = []

    for index, row in alerts.iterrows():

        priority = determine_priority(
            row["severity"],
            configuration,
        )

        incidents.append(
            {
                # ------------------------------------------------
                # Identity
                # ------------------------------------------------

                "incident_id": (
                    generate_incident_id(
                        index
                    )
                ),

                "alert_id": row[
                    "alert_id"
                ],

                "flow_id": row[
                    "flow_id"
                ],

                # ------------------------------------------------
                # Timing
                # ------------------------------------------------

                "timestamp": row[
                    "timestamp"
                ],

                # ------------------------------------------------
                # Incident information
                # ------------------------------------------------

                "title": generate_incident_title(
                    row
                ),

                "description": (
                    generate_incident_description(
                        row
                    )
                ),

                "scenario_type": row[
                    "scenario_type"
                ],

                # ------------------------------------------------
                # Network context
                # ------------------------------------------------

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
                    float(
                        row["risk_score"]
                    ),
                    2,
                ),

                "severity": row[
                    "severity"
                ],

                "priority": priority,

                "confidence": round(
                    float(
                        row["confidence"]
                    ),
                    2,
                ),

                # ------------------------------------------------
                # Detection evidence
                # ------------------------------------------------

                "detection_methods": row[
                    "detection_methods"
                ],

                "signature_score": row[
                    "signature_score"
                ],

                "anomaly_score": row[
                    "anomaly_score"
                ],

                "ml_score": row[
                    "ml_score"
                ],

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

                "evidence": row[
                    "explanation"
                ],

                # ------------------------------------------------
                # Response
                # ------------------------------------------------

                "recommended_action": row[
                    "recommended_action"
                ],

                "status": (
                    configuration.default_status
                ),

                "assigned_to": "",

                "analyst_notes": "",

                "resolution": "",

                # ------------------------------------------------
                # Ground truth / evaluation
                # ------------------------------------------------

                "ground_truth_label": row[
                    "ground_truth_label"
                ],
            }
        )

    return pd.DataFrame(
        incidents
    )


# ============================================================
# SUMMARY
# ============================================================

def print_summary(
    incidents: pd.DataFrame,
) -> None:
    """
    Print incident summary.
    """

    print("\n" + "=" * 80)
    print("INCIDENT MANAGEMENT SUMMARY")
    print("=" * 80)

    print(
        f"\nTotal incidents: "
        f"{len(incidents):,}"
    )

    if incidents.empty:

        print(
            "\nNo incidents were created."
        )

        return

    print("\nPriority distribution:")

    priority_counts = (
        incidents[
            "priority"
        ]
        .value_counts()
    )

    for priority in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]:

        print(
            f"  {priority:<10}"
            f"{priority_counts.get(priority, 0):,}"
        )

    print("\nStatus distribution:")

    status_counts = (
        incidents[
            "status"
        ]
        .value_counts()
    )

    for status in [
        "OPEN",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED",
        "FALSE_POSITIVE",
    ]:

        print(
            f"  {status:<15}"
            f"{status_counts.get(status, 0):,}"
        )

    print(
        f"\nAverage incident risk: "
        f"{incidents['risk_score'].mean():.2f}"
    )

    print(
        f"Highest incident risk: "
        f"{incidents['risk_score'].max():.2f}"
    )


# ============================================================
# PREVIEW
# ============================================================

def print_top_incidents(
    incidents: pd.DataFrame,
) -> None:
    """
    Display highest-risk incidents.
    """

    if incidents.empty:

        return

    print(
        "\nTop 10 incidents:"
    )

    columns = [
        "incident_id",
        "alert_id",
        "source_ip",
        "risk_score",
        "severity",
        "priority",
        "status",
    ]

    preview = (
        incidents
        .sort_values(
            "risk_score",
            ascending=False,
        )
        .head(10)
    )

    print(
        preview[
            columns
        ].to_string(
            index=False
        )
    )


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """
    Execute incident management pipeline.
    """

    print("=" * 80)
    print("NETWORK IDS — INCIDENT MANAGEMENT")
    print("=" * 80)

    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    print(
        "\nLoading incident configuration..."
    )

    configuration = IncidentConfiguration()

    print(
        "Incident configuration validated."
    )

    # --------------------------------------------------------
    # Input
    # --------------------------------------------------------

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"\nAlerts file not found:\n"
            f"{INPUT_FILE}\n\n"
            "Run first:\n"
            "python ids\\alert_generator.py"
        )

    print(
        f"\nLoading alerts:\n"
        f"{INPUT_FILE}"
    )

    alerts = pd.read_csv(
        INPUT_FILE
    )

    validate_alert_data(
        alerts
    )

    print(
        f"Loaded {len(alerts):,} alerts."
    )

    # --------------------------------------------------------
    # Create incidents
    # --------------------------------------------------------

    if not configuration.auto_create_incidents:

        print(
            "\nAutomatic incident creation "
            "is disabled."
        )

        return

    print(
        "\nCreating incident records..."
    )

    incidents = create_incidents(
        alerts,
        configuration,
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    incidents.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print_summary(
        incidents
    )

    print_top_incidents(
        incidents
    )

    print(
        f"\nIncidents saved to:\n"
        f"{OUTPUT_FILE}"
    )

    print("\n" + "=" * 80)
    print(
        "INCIDENT MANAGEMENT COMPLETED SUCCESSFULLY"
    )
    print("=" * 80)


if __name__ == "__main__":
    main()