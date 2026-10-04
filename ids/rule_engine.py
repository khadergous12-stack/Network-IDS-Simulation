"""
Network IDS - Signature-Based Detection Engine
-----------------------------------------------

Evaluates extracted network-flow features against
configurable IDS rules.

Rules:
    IDS-001 -> High Connection Rate
    IDS-002 -> Repeated Failed Connections
    IDS-003 -> Destination Port Diversity
    IDS-004 -> SYN-Heavy Behavior
    IDS-005 -> Unusual Service Port
    IDS-006 -> High Traffic Volume

Important:
A rule match indicates suspicious behavior requiring
investigation. It does NOT by itself prove an intrusion.
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

RULES_FILE = BASE_DIR / "config" / "detection_rules.json"
FEATURE_FILE = BASE_DIR / "data" / "network_features.csv"
OUTPUT_FILE = BASE_DIR / "data" / "rule_detection_results.csv"


# ============================================================
# REQUIRED FEATURES
# ============================================================

REQUIRED_FEATURES = [
    "flow_id",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "packet_count",
    "byte_count",
    "duration_seconds",
    "connection_rate",
    "failed_connection_ratio",
    "syn_ratio",
    "unique_destination_ports",
    "label",
    "scenario_type",
]


# ============================================================
# RULE ENGINE
# ============================================================

class SignatureRuleEngine:
    """
    Configurable signature-based IDS rule engine.
    """

    def __init__(
        self,
        rules_file: Path = RULES_FILE,
    ) -> None:

        self.rules_file = rules_file

        self.rules = self._load_rules()

    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    def _load_rules(self) -> dict[str, dict[str, Any]]:
        """Load detection rules from JSON configuration."""

        if not self.rules_file.exists():
            raise FileNotFoundError(
                f"Detection rules file not found:\n"
                f"{self.rules_file}"
            )

        with self.rules_file.open(
            "r",
            encoding="utf-8",
        ) as file:

            rules = json.load(file)

        if not isinstance(rules, dict):
            raise ValueError(
                "Detection rules must be a JSON object."
            )

        return rules

    # --------------------------------------------------------
    # Rule 001
    # --------------------------------------------------------

    def check_high_connection_rate(
        self,
        flow: pd.Series,
        rule: dict[str, Any],
    ) -> dict[str, Any] | None:
        """IDS-001: High connection rate."""

        threshold = float(
            rule["threshold"]
        )

        value = float(
            flow["connection_rate"]
        )

        if value > threshold:

            return {
                "rule_id": "IDS-001",
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "score": rule["score"],
                "evidence": (
                    f"Connection rate {value:.2f} "
                    f"exceeded threshold {threshold:.2f}."
                ),
            }

        return None

    # --------------------------------------------------------
    # Rule 002
    # --------------------------------------------------------

    def check_failed_connections(
        self,
        flow: pd.Series,
        rule: dict[str, Any],
    ) -> dict[str, Any] | None:
        """IDS-002: Repeated failed connections."""

        threshold = float(
            rule["threshold"]
        )

        value = float(
            flow["failed_connection_ratio"]
        )

        if value > threshold:

            return {
                "rule_id": "IDS-002",
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "score": rule["score"],
                "evidence": (
                    f"Failed connection ratio {value:.2%} "
                    f"exceeded threshold {threshold:.2%}."
                ),
            }

        return None

    # --------------------------------------------------------
    # Rule 003
    # --------------------------------------------------------

    def check_port_diversity(
        self,
        flow: pd.Series,
        rule: dict[str, Any],
    ) -> dict[str, Any] | None:
        """IDS-003: Destination port diversity."""

        threshold = int(
            rule["threshold"]
        )

        value = int(
            flow["unique_destination_ports"]
        )

        if value > threshold:

            return {
                "rule_id": "IDS-003",
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "score": rule["score"],
                "evidence": (
                    f"Destination-port diversity {value} "
                    f"exceeded threshold {threshold}."
                ),
            }

        return None

    # --------------------------------------------------------
    # Rule 004
    # --------------------------------------------------------

    def check_syn_ratio(
        self,
        flow: pd.Series,
        rule: dict[str, Any],
    ) -> dict[str, Any] | None:
        """IDS-004: SYN-heavy behavior."""

        threshold = float(
            rule["threshold"]
        )

        value = float(
            flow["syn_ratio"]
        )

        protocol = str(
            flow["protocol"]
        ).upper()

        if protocol == "TCP" and value > threshold:

            return {
                "rule_id": "IDS-004",
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "score": rule["score"],
                "evidence": (
                    f"SYN ratio {value:.2%} "
                    f"exceeded threshold {threshold:.2%}."
                ),
            }

        return None

    # --------------------------------------------------------
    # Rule 005
    # --------------------------------------------------------

    def check_unusual_service_port(
        self,
        flow: pd.Series,
        rule: dict[str, Any],
    ) -> dict[str, Any] | None:
        """IDS-005: Unusual service port."""

        allowed_ports = {
            int(port)
            for port in rule["allowed_ports"]
        }

        destination_port = int(
            flow["destination_port"]
        )

        if destination_port not in allowed_ports:

            return {
                "rule_id": "IDS-005",
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "score": rule["score"],
                "evidence": (
                    f"Destination port {destination_port} "
                    "is outside the configured service-port set."
                ),
            }

        return None

    # --------------------------------------------------------
    # Rule 006
    # --------------------------------------------------------

    def check_high_traffic_volume(
        self,
        flow: pd.Series,
        rule: dict[str, Any],
    ) -> dict[str, Any] | None:
        """IDS-006: High traffic volume."""

        threshold = int(
            rule["threshold"]
        )

        value = int(
            flow["byte_count"]
        )

        if value > threshold:

            return {
                "rule_id": "IDS-006",
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "score": rule["score"],
                "evidence": (
                    f"Traffic volume {value:,} bytes "
                    f"exceeded threshold {threshold:,} bytes."
                ),
            }

        return None

    # --------------------------------------------------------
    # Evaluate one flow
    # --------------------------------------------------------

    def evaluate_flow(
        self,
        flow: pd.Series,
    ) -> list[dict[str, Any]]:
        """
        Evaluate a single flow against every enabled rule.
        """

        matches: list[dict[str, Any]] = []

        rule_methods = {
            "IDS-001": self.check_high_connection_rate,
            "IDS-002": self.check_failed_connections,
            "IDS-003": self.check_port_diversity,
            "IDS-004": self.check_syn_ratio,
            "IDS-005": self.check_unusual_service_port,
            "IDS-006": self.check_high_traffic_volume,
        }

        for rule_id, method in rule_methods.items():

            rule = self.rules.get(rule_id)

            if rule is None:
                continue

            if not rule.get(
                "enabled",
                True,
            ):
                continue

            match = method(
                flow,
                rule,
            )

            if match is not None:
                matches.append(match)

        return matches

    # --------------------------------------------------------
    # Evaluate complete dataset
    # --------------------------------------------------------

    def evaluate_dataset(
        self,
        dataframe: pd.DataFrame,
    ) -> pd.DataFrame:
        """
        Evaluate all flows and create rule-detection results.
        """

        results = []

        for _, flow in dataframe.iterrows():

            matches = self.evaluate_flow(
                flow
            )

            matched_rule_ids = [
                match["rule_id"]
                for match in matches
            ]

            matched_rule_names = [
                match["rule_name"]
                for match in matches
            ]

            matched_severities = [
                match["severity"]
                for match in matches
            ]

            rule_score = sum(
                match["score"]
                for match in matches
            )

            rule_score = min(
                rule_score,
                100,
            )

            if matches:

                classification = "SUSPICIOUS"

                explanation = " | ".join(
                    match["evidence"]
                    for match in matches
                )

                highest_severity = (
                    self._highest_severity(
                        matched_severities
                    )
                )

            else:

                classification = "NORMAL"

                explanation = (
                    "No configured signature rule matched."
                )

                highest_severity = "NONE"

            results.append(
                {
                    "flow_id": flow["flow_id"],
                    "timestamp": flow["timestamp"],
                    "source_ip": flow["source_ip"],
                    "destination_ip": flow["destination_ip"],
                    "protocol": flow["protocol"],
                    "source_port": flow["source_port"],
                    "destination_port": flow[
                        "destination_port"
                    ],
                    "matched_rule_ids": ",".join(
                        matched_rule_ids
                    ),
                    "matched_rule_names": ",".join(
                        matched_rule_names
                    ),
                    "rule_match_count": len(matches),
                    "rule_score": rule_score,
                    "severity": highest_severity,
                    "classification": classification,
                    "explanation": explanation,
                    "ground_truth_label": flow["label"],
                    "scenario_type": flow[
                        "scenario_type"
                    ],
                }
            )

        return pd.DataFrame(results)

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    @staticmethod
    def _highest_severity(
        severities: list[str],
    ) -> str:
        """Return the highest severity among matched rules."""

        priority = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "NONE": 0,
        }

        if not severities:
            return "NONE"

        return max(
            severities,
            key=lambda severity: priority.get(
                severity.upper(),
                0,
            ),
        )


# ============================================================
# DATA VALIDATION
# ============================================================

def validate_feature_dataset(
    dataframe: pd.DataFrame,
) -> None:
    """Validate required input features."""

    missing = [
        column
        for column in REQUIRED_FEATURES
        if column not in dataframe.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required features: {missing}"
        )

    if dataframe.empty:
        raise ValueError(
            "Feature dataset is empty."
        )


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """Run signature-based detection on the feature dataset."""

    print("=" * 80)
    print("NETWORK IDS — SIGNATURE-BASED DETECTION")
    print("=" * 80)

    if not FEATURE_FILE.exists():

        raise FileNotFoundError(
            f"\nFeature dataset not found:\n"
            f"{FEATURE_FILE}\n\n"
            "Run first:\n"
            "python ids\\feature_extractor.py"
        )

    print(
        f"\nLoading features:\n{FEATURE_FILE}"
    )

    dataframe = pd.read_csv(
        FEATURE_FILE
    )

    validate_feature_dataset(
        dataframe
    )

    print(
        f"Loaded {len(dataframe):,} flows."
    )

    print(
        f"\nLoading detection rules:\n"
        f"{RULES_FILE}"
    )

    engine = SignatureRuleEngine()

    print(
        f"Loaded {len(engine.rules)} rules."
    )

    print(
        "\nRunning signature detection..."
    )

    results = engine.evaluate_dataset(
        dataframe
    )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    results.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    suspicious = results[
        results["classification"] == "SUSPICIOUS"
    ]

    normal = results[
        results["classification"] == "NORMAL"
    ]

    print("\n" + "=" * 80)
    print("SIGNATURE DETECTION COMPLETED")
    print("=" * 80)

    print(
        f"\nTotal flows evaluated : {len(results):,}"
    )

    print(
        f"Normal flows          : {len(normal):,}"
    )

    print(
        f"Suspicious flows      : {len(suspicious):,}"
    )

    print(
        f"\nDetection rate        : "
        f"{len(suspicious) / len(results) * 100:.2f}%"
    )

    print("\nRule match counts:")

    if suspicious.empty:

        print(
            "  No rules matched."
        )

    else:

        for rule_id, count in (
            suspicious["matched_rule_ids"]
            .str.split(",")
            .explode()
            .value_counts()
            .items()
        ):

            if rule_id.strip():

                print(
                    f"  {rule_id}: {count}"
                )

    print(
        f"\nResults saved to:\n"
        f"{OUTPUT_FILE}"
    )

    print("\nSignature engine validation: PASSED")


if __name__ == "__main__":
    main()