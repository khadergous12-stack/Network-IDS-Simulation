"""
Synthetic Network Traffic Dataset Generator
--------------------------------------------

Generates safe, synthetic network-flow records for the
Network Intrusion Detection System simulation.

IMPORTANT:
- No real network traffic is generated.
- No packets are sent.
- No external systems are contacted.
- All IP addresses come from documentation/reserved ranges.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_SEED = 42
NUM_RECORDS = 6000

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_FILE = DATA_DIR / "network_traffic.csv"

random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)


# Documentation / reserved IPv4 ranges.
SOURCE_IPS = [
    "192.0.2.10",
    "192.0.2.11",
    "192.0.2.12",
    "192.0.2.13",
    "192.0.2.14",
    "192.0.2.15",
    "192.0.2.16",
    "192.0.2.17",
    "192.0.2.18",
    "192.0.2.19",
]

DESTINATION_IPS = [
    "198.51.100.10",
    "198.51.100.11",
    "198.51.100.12",
    "198.51.100.13",
    "198.51.100.14",
    "203.0.113.10",
    "203.0.113.11",
    "203.0.113.12",
    "203.0.113.13",
]


# ============================================================
# SCENARIO DEFINITIONS
# ============================================================

NORMAL_SCENARIOS = [
    "NORMAL_WEB",
    "NORMAL_DNS",
    "NORMAL_SSH",
    "NORMAL_EMAIL",
    "NORMAL_DATABASE",
]

SUSPICIOUS_SCENARIOS = [
    "HIGH_CONNECTION_RATE",
    "REPEATED_FAILED_CONNECTIONS",
    "MULTI_PORT_PROBING_PATTERN",
    "SYN_HEAVY_PATTERN",
    "UNUSUAL_PORT_ACTIVITY",
    "HIGH_TRAFFIC_VOLUME",
]


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def random_timestamp(start: datetime, end: datetime) -> datetime:
    """Generate a random timestamp between start and end."""
    total_seconds = int((end - start).total_seconds())

    if total_seconds <= 0:
        return start

    offset = random.randint(0, total_seconds)
    return start + timedelta(seconds=offset)


def random_ip(ip_pool: list[str]) -> str:
    """Select a random IP from a predefined safe pool."""
    return random.choice(ip_pool)


def random_normal_port() -> int:
    """Generate a realistic ephemeral source port."""
    return random.randint(1024, 65535)


def choose_protocol() -> str:
    """Choose a common network protocol."""
    return random.choices(
        ["TCP", "UDP"],
        weights=[75, 25],
        k=1,
    )[0]


def calculate_average_packet_size(
    byte_count: int,
    packet_count: int,
) -> float:
    """Calculate average packet size safely."""
    if packet_count <= 0:
        return 0.0

    return round(byte_count / packet_count, 2)


# ============================================================
# NORMAL TRAFFIC GENERATORS
# ============================================================

def generate_normal_web() -> dict:
    """Generate normal HTTPS/web browsing flow."""
    packet_count = random.randint(8, 80)
    average_packet_size = random.uniform(450, 1300)
    byte_count = int(packet_count * average_packet_size)

    duration = round(random.uniform(0.5, 12.0), 2)

    return {
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": random.randint(1, 5),
        "failed_connection_count": 0,
        "syn_count": random.randint(1, 3),
        "rst_count": random.choice([0, 0, 1]),
    }


def generate_normal_dns() -> dict:
    """Generate normal DNS flow."""
    packet_count = random.randint(2, 15)
    average_packet_size = random.uniform(60, 300)
    byte_count = int(packet_count * average_packet_size)

    duration = round(random.uniform(0.01, 2.0), 2)

    return {
        "destination_port": 53,
        "protocol": "UDP",
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": random.randint(1, 3),
        "failed_connection_count": 0,
        "syn_count": 0,
        "rst_count": 0,
    }


def generate_normal_ssh() -> dict:
    """Generate normal SSH flow."""
    packet_count = random.randint(20, 180)
    average_packet_size = random.uniform(100, 900)
    byte_count = int(packet_count * average_packet_size)

    duration = round(random.uniform(2.0, 120.0), 2)

    return {
        "destination_port": 22,
        "protocol": "TCP",
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": random.randint(1, 3),
        "failed_connection_count": random.randint(0, 1),
        "syn_count": random.randint(1, 3),
        "rst_count": random.choice([0, 0, 1]),
    }


def generate_normal_email() -> dict:
    """Generate normal email flow."""
    destination_port = random.choice([25, 465, 587, 993])

    packet_count = random.randint(15, 120)
    average_packet_size = random.uniform(250, 1200)
    byte_count = int(packet_count * average_packet_size)

    duration = round(random.uniform(1.0, 60.0), 2)

    return {
        "destination_port": destination_port,
        "protocol": "TCP",
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": random.randint(1, 4),
        "failed_connection_count": random.randint(0, 1),
        "syn_count": random.randint(1, 3),
        "rst_count": random.choice([0, 0, 1]),
    }


def generate_normal_database() -> dict:
    """Generate normal database traffic."""
    destination_port = random.choice([1433, 3306, 5432, 1521])

    packet_count = random.randint(20, 250)
    average_packet_size = random.uniform(200, 1500)
    byte_count = int(packet_count * average_packet_size)

    duration = round(random.uniform(1.0, 180.0), 2)

    return {
        "destination_port": destination_port,
        "protocol": "TCP",
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": random.randint(1, 8),
        "failed_connection_count": random.randint(0, 1),
        "syn_count": random.randint(1, 3),
        "rst_count": random.choice([0, 0, 1]),
    }


# ============================================================
# SUSPICIOUS PATTERN GENERATORS
# ============================================================

def generate_high_connection_rate() -> dict:
    """Generate a synthetic high-connection-rate pattern."""
    packet_count = random.randint(150, 700)
    byte_count = random.randint(15000, 100000)

    return {
        "destination_port": random.choice([80, 443, 22, 8080]),
        "protocol": "TCP",
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(0.5, 4.0), 2),
        "connection_count": random.randint(80, 250),
        "failed_connection_count": random.randint(20, 100),
        "syn_count": random.randint(50, 180),
        "rst_count": random.randint(10, 70),
    }


def generate_repeated_failed_connections() -> dict:
    """Generate repeated failed connection behavior."""
    packet_count = random.randint(30, 150)
    byte_count = random.randint(3000, 25000)

    failed = random.randint(15, 80)
    connections = max(failed + random.randint(5, 30), failed)

    return {
        "destination_port": random.choice([22, 23, 3389, 3306]),
        "protocol": "TCP",
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(1.0, 20.0), 2),
        "connection_count": connections,
        "failed_connection_count": failed,
        "syn_count": random.randint(15, 80),
        "rst_count": random.randint(10, 60),
    }


def generate_multi_port_probing() -> dict:
    """Generate a synthetic multi-port probing-like flow."""
    packet_count = random.randint(50, 300)
    byte_count = random.randint(5000, 40000)

    return {
        "destination_port": random.randint(1, 65535),
        "protocol": "TCP",
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(0.2, 8.0), 2),
        "connection_count": random.randint(40, 160),
        "failed_connection_count": random.randint(15, 100),
        "syn_count": random.randint(30, 140),
        "rst_count": random.randint(15, 100),
    }


def generate_syn_heavy() -> dict:
    """Generate a synthetic SYN-heavy statistical pattern."""
    packet_count = random.randint(100, 600)
    syn_count = random.randint(
        max(60, int(packet_count * 0.65)),
        packet_count,
    )

    byte_count = random.randint(5000, 50000)

    return {
        "destination_port": random.choice([22, 80, 443, 8080]),
        "protocol": "TCP",
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(0.1, 5.0), 2),
        "connection_count": random.randint(50, 220),
        "failed_connection_count": random.randint(10, 100),
        "syn_count": syn_count,
        "rst_count": random.randint(20, 120),
    }


def generate_unusual_port_activity() -> dict:
    """Generate activity involving an unusual service port."""
    packet_count = random.randint(30, 180)
    average_packet_size = random.uniform(100, 1000)
    byte_count = int(packet_count * average_packet_size)

    unusual_ports = [
        31337,
        4444,
        5555,
        8081,
        9999,
        10000,
        12345,
    ]

    return {
        "destination_port": random.choice(unusual_ports),
        "protocol": random.choice(["TCP", "UDP"]),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(0.5, 30.0), 2),
        "connection_count": random.randint(5, 30),
        "failed_connection_count": random.randint(1, 15),
        "syn_count": random.randint(1, 20),
        "rst_count": random.randint(0, 15),
    }


def generate_high_traffic_volume() -> dict:
    """Generate a synthetic unusually high-volume flow."""
    packet_count = random.randint(2000, 10000)
    average_packet_size = random.uniform(800, 1450)
    byte_count = int(packet_count * average_packet_size)

    return {
        "destination_port": random.choice([80, 443, 8080]),
        "protocol": random.choice(["TCP", "UDP"]),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(random.uniform(2.0, 30.0), 2),
        "connection_count": random.randint(100, 500),
        "failed_connection_count": random.randint(5, 80),
        "syn_count": random.randint(50, 250),
        "rst_count": random.randint(5, 80),
    }


# ============================================================
# SCENARIO GENERATION
# ============================================================

NORMAL_GENERATORS = {
    "NORMAL_WEB": generate_normal_web,
    "NORMAL_DNS": generate_normal_dns,
    "NORMAL_SSH": generate_normal_ssh,
    "NORMAL_EMAIL": generate_normal_email,
    "NORMAL_DATABASE": generate_normal_database,
}

SUSPICIOUS_GENERATORS = {
    "HIGH_CONNECTION_RATE": generate_high_connection_rate,
    "REPEATED_FAILED_CONNECTIONS": generate_repeated_failed_connections,
    "MULTI_PORT_PROBING_PATTERN": generate_multi_port_probing,
    "SYN_HEAVY_PATTERN": generate_syn_heavy,
    "UNUSUAL_PORT_ACTIVITY": generate_unusual_port_activity,
    "HIGH_TRAFFIC_VOLUME": generate_high_traffic_volume,
}


def generate_flow(
    scenario_type: str,
    timestamp: datetime,
) -> dict:
    """Generate one complete synthetic network-flow record."""

    if scenario_type in NORMAL_GENERATORS:
        generator = NORMAL_GENERATORS[scenario_type]
        label = "NORMAL"
    else:
        generator = SUSPICIOUS_GENERATORS[scenario_type]
        label = "SUSPICIOUS"

    traffic = generator()

    source_ip = random_ip(SOURCE_IPS)
    destination_ip = random_ip(DESTINATION_IPS)

    # Avoid identical source and destination addresses.
    while destination_ip == source_ip:
        destination_ip = random_ip(DESTINATION_IPS)

    packet_count = traffic["packet_count"]
    byte_count = traffic["byte_count"]

    return {
        "flow_id": str(uuid.uuid4()),
        "timestamp": timestamp.isoformat(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": random_normal_port(),
        "destination_port": traffic["destination_port"],
        "protocol": traffic["protocol"],
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": traffic["duration_seconds"],
        "connection_count": traffic["connection_count"],
        "failed_connection_count": traffic["failed_connection_count"],
        "syn_count": traffic["syn_count"],
        "rst_count": traffic["rst_count"],
        "average_packet_size": calculate_average_packet_size(
            byte_count,
            packet_count,
        ),
        "label": label,
        "scenario_type": scenario_type,
    }


# ============================================================
# DATASET CREATION
# ============================================================

def build_dataset(num_records: int) -> pd.DataFrame:
    """Build the complete synthetic network-flow dataset."""

    start_time = datetime.now() - timedelta(days=30)
    end_time = datetime.now()

    # Roughly 70% normal and 30% suspicious traffic.
    normal_count = int(num_records * 0.70)
    suspicious_count = num_records - normal_count

    normal_scenarios = random.choices(
        NORMAL_SCENARIOS,
        k=normal_count,
    )

    suspicious_scenarios = random.choices(
        SUSPICIOUS_SCENARIOS,
        k=suspicious_count,
    )

    scenarios = normal_scenarios + suspicious_scenarios

    random.shuffle(scenarios)

    records = []

    for scenario in scenarios:
        timestamp = random_timestamp(start_time, end_time)
        record = generate_flow(scenario, timestamp)
        records.append(record)

    dataframe = pd.DataFrame(records)

    dataframe.sort_values(
        by="timestamp",
        inplace=True,
    )

    dataframe.reset_index(
        drop=True,
        inplace=True,
    )

    return dataframe


def validate_dataset(dataframe: pd.DataFrame) -> None:
    """Validate the generated dataset against project requirements."""

    required_columns = [
        "flow_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "packet_count",
        "byte_count",
        "duration_seconds",
        "connection_count",
        "failed_connection_count",
        "syn_count",
        "rst_count",
        "average_packet_size",
        "label",
        "scenario_type",
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    if len(dataframe) < 5000:
        raise ValueError(
            f"Dataset contains only {len(dataframe)} records. "
            "At least 5,000 are required."
        )

    valid_labels = {"NORMAL", "SUSPICIOUS"}

    actual_labels = set(dataframe["label"].unique())

    if not actual_labels.issubset(valid_labels):
        raise ValueError(
            f"Unexpected labels detected: {actual_labels}"
        )

    if dataframe["flow_id"].duplicated().any():
        raise ValueError("Duplicate flow IDs detected.")

    if (dataframe["packet_count"] < 0).any():
        raise ValueError("Negative packet count detected.")

    if (dataframe["byte_count"] < 0).any():
        raise ValueError("Negative byte count detected.")

    if (dataframe["duration_seconds"] <= 0).any():
        raise ValueError("Invalid duration detected.")

    if not dataframe["source_port"].between(1, 65535).all():
        raise ValueError("Invalid source port detected.")

    if not dataframe["destination_port"].between(1, 65535).all():
        raise ValueError("Invalid destination port detected.")


def save_dataset(dataframe: pd.DataFrame) -> None:
    """Save the generated dataset to the project's data directory."""

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    dataframe.to_csv(
        OUTPUT_FILE,
        index=False,
    )


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """Generate, validate and save the synthetic dataset."""

    print("=" * 70)
    print("NETWORK IDS — SYNTHETIC DATASET GENERATOR")
    print("=" * 70)

    print(f"\nGenerating {NUM_RECORDS:,} synthetic network-flow records...")

    dataframe = build_dataset(NUM_RECORDS)

    print("Validating dataset...")
    validate_dataset(dataframe)

    print("Saving dataset...")
    save_dataset(dataframe)

    print("\n" + "=" * 70)
    print("DATASET GENERATED SUCCESSFULLY")
    print("=" * 70)

    print(f"\nOutput file:")
    print(f"  {OUTPUT_FILE}")

    print(f"\nTotal records:")
    print(f"  {len(dataframe):,}")

    print("\nLabels:")
    print(dataframe["label"].value_counts().to_string())

    print("\nScenario distribution:")
    print(dataframe["scenario_type"].value_counts().to_string())

    print("\nProtocols:")
    print(dataframe["protocol"].value_counts().to_string())

    print("\nDataset columns:")
    for column in dataframe.columns:
        print(f"  - {column}")

    print("\nFirst 5 records:")
    print(dataframe.head().to_string(index=False))

    print("\nDataset validation: PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()