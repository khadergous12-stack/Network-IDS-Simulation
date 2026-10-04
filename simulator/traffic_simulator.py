"""
Synthetic Network Traffic Simulator
------------------------------------

This simulator generates SAFE synthetic network-flow records.

IMPORTANT:
- No real packets are sent.
- No sockets are opened.
- No external hosts are contacted.
- No attack traffic is generated.
- All records are synthetic data.

The simulator is designed to provide a continuous stream of
network-flow-like events for the IDS pipeline.
"""

from __future__ import annotations

import argparse
import random
import time
import uuid
from datetime import datetime
from pathlib import Path

import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = BASE_DIR / "data" / "network_traffic.csv"

RANDOM_SEED = 42

random.seed(RANDOM_SEED)


# ============================================================
# SPEED CONFIGURATION
# ============================================================

SPEED_INTERVALS = {
    "slow": 2.0,
    "normal": 1.0,
    "fast": 0.2,
}


# ============================================================
# DISPLAY HELPERS
# ============================================================

def print_header() -> None:
    """Display simulator header."""

    print("=" * 80)
    print("NETWORK IDS — SYNTHETIC TRAFFIC SIMULATOR")
    print("=" * 80)

    print(
        "\nSAFE SIMULATION MODE:"
        "\n  • No real packets are generated"
        "\n  • No network connections are opened"
        "\n  • No external systems are contacted"
        "\n  • Only synthetic flow records are produced"
    )


def print_flow(flow: dict) -> None:
    """Display one simulated flow."""

    print("\n" + "-" * 80)

    print(f"Flow ID       : {flow['flow_id']}")
    print(f"Timestamp     : {flow['timestamp']}")
    print(f"Source        : {flow['source_ip']}:{flow['source_port']}")
    print(
        f"Destination   : "
        f"{flow['destination_ip']}:{flow['destination_port']}"
    )
    print(f"Protocol      : {flow['protocol']}")
    print(f"Packets       : {flow['packet_count']}")
    print(f"Bytes         : {flow['byte_count']}")
    print(f"Duration      : {flow['duration_seconds']} sec")
    print(f"Connections   : {flow['connection_count']}")
    print(
        f"Failed Conn.  : "
        f"{flow['failed_connection_count']}"
    )
    print(f"SYN Count     : {flow['syn_count']}")
    print(f"RST Count     : {flow['rst_count']}")
    print(
        f"Avg Packet    : "
        f"{flow['average_packet_size']}"
    )
    print(f"Label         : {flow['label']}")
    print(f"Scenario      : {flow['scenario_type']}")


# ============================================================
# DATASET LOADING
# ============================================================

def load_dataset() -> pd.DataFrame:
    """Load the previously generated synthetic dataset."""

    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"\nDataset not found:\n{DATA_FILE}\n\n"
            "Run this first:\n"
            "python simulator\\generate_dataset.py"
        )

    dataframe = pd.read_csv(DATA_FILE)

    if dataframe.empty:
        raise ValueError("The dataset is empty.")

    return dataframe


# ============================================================
# FLOW SELECTION
# ============================================================

def select_normal_flow(dataframe: pd.DataFrame) -> dict:
    """Select one normal flow."""

    normal = dataframe[
        dataframe["label"] == "NORMAL"
    ]

    if normal.empty:
        raise ValueError(
            "No NORMAL records exist in the dataset."
        )

    record = normal.sample(
        n=1,
        random_state=random.randint(1, 100000),
    ).iloc[0]

    return record.to_dict()


def select_suspicious_flow(dataframe: pd.DataFrame) -> dict:
    """Select one suspicious flow."""

    suspicious = dataframe[
        dataframe["label"] == "SUSPICIOUS"
    ]

    if suspicious.empty:
        raise ValueError(
            "No SUSPICIOUS records exist in the dataset."
        )

    record = suspicious.sample(
        n=1,
        random_state=random.randint(1, 100000),
    ).iloc[0]

    return record.to_dict()


def select_mixed_flow(dataframe: pd.DataFrame) -> dict:
    """
    Select a mixture of normal and suspicious traffic.

    Approximately 70% normal and 30% suspicious traffic.
    """

    if random.random() < 0.70:
        return select_normal_flow(dataframe)

    return select_suspicious_flow(dataframe)


# ============================================================
# FLOW PREPARATION
# ============================================================

def prepare_flow(flow: dict) -> dict:
    """
    Prepare a selected dataset record as a new simulated event.

    A new flow ID and current timestamp are assigned so that each
    simulated event represents a newly observed flow.
    """

    flow = dict(flow)

    flow["flow_id"] = str(uuid.uuid4())

    flow["timestamp"] = datetime.now().isoformat()

    return flow


# ============================================================
# SIMULATION
# ============================================================

def run_simulator(
    dataframe: pd.DataFrame,
    mode: str,
    speed: str,
    count: int | None,
) -> None:
    """Run the synthetic traffic simulator."""

    interval = SPEED_INTERVALS[speed]

    generated = 0

    print(f"\nMode        : {mode}")
    print(f"Speed       : {speed}")
    print(f"Interval    : {interval} seconds")

    if count is None:
        print("Flow count  : Continuous")
    else:
        print(f"Flow count  : {count}")

    print(
        "\nPress CTRL+C to stop the simulator.\n"
    )

    try:
        while True:

            if mode == "normal":
                flow = select_normal_flow(dataframe)

            elif mode == "mixed":
                flow = select_mixed_flow(dataframe)

            else:
                raise ValueError(
                    f"Unsupported mode: {mode}"
                )

            flow = prepare_flow(flow)

            print_flow(flow)

            generated += 1

            print(
                f"\nSimulated flows generated: {generated}"
            )

            if count is not None and generated >= count:
                break

            time.sleep(interval)

    except KeyboardInterrupt:

        print("\n\n" + "=" * 80)
        print("SIMULATOR STOPPED")
        print("=" * 80)

        print(
            f"\nTotal simulated flows: {generated}"
        )


# ============================================================
# ARGUMENT PARSER
# ============================================================

def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Safe synthetic network traffic simulator "
            "for the Network IDS project."
        )
    )

    parser.add_argument(
        "--mode",
        choices=["normal", "mixed"],
        default="mixed",
        help=(
            "Traffic mode. "
            "'normal' generates only normal flows; "
            "'mixed' generates normal and suspicious flows."
        ),
    )

    parser.add_argument(
        "--speed",
        choices=["slow", "normal", "fast"],
        default="normal",
        help=(
            "Simulation speed."
        ),
    )

    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help=(
            "Number of flows to generate. "
            "If omitted, simulation continues until stopped."
        ),
    )

    return parser


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """Main simulator entry point."""

    print_header()

    parser = create_parser()

    args = parser.parse_args()

    dataframe = load_dataset()

    print(
        f"\nLoaded dataset: "
        f"{len(dataframe):,} records"
    )

    run_simulator(
        dataframe=dataframe,
        mode=args.mode,
        speed=args.speed,
        count=args.count,
    )


if __name__ == "__main__":
    main()