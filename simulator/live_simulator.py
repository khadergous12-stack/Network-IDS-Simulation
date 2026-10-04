"""
Network IDS - Live Synthetic Traffic Simulator

IMPORTANT:
This simulator generates DATA RECORDS only.
It does NOT send packets and does NOT interact with
any external network.

Usage:

    python simulator/live_simulator.py

    python simulator/live_simulator.py --mode normal

    python simulator/live_simulator.py --mode mixed

    python simulator/live_simulator.py --mode suspicious

    python simulator/live_simulator.py --speed slow

    python simulator/live_simulator.py --speed fast
"""

from __future__ import annotations

import argparse
import random
import time
from datetime import datetime, timezone
from typing import Any

import requests


# ============================================================
# CONFIGURATION
# ============================================================

API_URL = "http://127.0.0.1:8000/api/flows"

SPEEDS = {
    "slow": 3.0,
    "normal": 1.5,
    "fast": 0.5,
}


NORMAL_DESTINATIONS = [
    "198.51.100.10",
    "198.51.100.11",
    "198.51.100.12",
    "198.51.100.13",
]


SUSPICIOUS_DESTINATIONS = [
    "203.0.113.10",
    "203.0.113.11",
    "203.0.113.12",
]


# ============================================================
# IP GENERATION
# ============================================================

def generate_source_ip() -> str:

    return (
        f"192.0.2."
        f"{random.randint(10, 30)}"
    )


def generate_normal_destination() -> str:

    return random.choice(
        NORMAL_DESTINATIONS
    )


def generate_suspicious_destination() -> str:

    return random.choice(
        SUSPICIOUS_DESTINATIONS
    )


# ============================================================
# NORMAL FLOW
# ============================================================

def generate_normal_flow() -> dict[str, Any]:

    protocol = random.choice(
        [
            "TCP",
            "UDP",
        ]
    )

    destination_port = random.choice(
        [
            53,
            80,
            443,
            22,
            25,
            587,
        ]
    )

    packet_count = random.randint(
        10,
        80,
    )

    duration = round(
        random.uniform(
            1.0,
            10.0,
        ),
        3,
    )

    byte_count = random.randint(
        1000,
        50000,
    )

    connection_count = random.randint(
        1,
        5,
    )

    failed_connections = random.randint(
        0,
        1,
    )

    syn_count = random.randint(
        0,
        5,
    )

    rst_count = random.randint(
        0,
        2,
    )

    return {
        "flow_id": (
            f"LIVE-"
            f"{int(time.time() * 1000)}-"
            f"{random.randint(100, 999)}"
        ),

        "timestamp": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "source_ip": (
            generate_source_ip()
        ),

        "destination_ip": (
            generate_normal_destination()
        ),

        "source_port": random.randint(
            1024,
            65535,
        ),

        "destination_port": (
            destination_port
        ),

        "protocol": protocol,

        "packet_count": packet_count,

        "byte_count": byte_count,

        "duration_seconds": duration,

        "connection_count": connection_count,

        "failed_connection_count": (
            failed_connections
        ),

        "syn_count": syn_count,

        "rst_count": rst_count,

        "average_packet_size": round(
            byte_count /
            max(packet_count, 1),
            2,
        ),

        "label": "NORMAL",

        "scenario_type": (
            "LIVE_NORMAL"
        ),
    }


# ============================================================
# HIGH CONNECTION RATE
# ============================================================

def generate_high_connection_flow() -> dict[str, Any]:

    duration = round(
        random.uniform(
            0.5,
            2.0,
        ),
        3,
    )

    packet_count = random.randint(
        150,
        400,
    )

    byte_count = random.randint(
        50000,
        150000,
    )

    connection_count = random.randint(
        80,
        180,
    )

    failed_connections = random.randint(
        20,
        80,
    )

    syn_count = random.randint(
        30,
        100,
    )

    return {
        "flow_id": (
            f"LIVE-SUSP-"
            f"{int(time.time() * 1000)}-"
            f"{random.randint(100, 999)}"
        ),

        "timestamp": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "source_ip": (
            generate_source_ip()
        ),

        "destination_ip": (
            generate_suspicious_destination()
        ),

        "source_port": random.randint(
            1024,
            65535,
        ),

        "destination_port": random.randint(
            1000,
            65000,
        ),

        "protocol": "TCP",

        "packet_count": packet_count,

        "byte_count": byte_count,

        "duration_seconds": duration,

        "connection_count": connection_count,

        "failed_connection_count": (
            failed_connections
        ),

        "syn_count": syn_count,

        "rst_count": random.randint(
            5,
            30,
        ),

        "average_packet_size": round(
            byte_count /
            max(packet_count, 1),
            2,
        ),

        "label": "SUSPICIOUS",

        "scenario_type": (
            "LIVE_HIGH_CONNECTION_RATE"
        ),
    }


# ============================================================
# MULTI-PORT PATTERN
# ============================================================

def generate_multi_port_flow() -> dict[str, Any]:

    duration = round(
        random.uniform(
            1.0,
            3.0,
        ),
        3,
    )

    packet_count = random.randint(
        100,
        250,
    )

    byte_count = random.randint(
        20000,
        80000,
    )

    return {
        "flow_id": (
            f"LIVE-PORT-"
            f"{int(time.time() * 1000)}-"
            f"{random.randint(100, 999)}"
        ),

        "timestamp": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "source_ip": (
            generate_source_ip()
        ),

        "destination_ip": (
            generate_suspicious_destination()
        ),

        "source_port": random.randint(
            1024,
            65535,
        ),

        "destination_port": random.randint(
            1,
            65535,
        ),

        "protocol": "TCP",

        "packet_count": packet_count,

        "byte_count": byte_count,

        "duration_seconds": duration,

        "connection_count": random.randint(
            20,
            60,
        ),

        "failed_connection_count": random.randint(
            10,
            40,
        ),

        "syn_count": random.randint(
            20,
            70,
        ),

        "rst_count": random.randint(
            5,
            20,
        ),

        "average_packet_size": round(
            byte_count /
            max(packet_count, 1),
            2,
        ),

        "label": "SUSPICIOUS",

        "scenario_type": (
            "LIVE_MULTI_PORT_PATTERN"
        ),
    }


# ============================================================
# SYN-HEAVY PATTERN
# ============================================================

def generate_syn_heavy_flow() -> dict[str, Any]:

    duration = round(
        random.uniform(
            0.2,
            1.0,
        ),
        3,
    )

    packet_count = random.randint(
        200,
        500,
    )

    byte_count = random.randint(
        20000,
        100000,
    )

    syn_count = random.randint(
        120,
        300,
    )

    return {
        "flow_id": (
            f"LIVE-SYN-"
            f"{int(time.time() * 1000)}-"
            f"{random.randint(100, 999)}"
        ),

        "timestamp": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "source_ip": (
            generate_source_ip()
        ),

        "destination_ip": (
            generate_suspicious_destination()
        ),

        "source_port": random.randint(
            1024,
            65535,
        ),

        "destination_port": random.choice(
            [
                80,
                443,
                22,
            ]
        ),

        "protocol": "TCP",

        "packet_count": packet_count,

        "byte_count": byte_count,

        "duration_seconds": duration,

        "connection_count": random.randint(
            30,
            100,
        ),

        "failed_connection_count": random.randint(
            10,
            50,
        ),

        "syn_count": syn_count,

        "rst_count": random.randint(
            20,
            80,
        ),

        "average_packet_size": round(
            byte_count /
            max(packet_count, 1),
            2,
        ),

        "label": "SUSPICIOUS",

        "scenario_type": (
            "LIVE_SYN_HEAVY_PATTERN"
        ),
    }


# ============================================================
# FLOW GENERATOR
# ============================================================

def generate_flow(
    mode: str,
) -> dict[str, Any]:

    if mode == "normal":

        return generate_normal_flow()

    if mode == "suspicious":

        generator = random.choice(
            [
                generate_high_connection_flow,
                generate_multi_port_flow,
                generate_syn_heavy_flow,
            ]
        )

        return generator()

    # mixed mode

    probability = random.random()

    if probability < 0.75:

        return generate_normal_flow()

    generator = random.choice(
        [
            generate_high_connection_flow,
            generate_multi_port_flow,
            generate_syn_heavy_flow,
        ]
    )

    return generator()


# ============================================================
# SEND FLOW TO BACKEND
# ============================================================

def send_flow(
    flow: dict[str, Any],
) -> None:

    try:

        response = requests.post(
            API_URL,
            json=flow,
            timeout=5,
        )

        if response.status_code == 200:

            result = response.json()

            print(
                "\n"
                f"[FLOW] "
                f"{flow['flow_id']} | "
                f"{flow['scenario_type']}"
            )

            print(
                f"[IDS] "
                f"classification="
                f"{result.get('classification')} | "
                f"risk="
                f"{result.get('risk_score')} | "
                f"alert="
                f"{result.get('alert_generated')}"
            )

        else:

            print(
                "[ERROR] Backend returned "
                f"{response.status_code}: "
                f"{response.text}"
            )

    except requests.RequestException as exc:

        print(
            "[ERROR] Unable to connect "
            f"to backend: {exc}"
        )


# ============================================================
# MAIN SIMULATION LOOP
# ============================================================

def run_simulation(
    mode: str,
    speed: str,
) -> None:

    interval = SPEEDS[
        speed
    ]

    print("=" * 80)

    print(
        "NETWORK IDS — LIVE "
        "SYNTHETIC TRAFFIC SIMULATOR"
    )

    print("=" * 80)

    print(
        f"Mode : {mode}"
    )

    print(
        f"Speed: {speed}"
    )

    print(
        f"Interval: {interval} seconds"
    )

    print()

    print(
        "Safety: DATA GENERATION ONLY"
    )

    print(
        "No network packets are sent."
    )

    print()

    print(
        "Press CTRL+C to stop."
    )

    print("=" * 80)

    try:

        while True:

            flow = generate_flow(
                mode
            )

            send_flow(
                flow
            )

            time.sleep(
                interval
            )

    except KeyboardInterrupt:

        print(
            "\n"
            "Simulation stopped."
        )


# ============================================================
# CLI
# ============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Safe synthetic Network IDS "
            "traffic simulator."
        )
    )

    parser.add_argument(
        "--mode",
        choices=[
            "normal",
            "mixed",
            "suspicious",
        ],
        default="mixed",
    )

    parser.add_argument(
        "--speed",
        choices=[
            "slow",
            "normal",
            "fast",
        ],
        default="normal",
    )

    args = parser.parse_args()

    run_simulation(
        mode=args.mode,
        speed=args.speed,
    )


if __name__ == "__main__":

    main()