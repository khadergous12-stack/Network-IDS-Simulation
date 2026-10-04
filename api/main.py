"""

Network IDS - SOC Dashboard API

--------------------------------



FastAPI backend for exposing IDS results.



Data sources:



    data/hybrid_risk_results.csv

    data/alerts.csv

    data/incidents.csv

    data/evaluation_metrics.json



Run:



    uvicorn api.main:app --reload

"""



from __future__ import annotations



import json

from pathlib import Path

from typing import Any



import pandas as pd

from fastapi import FastAPI, HTTPException

from fastapi.middleware.cors import CORSMiddleware



from pydantic import BaseModel

from datetime import datetime, timezone

import time





# ============================================================

# PATHS

# ============================================================



BASE_DIR = Path(__file__).resolve().parent.parent



DATA_DIR = BASE_DIR / "data"



HYBRID_FILE = (

    DATA_DIR / "hybrid_risk_results.csv"

)



ALERT_FILE = (

    DATA_DIR / "alerts.csv"

)



INCIDENT_FILE = (

    DATA_DIR / "incidents.csv"

)



METRICS_FILE = (

    DATA_DIR / "evaluation_metrics.json"

)

FEATURES_FILE = (
    DATA_DIR / "network_features.csv"
)





# ============================================================

# APPLICATION

# ============================================================



app = FastAPI(

    title="Network IDS SOC API",

    description=(

        "Backend API for the Network IDS "

        "Simulation and SOC Dashboard."

    ),

    version="1.0.0",

)





# ============================================================

# CORS

# ============================================================



app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

)





# ============================================================

# HELPERS

# ============================================================



def load_csv(

    file_path: Path,

) -> pd.DataFrame:



    if not file_path.exists():



        raise HTTPException(

            status_code=404,

            detail=(

                f"Required data file not found: "

                f"{file_path.name}"

            ),

        )



    try:



        dataframe = pd.read_csv(

            file_path

        )



    except Exception as exc:



        raise HTTPException(

            status_code=500,

            detail=(

                f"Unable to read "

                f"{file_path.name}: {exc}"

            ),

        ) from exc



    return dataframe





def load_metrics() -> dict[str, Any]:



    if not METRICS_FILE.exists():



        raise HTTPException(

            status_code=404,

            detail=(

                "Evaluation metrics file not found."

            ),

        )



    try:



        with METRICS_FILE.open(

            "r",

            encoding="utf-8",

        ) as file:



            return json.load(file)



    except Exception as exc:



        raise HTTPException(

            status_code=500,

            detail=(

                f"Unable to read evaluation "

                f"metrics: {exc}"

            ),

        ) from exc





def clean_value(

    value: Any,

) -> Any:



    if pd.isna(value):



        return None



    if hasattr(

        value,

        "item",

    ):



        try:



            return value.item()



        except Exception:



            pass



    return value





def dataframe_records(

    dataframe: pd.DataFrame,

) -> list[dict[str, Any]]:



    records = []



    for record in (

        dataframe

        .to_dict(

            orient="records"

        )

    ):



        cleaned = {

            key: clean_value(value)

            for key, value in record.items()

        }



        records.append(

            cleaned

        )



    return records



class LiveFlow(BaseModel):



    flow_id: str



    timestamp: str



    source_ip: str



    destination_ip: str



    source_port: int



    destination_port: int



    protocol: str



    packet_count: int



    byte_count: int



    duration_seconds: float



    connection_count: int



    failed_connection_count: int



    syn_count: int



    rst_count: int



    average_packet_size: float



    label: str



    scenario_type: str





# ============================================================

# ROOT

# ============================================================



@app.get("/")

def root() -> dict[str, Any]:



    return {

        "application": (

            "Network IDS SOC API"

        ),

        "version": "1.0.0",

        "status": "online",

        "documentation": "/docs",

    }





# ============================================================

# HEALTH

# ============================================================



@app.get("/api/health")

def health() -> dict[str, Any]:



    files = {

        "hybrid_results": HYBRID_FILE.exists(),

        "alerts": ALERT_FILE.exists(),

        "incidents": INCIDENT_FILE.exists(),

        "evaluation_metrics": METRICS_FILE.exists(),

    }



    return {

        "status": "healthy",

        "data_sources": files,

    }





# ============================================================

# DASHBOARD SUMMARY

# ============================================================



@app.get("/api/dashboard/summary")

def dashboard_summary() -> dict[str, Any]:



    hybrid = load_csv(

        HYBRID_FILE

    )



    alerts = load_csv(

        ALERT_FILE

    )



    incidents = load_csv(

        INCIDENT_FILE

    )



    # --------------------------------------------------------

    # Severity counts

    # --------------------------------------------------------



    severity_counts = (

        alerts[

            "severity"

        ]

        .astype(str)

        .str.upper()

        .value_counts()

        .to_dict()

    )



    # --------------------------------------------------------

    # Incident status

    # --------------------------------------------------------



    incident_status_counts = (

        incidents[

            "status"

        ]

        .astype(str)

        .str.upper()

        .value_counts()

        .to_dict()

    )



    # --------------------------------------------------------

    # Detection methods

    # --------------------------------------------------------



    detection_methods = {}



    if not alerts.empty:



        for value in alerts[

            "detection_methods"

        ].dropna():



            methods = str(

                value

            ).split(", ")



            for method in methods:



                detection_methods[

                    method

                ] = (

                    detection_methods.get(

                        method,

                        0,

                    )

                    + 1

                )



    # --------------------------------------------------------

    # Scenario distribution

    # --------------------------------------------------------



    scenario_counts = (

        hybrid[

            "scenario_type"

        ]

        .astype(str)

        .value_counts()

        .to_dict()

    )



    # --------------------------------------------------------

    # Response

    # --------------------------------------------------------



    return {

        "total_flows": int(

            len(hybrid)

        ),



        "total_alerts": int(

            len(alerts)

        ),



        "total_incidents": int(

            len(incidents)

        ),



        "average_risk_score": round(

            float(

                hybrid[

                    "risk_score"

                ].mean()

            ),

            2,

        ),



        "maximum_risk_score": round(

            float(

                hybrid[

                    "risk_score"

                ].max()

            ),

            2,

        ),



        "severity": {

            "critical": int(

                severity_counts.get(

                    "CRITICAL",

                    0,

                )

            ),

            "high": int(

                severity_counts.get(

                    "HIGH",

                    0,

                )

            ),

            "medium": int(

                severity_counts.get(

                    "MEDIUM",

                    0,

                )

            ),

            "low": int(

                severity_counts.get(

                    "LOW",

                    0,

                )

            ),

        },



        "incident_status": {

            key.lower(): int(value)

            for key, value

            in incident_status_counts.items()

        },



        "detection_methods": {

            key: int(value)

            for key, value

            in detection_methods.items()

        },



        "scenario_distribution": {

            key: int(value)

            for key, value

            in scenario_counts.items()

        },

    }





# ============================================================

# RECENT ALERTS

# ============================================================



@app.get("/api/alerts")

def get_alerts(

    limit: int = 20,

) -> dict[str, Any]:



    if limit < 1 or limit > 200:



        raise HTTPException(

            status_code=400,

            detail=(

                "limit must be between "

                "1 and 200."

            ),

        )



    alerts = load_csv(

        ALERT_FILE

    )



    alerts = alerts.sort_values(

        "risk_score",

        ascending=False,

    )



    alerts = alerts.head(

        limit

    )



    return {

        "count": len(alerts),

        "alerts": dataframe_records(

            alerts

        ),

    }





# ============================================================
# SINGLE ALERT — EVENT INVESTIGATION
# ============================================================

@app.get("/api/alerts/{alert_id}")
def get_alert(
    alert_id: str,
) -> dict[str, Any]:
    """
    Return a complete investigation record for a single alert.

    Combines:
        - alerts.csv
        - network_features.csv
        - hybrid_risk_results.csv

    This endpoint powers the Event Investigation Page.
    """

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    alerts = load_csv(ALERT_FILE)
    features = load_csv(FEATURES_FILE)
    hybrid = load_csv(HYBRID_FILE)

    # --------------------------------------------------------
    # Validate alert_id column
    # --------------------------------------------------------

    if "alert_id" not in alerts.columns:
        raise HTTPException(
            status_code=500,
            detail="alerts.csv is missing required column: alert_id",
        )

    # --------------------------------------------------------
    # Find requested alert
    # --------------------------------------------------------

    alert_matches = alerts[
        alerts["alert_id"]
        .astype(str)
        .str.strip()
        == str(alert_id).strip()
    ]

    if alert_matches.empty:
        raise HTTPException(
            status_code=404,
            detail=f"Alert '{alert_id}' not found.",
        )

    alert_record = alert_matches.iloc[0].to_dict()

    # --------------------------------------------------------
    # Determine flow_id
    # --------------------------------------------------------

    flow_id = alert_record.get("flow_id")

    if flow_id is None:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Alert '{alert_id}' does not contain "
                "a flow_id."
            ),
        )

    flow_id = str(flow_id)

    # --------------------------------------------------------
    # Find network flow
    # --------------------------------------------------------

    if "flow_id" not in features.columns:
        raise HTTPException(
            status_code=500,
            detail=(
                "network_features.csv is missing "
                "required column: flow_id"
            ),
        )

    feature_matches = features[
        features["flow_id"]
        .astype(str)
        .str.strip()
        == flow_id
    ]

    flow_record = {}

    if not feature_matches.empty:
        flow_record = (
            feature_matches
            .iloc[0]
            .to_dict()
        )

    # --------------------------------------------------------
    # Find hybrid detection result
    # --------------------------------------------------------

    if "flow_id" not in hybrid.columns:
        raise HTTPException(
            status_code=500,
            detail=(
                "hybrid_risk_results.csv is missing "
                "required column: flow_id"
            ),
        )

    hybrid_matches = hybrid[
        hybrid["flow_id"]
        .astype(str)
        .str.strip()
        == flow_id
    ]

    hybrid_record = {}

    if not hybrid_matches.empty:
        hybrid_record = (
            hybrid_matches
            .iloc[0]
            .to_dict()
        )

    # --------------------------------------------------------
    # Helper for safe values
    # --------------------------------------------------------

    def first_value(
        *values: Any,
        default: Any = None,
    ) -> Any:

        for value in values:
            if value is None:
                continue

            try:
                if pd.isna(value):
                    continue
            except Exception:
                pass

            if isinstance(value, str):
                if not value.strip():
                    continue

            return value

        return default

    # --------------------------------------------------------
    # Basic alert information
    # --------------------------------------------------------

    timestamp = first_value(
        alert_record.get("timestamp"),
        flow_record.get("timestamp"),
        hybrid_record.get("timestamp"),
    )

    source_ip = first_value(
        alert_record.get("source_ip"),
        flow_record.get("source_ip"),
        hybrid_record.get("source_ip"),
    )

    destination_ip = first_value(
        alert_record.get("destination_ip"),
        flow_record.get("destination_ip"),
        hybrid_record.get("destination_ip"),
    )

    protocol = first_value(
        alert_record.get("protocol"),
        flow_record.get("protocol"),
        hybrid_record.get("protocol"),
    )

    source_port = first_value(
        alert_record.get("source_port"),
        flow_record.get("source_port"),
        hybrid_record.get("source_port"),
    )

    destination_port = first_value(
        alert_record.get("destination_port"),
        flow_record.get("destination_port"),
        hybrid_record.get("destination_port"),
    )

    # --------------------------------------------------------
    # Traffic statistics
    # --------------------------------------------------------

    traffic_statistics = {
        "packet_count": first_value(
            flow_record.get("packet_count"),
            default=0,
        ),
        "byte_count": first_value(
            flow_record.get("byte_count"),
            default=0,
        ),
        "duration_seconds": first_value(
            flow_record.get("duration_seconds"),
            default=0,
        ),
        "connection_count": first_value(
            flow_record.get("connection_count"),
            default=0,
        ),
        "failed_connection_count": first_value(
            flow_record.get(
                "failed_connection_count"
            ),
            default=0,
        ),
        "syn_count": first_value(
            flow_record.get("syn_count"),
            default=0,
        ),
        "rst_count": first_value(
            flow_record.get("rst_count"),
            default=0,
        ),
        "average_packet_size": first_value(
            flow_record.get(
                "average_packet_size"
            ),
            default=0,
        ),
        "packets_per_second": first_value(
            flow_record.get(
                "packets_per_second"
            ),
        ),
        "bytes_per_second": first_value(
            flow_record.get(
                "bytes_per_second"
            ),
        ),
        "connection_rate": first_value(
            flow_record.get(
                "connection_rate"
            ),
        ),
        "failed_connection_ratio": first_value(
            flow_record.get(
                "failed_connection_ratio"
            ),
        ),
        "syn_ratio": first_value(
            flow_record.get("syn_ratio"),
        ),
        "rst_ratio": first_value(
            flow_record.get("rst_ratio"),
        ),
    }

    # --------------------------------------------------------
    # Detection information
    # --------------------------------------------------------

    matched_rule_ids = first_value(
        hybrid_record.get(
            "matched_rule_ids"
        ),
        alert_record.get(
            "matched_rule_ids"
        ),
        default="",
    )

    matched_rule_names = first_value(
        hybrid_record.get(
            "matched_rule_names"
        ),
        alert_record.get(
            "matched_rule_names"
        ),
        default="",
    )

    anomaly_score = first_value(
        hybrid_record.get("anomaly_score"),
        alert_record.get("anomaly_score"),
        default=0,
    )

    ml_score = first_value(
        hybrid_record.get("ml_score"),
        alert_record.get("ml_score"),
    )

    risk_score = first_value(
        hybrid_record.get("risk_score"),
        alert_record.get("risk_score"),
        default=0,
    )

    severity = first_value(
        alert_record.get("severity"),
        hybrid_record.get("severity"),
        default="INFO",
    )

    decision = first_value(
        hybrid_record.get("decision"),
        alert_record.get("decision"),
        default="ALERT",
    )

    anomaly_classification = first_value(
        hybrid_record.get(
            "anomaly_classification"
        ),
        alert_record.get(
            "anomaly_classification"
        ),
    )

    ml_classification = first_value(
        hybrid_record.get(
            "ml_classification"
        ),
        alert_record.get(
            "ml_classification"
        ),
    )

    risk_explanation = first_value(
        hybrid_record.get(
            "risk_explanation"
        ),
        alert_record.get(
            "risk_explanation"
        ),
        default="Risk identified by the IDS detection pipeline.",
    )

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    status = first_value(
        alert_record.get("status"),
        default="NEW",
    )

    status = str(status).upper()

    # --------------------------------------------------------
    # Scenario
    # --------------------------------------------------------

    scenario_type = first_value(
        alert_record.get("scenario_type"),
        flow_record.get("scenario_type"),
        hybrid_record.get("scenario_type"),
        default="UNKNOWN",
    )

    # --------------------------------------------------------
    # Investigation recommendations
    # --------------------------------------------------------

    recommended_steps = [
        "Review related network and security logs.",
        "Check whether the source IP is known and authorized.",
        "Compare the activity with the historical network baseline.",
        "Review authentication logs for related activity.",
        "Review relevant firewall records.",
        "Review endpoint telemetry where authorized.",
        "Determine whether the observed activity is expected.",
    ]

    # --------------------------------------------------------
    # Investigation response
    # --------------------------------------------------------

    investigation = {
        "alert_id": str(alert_id),
        "flow_id": flow_id,
        "timestamp": clean_value(timestamp),
        "source": {
            "ip": clean_value(source_ip),
            "port": clean_value(source_port),
        },
        "destination": {
            "ip": clean_value(destination_ip),
            "port": clean_value(destination_port),
        },
        "protocol": clean_value(protocol),
        "severity": clean_value(severity),
        "status": status,
        "scenario_type": clean_value(
            scenario_type
        ),
        "decision": clean_value(decision),

        "traffic_statistics": {
            key: clean_value(value)
            for key, value
            in traffic_statistics.items()
        },

        "detection": {
            "matched_rule_ids": clean_value(
                matched_rule_ids
            ),
            "matched_rule_names": clean_value(
                matched_rule_names
            ),
            "anomaly_score": clean_value(
                anomaly_score
            ),
            "ml_score": clean_value(
                ml_score
            ),
            "risk_score": clean_value(
                risk_score
            ),
            "anomaly_classification": clean_value(
                anomaly_classification
            ),
            "ml_classification": clean_value(
                ml_classification
            ),
        },

        "reason": clean_value(
            risk_explanation
        ),

        "recommended_investigation": (
            recommended_steps
        ),

        "analyst_notes": first_value(
            alert_record.get("analyst_notes"),
            default="",
        ),

        "investigation_timestamp": first_value(
            alert_record.get(
                "investigation_timestamp"
            ),
        ),

        "resolution_notes": first_value(
            alert_record.get(
                "resolution_notes"
            ),
            default="",
        ),
    }

    return {
        "status": "success",
        "alert": investigation,
    }


# ============================================================
# ALERT STATUS UPDATE
# ============================================================

class AlertStatusUpdate(BaseModel):
    status: str


ALLOWED_ALERT_STATUSES = {
    "NEW",
    "INVESTIGATING",
    "RESOLVED",
    "FALSE_POSITIVE",
}


@app.put("/api/alerts/{alert_id}/status")
def update_alert_status(
    alert_id: str,
    payload: AlertStatusUpdate,
) -> dict[str, Any]:

    requested_status = (
        str(payload.status or "")
        .strip()
        .upper()
    )

    # --------------------------------------------------------
    # Validate status
    # --------------------------------------------------------

    if requested_status not in ALLOWED_ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Invalid alert status.",
                "allowed_statuses": sorted(
                    ALLOWED_ALERT_STATUSES
                ),
            },
        )

    # --------------------------------------------------------
    # Load alerts
    # --------------------------------------------------------

    alerts = load_csv(
        ALERT_FILE
    )

    if "alert_id" not in alerts.columns:
        raise HTTPException(
            status_code=500,
            detail=(
                "alerts.csv is missing "
                "required column: alert_id"
            ),
        )

    # --------------------------------------------------------
    # Locate alert
    # --------------------------------------------------------

    matches = (
        alerts["alert_id"]
        .astype(str)
        == str(alert_id)
    )

    if not matches.any():
        raise HTTPException(
            status_code=404,
            detail=(
                f"Alert '{alert_id}' "
                "not found."
            ),
        )

    # --------------------------------------------------------
    # Ensure workflow columns exist
    # --------------------------------------------------------

    if "status" not in alerts.columns:
        alerts["status"] = "NEW"

    if "investigation_started_at" not in alerts.columns:
        alerts[
            "investigation_started_at"
        ] = ""

    if "resolved_at" not in alerts.columns:
        alerts[
            "resolved_at"
        ] = ""

    if "resolution_notes" not in alerts.columns:
        alerts[
            "resolution_notes"
        ] = ""

    # --------------------------------------------------------
    # Current status
    # --------------------------------------------------------

    row_index = alerts.index[matches][0]

    current_status = str(
        alerts.at[
            row_index,
            "status"
        ]
        if pd.notna(
            alerts.at[
                row_index,
                "status"
            ]
        )
        else "NEW"
    ).strip().upper()

    # --------------------------------------------------------
    # Validate workflow transition
    #
    # NEW
    #   ↓
    # INVESTIGATING
    #   ↓
    # RESOLVED / FALSE_POSITIVE
    # --------------------------------------------------------

    allowed_transitions = {
        "NEW": {
            "NEW",
            "INVESTIGATING",
        },
        "INVESTIGATING": {
            "INVESTIGATING",
            "RESOLVED",
            "FALSE_POSITIVE",
        },
        "RESOLVED": {
            "RESOLVED",
            "INVESTIGATING",
        },
        "FALSE_POSITIVE": {
            "FALSE_POSITIVE",
            "INVESTIGATING",
        },
    }

    if requested_status not in (
        allowed_transitions.get(
            current_status,
            {"NEW"},
        )
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    "Invalid status transition."
                ),
                "current_status": current_status,
                "requested_status": requested_status,
            },
        )

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    now = datetime.now(
        timezone.utc
    ).isoformat()

    # --------------------------------------------------------
    # Apply status
    # --------------------------------------------------------

    alerts.at[
        row_index,
        "status"
    ] = requested_status

    # First investigation timestamp
    if (
        requested_status == "INVESTIGATING"
        and not str(
            alerts.at[
                row_index,
                "investigation_started_at"
            ]
        ).strip()
    ):
        alerts.at[
            row_index,
            "investigation_started_at"
        ] = now

    # Resolution timestamp
    if requested_status in {
        "RESOLVED",
        "FALSE_POSITIVE",
    }:
        alerts.at[
            row_index,
            "resolved_at"
        ] = now

    # If reopened, remove resolution timestamp
    if requested_status == "INVESTIGATING":
        alerts.at[
            row_index,
            "resolved_at"
        ] = ""

    # --------------------------------------------------------
    # Save CSV
    # --------------------------------------------------------

    try:

        alerts.to_csv(
            ALERT_FILE,
            index=False,
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to save alert status: "
                f"{exc}"
            ),
        )

    # --------------------------------------------------------
    # Return updated alert
    # --------------------------------------------------------

    updated_record = (
        alerts.loc[
            row_index
        ].to_dict()
    )

    return {
        "status": "success",
        "message": (
            f"Alert '{alert_id}' "
            f"updated successfully."
        ),
        "previous_status": current_status,
        "new_status": requested_status,
        "updated_at": now,
        "alert": {
            key: clean_value(value)
            for key, value
            in updated_record.items()
        },
    }

# ============================================================

# INCIDENTS

# ============================================================



@app.get("/api/incidents")

def get_incidents(

    limit: int = 20,

) -> dict[str, Any]:



    if limit < 1 or limit > 200:



        raise HTTPException(

            status_code=400,

            detail=(

                "limit must be between "

                "1 and 200."

            ),

        )



    incidents = load_csv(

        INCIDENT_FILE

    )



    incidents = incidents.sort_values(

        "risk_score",

        ascending=False,

    )



    incidents = incidents.head(

        limit

    )



    return {

        "count": len(incidents),

        "incidents": dataframe_records(

            incidents

        ),

    }





# ============================================================

# SINGLE INCIDENT

# ============================================================



@app.get("/api/incidents/{incident_id}")

def get_incident(

    incident_id: str,

) -> dict[str, Any]:



    incidents = load_csv(

        INCIDENT_FILE

    )



    matches = incidents[

        incidents[

            "incident_id"

        ]

        .astype(str)

        == str(incident_id)

    ]



    if matches.empty:



        raise HTTPException(

            status_code=404,

            detail=(

                f"Incident '{incident_id}' "

                "not found."

            ),

        )



    record = matches.iloc[

        0

    ].to_dict()



    return {

        "incident": {

            key: clean_value(value)

            for key, value

            in record.items()

        }

    }





# ============================================================

# RISK DISTRIBUTION

# ============================================================



@app.get("/api/risk/distribution")

def risk_distribution() -> dict[str, Any]:



    hybrid = load_csv(

        HYBRID_FILE

    )



    bins = [

        0,

        25,

        50,

        75,

        90,

        101,

    ]



    labels = [

        "0-24",

        "25-49",

        "50-74",

        "75-89",

        "90-100",

    ]



    categories = pd.cut(

        hybrid[

            "risk_score"

        ],

        bins=bins,

        labels=labels,

        right=False,

    )



    counts = (

        categories

        .value_counts()

        .sort_index()

    )



    return {

        "distribution": [

            {

                "range": str(

                    category

                ),

                "count": int(

                    counts.get(

                        category,

                        0,

                    )

                ),

            }

            for category in labels

        ]

    }





# ============================================================

# TOP SOURCE IPS

# ============================================================



@app.get("/api/network/top-sources")

def top_sources(

    limit: int = 10,

) -> dict[str, Any]:



    if limit < 1 or limit > 100:



        raise HTTPException(

            status_code=400,

            detail=(

                "limit must be between "

                "1 and 100."

            ),

        )



    alerts = load_csv(

        ALERT_FILE

    )



    counts = (

        alerts[

            "source_ip"

        ]

        .astype(str)

        .value_counts()

        .head(limit)

    )



    sources = [

        {

            "source_ip": str(

                ip

            ),

            "alert_count": int(

                count

            ),

        }

        for ip, count

        in counts.items()

    ]



    return {

        "sources": sources

    }





# ============================================================

# SCENARIOS

# ============================================================



@app.get("/api/scenarios")

def scenarios() -> dict[str, Any]:



    hybrid = load_csv(

        HYBRID_FILE

    )



    grouped = (

        hybrid.groupby(

            "scenario_type"

        )

        .agg(

            flows=(

                "flow_id",

                "count",

            ),

            average_risk=(

                "risk_score",

                "mean",

            ),

        )

        .reset_index()

    )



    grouped[

        "average_risk"

    ] = grouped[

        "average_risk"

    ].round(2)



    grouped = grouped.sort_values(

        "flows",

        ascending=False,

    )



    return {

        "scenarios": dataframe_records(

            grouped

        )

    }



# ============================================================

# NETWORK TRAFFIC ANALYTICS

# ============================================================



@app.get("/api/dashboard/traffic")

def dashboard_traffic(

    limit: int = 120,

) -> dict[str, Any]:

    """

    Network traffic analytics for the SOC dashboard.



    Data sources:

        - network_features.csv

        - hybrid_risk_results.csv

        - alerts.csv



    Analytics:

        1. Packets per second

        2. Bytes per second

        3. Connections per minute

        4. Failed connections

        5. Protocol distribution

        6. Port distribution

        7. Alert timeline

        8. Risk timeline

    """



    # --------------------------------------------------------

    # Validate limit

    # --------------------------------------------------------



    if limit < 10 or limit > 500:

        raise HTTPException(

            status_code=400,

            detail="limit must be between 10 and 500.",

        )



    # --------------------------------------------------------

    # Load datasets

    # --------------------------------------------------------



    features = load_csv(

        FEATURES_FILE

    )



    hybrid = load_csv(

        HYBRID_FILE

    )



    alerts = load_csv(

        ALERT_FILE

    )



    # --------------------------------------------------------

    # Validate required feature columns

    # --------------------------------------------------------



    required_feature_columns = {

        "flow_id",

        "timestamp",

        "packet_count",

        "byte_count",

        "duration_seconds",

        "connection_count",

        "failed_connection_count",

        "protocol",

        "destination_port",

    }



    missing_features = (

        required_feature_columns

        - set(features.columns)

    )



    if missing_features:

        raise HTTPException(

            status_code=500,

            detail=(

                "network_features.csv is missing "

                "required columns: "

                f"{sorted(missing_features)}"

            ),

        )



    # --------------------------------------------------------

    # Validate required hybrid columns

    # --------------------------------------------------------



    required_hybrid_columns = {

        "flow_id",

        "risk_score",

    }



    missing_hybrid = (

        required_hybrid_columns

        - set(hybrid.columns)

    )



    if missing_hybrid:

        raise HTTPException(

            status_code=500,

            detail=(

                "hybrid_risk_results.csv is missing "

                "required columns: "

                f"{sorted(missing_hybrid)}"

            ),

        )



    # --------------------------------------------------------

    # Select only required columns

    # --------------------------------------------------------



    traffic = features[

        [

            "flow_id",

            "timestamp",

            "packet_count",

            "byte_count",

            "duration_seconds",

            "connection_count",

            "failed_connection_count",

            "protocol",

            "destination_port",

        ]

    ].copy()



    risk_data = hybrid[

        [

            "flow_id",

            "risk_score",

        ]

    ].copy()



    # --------------------------------------------------------

    # Convert data types

    # --------------------------------------------------------



    traffic["timestamp"] = pd.to_datetime(

        traffic["timestamp"],

        errors="coerce",

        utc=True,

    )



    traffic["packet_count"] = pd.to_numeric(

        traffic["packet_count"],

        errors="coerce",

    )



    traffic["byte_count"] = pd.to_numeric(

        traffic["byte_count"],

        errors="coerce",

    )



    traffic["duration_seconds"] = pd.to_numeric(

        traffic["duration_seconds"],

        errors="coerce",

    )



    traffic["connection_count"] = pd.to_numeric(

        traffic["connection_count"],

        errors="coerce",

    )



    traffic["failed_connection_count"] = pd.to_numeric(

        traffic["failed_connection_count"],

        errors="coerce",

    )



    traffic["destination_port"] = pd.to_numeric(

        traffic["destination_port"],

        errors="coerce",

    )



    risk_data["risk_score"] = pd.to_numeric(

        risk_data["risk_score"],

        errors="coerce",

    )



    # --------------------------------------------------------

    # Clean invalid rows

    # --------------------------------------------------------



    traffic = traffic.dropna(

        subset=[

            "timestamp",

            "packet_count",

            "byte_count",

            "duration_seconds",

            "connection_count",

            "failed_connection_count",

        ]

    )



    risk_data = risk_data.dropna(

        subset=[

            "risk_score"

        ]

    )



    # --------------------------------------------------------

    # Protect against zero duration

    # --------------------------------------------------------



    traffic["safe_duration"] = (

        traffic["duration_seconds"]

        .clip(lower=0.001)

    )



    # --------------------------------------------------------

    # Calculate traffic rates

    # --------------------------------------------------------



    traffic["packets_per_second"] = (

        traffic["packet_count"]

        /

        traffic["safe_duration"]

    )



    traffic["bytes_per_second"] = (

        traffic["byte_count"]

        /

        traffic["safe_duration"]

    )



    # --------------------------------------------------------

    # Normalize protocol

    # --------------------------------------------------------



    traffic["protocol"] = (

        traffic["protocol"]

        .astype(str)

        .str.upper()

        .str.strip()

    )



    # --------------------------------------------------------

    # Join IDS risk results

    #

    # flow_id is the common identifier between

    # network_features.csv and hybrid_risk_results.csv.

    # --------------------------------------------------------



    traffic = traffic.merge(

        risk_data,

        on="flow_id",

        how="left",

    )



    traffic["risk_score"] = (

        traffic["risk_score"]

        .fillna(0)

    )



    # --------------------------------------------------------

    # Sort chronologically

    # --------------------------------------------------------



    traffic = traffic.sort_values(

        "timestamp"

    )



    # ========================================================

    # TIME BUCKETS

    # ========================================================



    traffic["time_bucket"] = (

        traffic["timestamp"]

        .dt.floor("1min")

    )



    timeline = (

        traffic

        .groupby("time_bucket")

        .agg(

            packet_count=(

                "packet_count",

                "sum",

            ),

            byte_count=(

                "byte_count",

                "sum",

            ),

            connection_count=(

                "connection_count",

                "sum",

            ),

            failed_connection_count=(

                "failed_connection_count",

                "sum",

            ),

            average_risk=(

                "risk_score",

                "mean",

            ),

        )

        .reset_index()

    )



    # --------------------------------------------------------

    # Packets per second

    #

    # One minute = 60 seconds.

    # --------------------------------------------------------



    timeline[

        "packets_per_second"

    ] = (

        timeline["packet_count"]

        / 60.0

    ).round(2)



    # --------------------------------------------------------

    # Bytes per second

    # --------------------------------------------------------



    timeline[

        "bytes_per_second"

    ] = (

        timeline["byte_count"]

        / 60.0

    ).round(2)



    # --------------------------------------------------------

    # Connections per minute

    # --------------------------------------------------------



    timeline[

        "connections_per_minute"

    ] = (

        timeline["connection_count"]

        .round(2)

    )



    # --------------------------------------------------------

    # Failed connections

    # --------------------------------------------------------



    timeline[

        "failed_connections"

    ] = (

        timeline[

            "failed_connection_count"

        ]

        .astype(int)

    )



    timeline[

        "average_risk"

    ] = (

        timeline[

            "average_risk"

        ]

        .round(2)

    )



    # --------------------------------------------------------

    # Keep latest buckets

    # --------------------------------------------------------



    timeline = timeline.tail(

        limit

    )



    # --------------------------------------------------------

    # ISO timestamps

    # --------------------------------------------------------



    timeline[

        "timestamp"

    ] = (

        timeline[

            "time_bucket"

        ]

        .dt.strftime(

            "%Y-%m-%dT%H:%M:%SZ"

        )

    )



    # ========================================================

    # TRAFFIC TIMELINE

    # ========================================================



    traffic_timeline = []



    for _, row in timeline.iterrows():



        traffic_timeline.append(

            {

                "timestamp": row[

                    "timestamp"

                ],



                "packets_per_second": float(

                    row[

                        "packets_per_second"

                    ]

                ),



                "bytes_per_second": float(

                    row[

                        "bytes_per_second"

                    ]

                ),



                "connections_per_minute": float(

                    row[

                        "connections_per_minute"

                    ]

                ),



                "failed_connections": int(

                    row[

                        "failed_connections"

                    ]

                ),



                "average_risk": float(

                    row[

                        "average_risk"

                    ]

                ),

            }

        )



    # ========================================================

    # PROTOCOL DISTRIBUTION

    # ========================================================



    protocol_counts = (

        traffic[

            "protocol"

        ]

        .value_counts()

    )



    protocol_distribution = []



    for protocol, count in protocol_counts.items():



        protocol_distribution.append(

            {

                "protocol": str(

                    protocol

                ),



                "count": int(

                    count

                ),

            }

        )



    # ========================================================

    # PORT DISTRIBUTION

    # ========================================================



    port_counts = (

        traffic[

            "destination_port"

        ]

        .dropna()

        .astype(int)

        .value_counts()

        .head(15)

    )



    port_distribution = []



    for port, count in port_counts.items():



        port_distribution.append(

            {

                "port": int(

                    port

                ),



                "count": int(

                    count

                ),

            }

        )



    # ========================================================

    # ALERT TIMELINE

    # ========================================================



    alert_timeline = []



    if not alerts.empty:



        alert_data = alerts.copy()



        # ----------------------------------------------------

        # Determine alert timestamp column

        # ----------------------------------------------------



        if "timestamp" in alert_data.columns:



            alert_data["timestamp"] = (

                pd.to_datetime(

                    alert_data[

                        "timestamp"

                    ],

                    errors="coerce",

                    utc=True,

                )

            )



        elif "created_at" in alert_data.columns:



            alert_data["timestamp"] = (

                pd.to_datetime(

                    alert_data[

                        "created_at"

                    ],

                    errors="coerce",

                    utc=True,

                )

            )



        else:



            alert_data["timestamp"] = pd.NaT



        alert_data = alert_data.dropna(

            subset=[

                "timestamp"

            ]

        )



        if not alert_data.empty:



            alert_data[

                "time_bucket"

            ] = (

                alert_data[

                    "timestamp"

                ]

                .dt.floor("1min")

            )



            alert_grouped = (

                alert_data

                .groupby(

                    "time_bucket"

                )

                .size()

                .reset_index(

                    name="alert_count"

                )

            )



            alert_grouped = (

                alert_grouped

                .tail(limit)

            )



            for _, row in (

                alert_grouped.iterrows()

            ):



                alert_timeline.append(

                    {

                        "timestamp": row[

                            "time_bucket"

                        ].strftime(

                            "%Y-%m-%dT%H:%M:%SZ"

                        ),



                        "alert_count": int(

                            row[

                                "alert_count"

                            ]

                        ),

                    }

                )



    # ========================================================

    # RISK TIMELINE

    # ========================================================



    risk_timeline = []



    for _, row in timeline.iterrows():



        risk_timeline.append(

            {

                "timestamp": row[

                    "timestamp"

                ],



                "risk_score": float(

                    row[

                        "average_risk"

                    ]

                ),

            }

        )



    # ========================================================

    # SUMMARY

    # ========================================================



    total_packets = int(

        traffic[

            "packet_count"

        ].sum()

    )



    total_bytes = int(

        traffic[

            "byte_count"

        ].sum()

    )



    total_connections = int(

        traffic[

            "connection_count"

        ].sum()

    )



    total_failed_connections = int(

        traffic[

            "failed_connection_count"

        ].sum()

    )



    average_packets_per_second = round(

        float(

            traffic[

                "packets_per_second"

            ].mean()

        ),

        2,

    )



    average_bytes_per_second = round(

        float(

            traffic[

                "bytes_per_second"

            ].mean()

        ),

        2,

    )



    average_risk = round(

        float(

            traffic[

                "risk_score"

            ].mean()

        ),

        2,

    )



    # ========================================================

    # FINAL RESPONSE

    # ========================================================



    return {

        "status": "success",



        "summary": {

            "total_flows": int(

                len(traffic)

            ),



            "total_packets": (

                total_packets

            ),



            "total_bytes": (

                total_bytes

            ),



            "total_connections": (

                total_connections

            ),



            "total_failed_connections": (

                total_failed_connections

            ),



            "average_packets_per_second": (

                average_packets_per_second

            ),



            "average_bytes_per_second": (

                average_bytes_per_second

            ),



            "average_risk_score": (

                average_risk

            ),

        },



        "traffic_timeline": (

            traffic_timeline

        ),



        "protocol_distribution": (

            protocol_distribution

        ),



        "port_distribution": (

            port_distribution

        ),



        "alert_timeline": (

            alert_timeline

        ),



        "risk_timeline": (

            risk_timeline

        ),

    }



# ============================================================

# EVALUATION

# ============================================================



@app.get("/api/evaluation")

def evaluation() -> dict[str, Any]:



    metrics = load_metrics()



    return metrics



@app.post("/api/flows")

def receive_live_flow(

    flow: LiveFlow,

) -> dict[str, Any]:



    data = flow.model_dump()



    # --------------------------------------------------------

    # Derived features

    # --------------------------------------------------------



    duration = max(

        float(

            data["duration_seconds"]

        ),

        0.001,

    )



    packet_count = max(

        int(

            data["packet_count"]

        ),

        0,

    )



    byte_count = max(

        int(

            data["byte_count"]

        ),

        0,

    )



    connection_count = max(

        int(

            data["connection_count"]

        ),

        0,

    )



    failed_connections = max(

        int(

            data[

                "failed_connection_count"

            ]

        ),

        0,

    )



    syn_count = max(

        int(

            data["syn_count"]

        ),

        0,

    )



    rst_count = max(

        int(

            data["rst_count"]

        ),

        0,

    )



    bytes_per_second = (

        byte_count / duration

    )



    packets_per_second = (

        packet_count / duration

    )



    failure_ratio = (

        failed_connections /

        max(

            connection_count,

            1,

        )

    )



    syn_ratio = (

        syn_count /

        max(

            packet_count,

            1,

        )

    )



    # --------------------------------------------------------

    # Safe synthetic detection logic

    # --------------------------------------------------------



    matched_rules = []



    if (

        connection_count >= 50

        or packets_per_second >= 100

    ):



        matched_rules.append(

            "HIGH_CONNECTION_RATE"

        )



    if (

        failed_connections >= 20

        or failure_ratio >= 0.40

    ):



        matched_rules.append(

            "REPEATED_FAILED_CONNECTIONS"

        )



    if syn_ratio >= 0.50:



        matched_rules.append(

            "SYN_HEAVY_PATTERN"

        )



    if (

        data["destination_port"]

        not in [

            22,

            25,

            53,

            80,

            443,

            587,

        ]

        and connection_count >= 20

    ):



        matched_rules.append(

            "UNUSUAL_PORT_ACTIVITY"

        )



    if bytes_per_second >= 50000:



        matched_rules.append(

            "HIGH_TRAFFIC_VOLUME"

        )



    # --------------------------------------------------------

    # Anomaly score

    # --------------------------------------------------------



    anomaly_score = 0.0



    anomaly_score += min(

        failure_ratio * 35,

        35,

    )



    anomaly_score += min(

        syn_ratio * 30,

        30,

    )



    anomaly_score += min(

        connection_count / 2,

        20,

    )



    anomaly_score += min(

        packets_per_second / 20,

        15,

    )



    anomaly_score = min(

        round(

            anomaly_score,

            2,

        ),

        100.0,

    )



    # --------------------------------------------------------

    # Rule score

    # --------------------------------------------------------



    rule_score = min(

        len(matched_rules) * 25,

        100,

    )



    # --------------------------------------------------------

    # Combined risk

    # --------------------------------------------------------



    risk_score = round(

        (

            rule_score * 0.60

            +

            anomaly_score * 0.40

        ),

        2,

    )



    # --------------------------------------------------------

    # Classification

    # --------------------------------------------------------



    if risk_score >= 81:



        classification = (

            "CRITICAL INVESTIGATION"

        )



    elif risk_score >= 61:



        classification = (

            "HIGH RISK"

        )



    elif risk_score >= 41:



        classification = (

            "SUSPICIOUS"

        )



    elif risk_score >= 21:



        classification = (

            "LOW RISK"

        )



    else:



        classification = (

            "NORMAL"

        )



    # --------------------------------------------------------

    # Severity

    # --------------------------------------------------------



    if risk_score >= 81:



        severity = "CRITICAL"



    elif risk_score >= 61:



        severity = "HIGH"



    elif risk_score >= 41:



        severity = "MEDIUM"



    elif risk_score >= 21:



        severity = "LOW"



    else:



        severity = "INFO"



    # --------------------------------------------------------

    # Alert

    # --------------------------------------------------------



    alert_generated = (

        risk_score >= 41

    )



    alert_id = None



    if alert_generated:



        alert_id = (

            f"LIVE-ALT-"

            f"{int(time.time() * 1000)}"

        )



    # --------------------------------------------------------

    # Response

    # --------------------------------------------------------



    return {



        "flow_id": data[

            "flow_id"

        ],



        "timestamp": data[

            "timestamp"

        ],



        "classification": (

            classification

        ),



        "severity": severity,



        "risk_score": risk_score,



        "anomaly_score": (

            anomaly_score

        ),



        "rule_score": rule_score,



        "matched_rules": (

            matched_rules

        ),



        "alert_generated": (

            alert_generated

        ),



        "alert_id": alert_id,



        "source_ip": data[

            "source_ip"

        ],



        "destination_ip": data[

            "destination_ip"

        ],



        "scenario_type": data[

            "scenario_type"

        ],

    }