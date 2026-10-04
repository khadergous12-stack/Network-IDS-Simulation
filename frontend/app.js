/**
 * Network IDS — SOC Dashboard
 *
 * Frontend client for the FastAPI backend.
 */

const API_BASE = "http://127.0.0.1:8000";

let riskChart = null;
let severityChart = null;


/* ============================================================
   TRAFFIC CHARTS
   ============================================================ */

const trafficCharts = {
    packetsPerSecond: null,
    bytesPerSecond: null,
    connectionsPerMinute: null,
    failedConnections: null,
    protocolDistribution: null,
    portDistribution: null,
    alertTimeline: null,
    riskTimeline: null,
};


const trafficChartColors = {

    primary: "#38bdf8",

    secondary: "#818cf8",

    warning: "#f97316",

    danger: "#ef4444",

    success: "#22c55e",

    purple: "#a78bfa",

    muted: "#64748b",

    text: "#94a3b8",

    grid: "rgba(148,163,184,0.08)",
};


/* ============================================================
   HELPERS
   ============================================================ */

async function fetchJSON(endpoint) {

    const response = await fetch(
        `${API_BASE}${endpoint}`
    );

    if (!response.ok) {

        throw new Error(
            `API request failed: ${response.status}`
        );

    }

    return response.json();
}


function formatNumber(value) {

    return Number(value || 0).toLocaleString(
        "en-US"
    );
}


function formatRisk(value) {

    return Number(value || 0).toFixed(2);
}


function severityClass(severity) {

    const value = String(
        severity || ""
    ).toLowerCase();

    return `badge badge-${value}`;
}


function escapeHTML(value) {

    return String(
        value ?? ""
    )
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function compactTrafficLabel(value) {

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {

        return String(value || "");

    }

    return date.toLocaleTimeString(
        "en-IN",
        {
            hour: "2-digit",
            minute: "2-digit",
            hour12: false,
        }
    );
}


function formatBytesPerSecond(value) {

    const number = Number(value || 0);

    if (
        number >=
        1024 * 1024 * 1024
    ) {

        return `${(
            number /
            (1024 * 1024 * 1024)
        ).toFixed(2)} GB/s`;

    }

    if (
        number >=
        1024 * 1024
    ) {

        return `${(
            number /
            (1024 * 1024)
        ).toFixed(2)} MB/s`;

    }

    if (number >= 1024) {

        return `${(
            number / 1024
        ).toFixed(2)} KB/s`;

    }

    return `${number.toFixed(2)} B/s`;
}


/* ============================================================
   SYSTEM STATUS
   ============================================================ */

async function loadHealth() {

    try {

        const data =
            await fetchJSON(
                "/api/health"
            );

        const healthy =
            data.status === "healthy";

        const status =
            document.getElementById(
                "systemStatus"
            );

        const dot =
            document.getElementById(
                "statusDot"
            );

        status.textContent =
            healthy
                ? "SYSTEM ONLINE"
                : "SYSTEM DEGRADED";

        dot.style.background =
            healthy
                ? "#22c55e"
                : "#ef4444";

    } catch (error) {

        console.error(error);

        document.getElementById(
            "systemStatus"
        ).textContent =
            "API OFFLINE";

        document.getElementById(
            "statusDot"
        ).style.background =
            "#ef4444";
    }
}


/* ============================================================
   DASHBOARD SUMMARY
   ============================================================ */

async function loadSummary() {

    const data =
        await fetchJSON(
            "/api/dashboard/summary"
        );

    document.getElementById(
        "totalFlows"
    ).textContent =
        formatNumber(
            data.total_flows
        );

    document.getElementById(
        "totalAlerts"
    ).textContent =
        formatNumber(
            data.total_alerts
        );

    document.getElementById(
        "criticalAlerts"
    ).textContent =
        formatNumber(
            data.severity.critical
        );

    document.getElementById(
        "averageRisk"
    ).textContent =
        formatRisk(
            data.average_risk_score
        );

    renderSeverityChart(
        data.severity
    );

    renderList(
        "scenarioList",
        data.scenario_distribution
    );

    renderList(
        "detectionList",
        data.detection_methods
    );
}


/* ============================================================
   RISK CHART
   ============================================================ */

async function loadRiskChart() {

    const data =
        await fetchJSON(
            "/api/risk/distribution"
        );

    const labels =
        data.distribution.map(
            item => item.range
        );

    const values =
        data.distribution.map(
            item => item.count
        );

    const context =
        document.getElementById(
            "riskChart"
        );

    if (riskChart) {

        riskChart.destroy();

    }

    riskChart = new Chart(
        context,
        {

            type: "bar",

            data: {

                labels,

                datasets: [

                    {

                        label:
                            "Flows",

                        data:
                            values,

                        borderRadius: 8,

                        borderWidth: 0,

                    }

                ]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                plugins: {

                    legend: {
                        display: false,
                    }

                },

                scales: {

                    x: {

                        grid: {
                            display: false,
                        },

                        ticks: {
                            color: "#64748b",
                        }

                    },

                    y: {

                        beginAtZero: true,

                        grid: {

                            color:
                                "rgba(148,163,184,0.08)",

                        },

                        ticks: {
                            color: "#64748b",
                        }

                    }

                }

            }

        }
    );
}


/* ============================================================
   SEVERITY CHART
   ============================================================ */

function renderSeverityChart(
    severity
) {

    const context =
        document.getElementById(
            "severityChart"
        );

    if (severityChart) {

        severityChart.destroy();

    }

    severityChart = new Chart(
        context,
        {

            type: "doughnut",

            data: {

                labels: [
                    "Critical",
                    "High",
                    "Medium",
                    "Low",
                ],

                datasets: [

                    {

                        data: [

                            severity.critical,

                            severity.high,

                            severity.medium,

                            severity.low,

                        ],

                        borderWidth: 0,

                    }

                ]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                cutout: "68%",

                plugins: {

                    legend: {

                        position:
                            "bottom",

                        labels: {

                            color:
                                "#94a3b8",

                            padding: 18,

                            usePointStyle: true,

                        }

                    }

                }

            }

        }
    );
}


/* ============================================================
   GENERIC LIST
   ============================================================ */

function renderList(
    elementId,
    data
) {

    const container =
        document.getElementById(
            elementId
        );

    const entries =
        Object.entries(
            data || {}
        ).sort(
            (a, b) =>
                Number(b[1]) -
                Number(a[1])
        );

    if (!entries.length) {

        container.innerHTML =
            `<div class="loading-cell">
                No data available
            </div>`;

        return;
    }

    container.innerHTML =
        entries
            .slice(0, 8)
            .map(
                ([name, value]) => `

                    <div class="list-item">

                        <span
                            class="list-name"
                            title="${escapeHTML(name)}"
                        >
                            ${escapeHTML(name)}
                        </span>

                        <span class="list-value">
                            ${formatNumber(value)}
                        </span>

                    </div>

                `
            )
            .join("");
}


/* ============================================================
   TOP SOURCE IPS
   ============================================================ */

async function loadSources() {

    const data =
        await fetchJSON(
            "/api/network/top-sources?limit=8"
        );

    const container =
        document.getElementById(
            "sourcesList"
        );

    if (!data.sources.length) {

        container.innerHTML =
            `<div class="loading-cell">
                No source data
            </div>`;

        return;
    }

    container.innerHTML =
        data.sources
            .map(
                item => `

                    <div class="list-item">

                        <span
                            class="list-name"
                            title="${escapeHTML(
                                item.source_ip
                            )}"
                        >
                            ${escapeHTML(
                                item.source_ip
                            )}
                        </span>

                        <span class="list-value">
                            ${formatNumber(
                                item.alert_count
                            )}
                        </span>

                    </div>

                `
            )
            .join("");
}


/* ============================================================
   ALERT TABLE
   ============================================================ */

async function loadAlerts() {
    const data =
        await fetchJSON(
            "/api/alerts?limit=15"
        );

    const table =
        document.getElementById(
            "alertTable"
        );

    if (!data.alerts.length) {
        table.innerHTML =
            `<tr>
                <td
                    colspan="6"
                    class="loading-cell"
                >
                    No alerts detected
                </td>
            </tr>`;

        return;
    }

    table.innerHTML =
        data.alerts
            .map(
                alert => `
                    <tr
                        class="alert-row"
                        data-alert-id="${escapeHTML(
                            alert.alert_id
                        )}"
                        tabindex="0"
                        role="button"
                        aria-label="Investigate alert ${escapeHTML(
                            alert.alert_id
                        )}"
                    >
                        <td>
                            <strong class="alert-id-link">
                                ${escapeHTML(
                                    alert.alert_id
                                )}
                            </strong>
                        </td>

                        <td>
                            ${escapeHTML(
                                alert.source_ip
                            )}
                        </td>

                        <td>
                            ${escapeHTML(
                                alert.destination_ip
                            )}
                        </td>

                        <td>
                            <span class="risk-number">
                                ${formatRisk(
                                    alert.risk_score
                                )}
                            </span>
                        </td>

                        <td>
                            <span class="${severityClass(
                                alert.severity
                            )}">
                                ${escapeHTML(
                                    alert.severity
                                )}
                            </span>
                        </td>

                        <td>
                            ${escapeHTML(
                                alert.detection_methods
                            )}
                        </td>
                    </tr>
                `
            )
            .join("");

    /*
     * Attach investigation handlers after
     * the table rows have been rendered.
     */

    document
        .querySelectorAll(".alert-row")
        .forEach(row => {

            row.addEventListener(
                "click",
                () => {
                    const alertId =
                        row.dataset.alertId;

                    openInvestigation(
                        alertId
                    );
                }
            );

            row.addEventListener(
                "keydown",
                event => {

                    if (
                        event.key === "Enter" ||
                        event.key === " "
                    ) {
                        event.preventDefault();

                        const alertId =
                            row.dataset.alertId;

                        openInvestigation(
                            alertId
                        );
                    }
                }
            );
        });
}


/* ============================================================
   EVENT INVESTIGATION
   ============================================================ */

async function openInvestigation(
    alertId
) {

    const modal =
        document.getElementById(
            "investigationModal"
        );

    const content =
        document.getElementById(
            "investigationContent"
        );

    if (!modal || !content) {
        console.error(
            "Investigation modal elements not found."
        );

        return;
    }

    /*
     * Show loading state immediately.
     */

    modal.classList.add(
        "active"
    );

    document.body.classList.add(
        "modal-open"
    );

    content.innerHTML = `
        <div class="investigation-loading">
            <div class="investigation-spinner"></div>

            <p>
                Loading investigation details...
            </p>
        </div>
    `;

    try {

        const data =
            await fetchJSON(
                `/api/alerts/${encodeURIComponent(
                    alertId
                )}`
            );

        if (
            !data ||
            !data.alert
        ) {
            throw new Error(
                "Investigation data is empty."
            );
        }

        renderInvestigation(
            data.alert
        );

    } catch (error) {

        console.error(
            "Investigation error:",
            error
        );

        content.innerHTML = `
            <div class="investigation-error">
                <div class="investigation-error-icon">
                    ⚠
                </div>

                <h3>
                    Unable to load investigation
                </h3>

                <p>
                    ${escapeHTML(
                        error.message
                    )}
                </p>

                <p>
                    Make sure the FastAPI backend
                    is running and the alert exists.
                </p>
            </div>
        `;
    }
}


/* ============================================================
   RENDER INVESTIGATION
   ============================================================ */

function renderInvestigation(
    alert
) {

    const content =
        document.getElementById(
            "investigationContent"
        );

    const traffic =
        alert.traffic_statistics ||
        {};

    const detection =
        alert.detection ||
        {};

    const recommendations =
        Array.isArray(
            alert.recommended_investigation
        )
            ? alert.recommended_investigation
            : [];

    const severity =
        String(
            alert.severity ||
            "INFO"
        ).toUpperCase();

    const status =
        String(
            alert.status ||
            "NEW"
        ).toUpperCase();

    const risk =
        formatRisk(
            detection.risk_score
        );

    const anomaly =
        formatRisk(
            detection.anomaly_score
        );

    const mlScore =
        detection.ml_score === null ||
        detection.ml_score === undefined ||
        detection.ml_score === ""
            ? "N/A"
            : formatRisk(
                detection.ml_score
            );

    const recommendationsHTML =
        recommendations.length
            ? recommendations
                .map(
                    item => `
                        <li>
                            <span class="recommendation-icon">
                                ✓
                            </span>

                            <span>
                                ${escapeHTML(
                                    item
                                )}
                            </span>
                        </li>
                    `
                )
                .join("")
            : `
                <li>
                    No specific recommendations
                    available.
                </li>
            `;

    content.innerHTML = `

        <!-- =================================================
             INVESTIGATION HEADER
        ================================================== -->

        <div class="investigation-header">

            <div>

                <div class="investigation-kicker">
                    SECURITY ALERT INVESTIGATION
                </div>

                <h2>
                    ${escapeHTML(
                        alert.alert_id
                    )}
                </h2>

                <p>
                    Flow:
                    ${escapeHTML(
                        alert.flow_id
                    )}
                </p>

            </div>

            <div class="investigation-header-status">

                <span class="${severityClass(
                    severity
                )}">
                    ${escapeHTML(
                        severity
                    )}
                </span>

                <span class="investigation-status-badge">
                    ${escapeHTML(
                        status
                    )}
                </span>

            </div>

        </div>


        <!-- =================================================
             BASIC INFORMATION
        ================================================== -->

        <section class="investigation-section">

            <div class="investigation-section-title">
                ALERT INFORMATION
            </div>

            <div class="investigation-grid">

                <div class="investigation-field">
                    <span>
                        Timestamp
                    </span>

                    <strong>
                        ${escapeHTML(
                            alert.timestamp
                        )}
                    </strong>
                </div>

                <div class="investigation-field">
                    <span>
                        Scenario
                    </span>

                    <strong>
                        ${escapeHTML(
                            alert.scenario_type
                        )}
                    </strong>
                </div>

                <div class="investigation-field">
                    <span>
                        Protocol
                    </span>

                    <strong>
                        ${escapeHTML(
                            alert.protocol
                        )}
                    </strong>
                </div>

                <div class="investigation-field">
                    <span>
                        Decision
                    </span>

                    <strong>
                        ${escapeHTML(
                            alert.decision
                        )}
                    </strong>
                </div>

            </div>

        </section>


        <!-- =================================================
             SOURCE / DESTINATION
        ================================================== -->

        <section class="investigation-section">

            <div class="investigation-section-title">
                NETWORK CONTEXT
            </div>

            <div class="endpoint-grid">

                <div class="endpoint-card">

                    <span class="endpoint-label">
                        SOURCE
                    </span>

                    <strong>
                        ${escapeHTML(
                            alert.source?.ip
                        )}
                    </strong>

                    <small>
                        Port:
                        ${escapeHTML(
                            alert.source?.port
                        )}
                    </small>

                </div>

                <div class="endpoint-arrow">
                    →
                </div>

                <div class="endpoint-card">

                    <span class="endpoint-label">
                        DESTINATION
                    </span>

                    <strong>
                        ${escapeHTML(
                            alert.destination?.ip
                        )}
                    </strong>

                    <small>
                        Port:
                        ${escapeHTML(
                            alert.destination?.port
                        )}
                    </small>

                </div>

            </div>

        </section>


        <!-- =================================================
             TRAFFIC STATISTICS
        ================================================== -->

        <section class="investigation-section">

            <div class="investigation-section-title">
                TRAFFIC STATISTICS
            </div>

            <div class="investigation-stats-grid">

                <div class="investigation-stat">
                    <span>
                        PACKETS
                    </span>

                    <strong>
                        ${formatNumber(
                            traffic.packet_count
                        )}
                    </strong>
                </div>

                <div class="investigation-stat">
                    <span>
                        BYTES
                    </span>

                    <strong>
                        ${formatNumber(
                            traffic.byte_count
                        )}
                    </strong>
                </div>

                <div class="investigation-stat">
                    <span>
                        DURATION
                    </span>

                    <strong>
                        ${escapeHTML(
                            traffic.duration_seconds
                        )} s
                    </strong>
                </div>

                <div class="investigation-stat">
                    <span>
                        CONNECTIONS
                    </span>

                    <strong>
                        ${formatNumber(
                            traffic.connection_count
                        )}
                    </strong>
                </div>

                <div class="investigation-stat">
                    <span>
                        FAILED CONNECTIONS
                    </span>

                    <strong>
                        ${formatNumber(
                            traffic.failed_connection_count
                        )}
                    </strong>
                </div>

                <div class="investigation-stat">
                    <span>
                        SYN COUNT
                    </span>

                    <strong>
                        ${formatNumber(
                            traffic.syn_count
                        )}
                    </strong>
                </div>

                <div class="investigation-stat">
                    <span>
                        RST COUNT
                    </span>

                    <strong>
                        ${formatNumber(
                            traffic.rst_count
                        )}
                    </strong>
                </div>

                <div class="investigation-stat">
                    <span>
                        AVG PACKET SIZE
                    </span>

                    <strong>
                        ${escapeHTML(
                            traffic.average_packet_size
                        )}
                    </strong>
                </div>

            </div>

        </section>


        <!-- =================================================
             DETECTION
        ================================================== -->

        <section class="investigation-section">

            <div class="investigation-section-title">
                DETECTION ANALYSIS
            </div>

            <div class="detection-score-grid">

                <div class="detection-score">
                    <span>
                        FINAL RISK
                    </span>

                    <strong>
                        ${risk}
                    </strong>
                </div>

                <div class="detection-score">
                    <span>
                        ANOMALY SCORE
                    </span>

                    <strong>
                        ${anomaly}
                    </strong>
                </div>

                <div class="detection-score">
                    <span>
                        ML SCORE
                    </span>

                    <strong>
                        ${mlScore}
                    </strong>
                </div>

            </div>

            <div class="detection-details">

                <div class="detail-row">

                    <span>
                        Matched Rule IDs
                    </span>

                    <strong>
                        ${escapeHTML(
                            detection.matched_rule_ids
                        )}
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        Matched Rules
                    </span>

                    <strong>
                        ${escapeHTML(
                            detection.matched_rule_names
                        )}
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        Anomaly Classification
                    </span>

                    <strong>
                        ${escapeHTML(
                            detection.anomaly_classification
                        )}
                    </strong>

                </div>

                <div class="detail-row">

                    <span>
                        ML Classification
                    </span>

                    <strong>
                        ${escapeHTML(
                            detection.ml_classification
                        )}
                    </strong>

                </div>

            </div>

        </section>


        <!-- =================================================
             REASON
        ================================================== -->

        <section class="investigation-section">

            <div class="investigation-section-title">
                INVESTIGATION REASON
            </div>

            <div class="investigation-reason">

                ${escapeHTML(
                    alert.reason
                )}

            </div>

        </section>


        <!-- =================================================
             RECOMMENDATIONS
        ================================================== -->

        <section class="investigation-section">

            <div class="investigation-section-title">
                RECOMMENDED INVESTIGATION
            </div>

            <ul class="recommendation-list">

                ${recommendationsHTML}

            </ul>

        </section>


        <!-- =================================================
     ANALYST STATUS WORKFLOW
================================================== -->

<section class="investigation-section">

    <div class="investigation-section-title">
        ANALYST STATUS
    </div>

    <div class="status-workflow">

        <div class="status-workflow-track">

            <div
                class="status-step"
                data-status-step="NEW"
            >
                <span class="status-step-number">
                    1
                </span>

                <span>
                    NEW
                </span>
            </div>

            <div class="status-workflow-line"></div>

            <div
                class="status-step"
                data-status-step="INVESTIGATING"
            >
                <span class="status-step-number">
                    2
                </span>

                <span>
                    INVESTIGATING
                </span>
            </div>

            <div class="status-workflow-line"></div>

            <div
                class="status-step"
                data-status-step="RESOLVED"
            >
                <span class="status-step-number">
                    3
                </span>

                <span>
                    RESOLVED
                </span>
            </div>

        </div>

    </div>


    <div class="status-control-row">

        <div class="investigation-field">

            <span>
                Current Status
            </span>

            <strong
                id="currentAlertStatus"
            >
                ${escapeHTML(
                    status
                )}
            </strong>

        </div>


        <div class="investigation-field">

            <label
                for="alertStatusSelect"
                class="status-select-label"
            >
                Change Status
            </label>

            <select
                id="alertStatusSelect"
                class="investigation-status-select"
            >

                <option
                    value="NEW"
                    ${
                        status === "NEW"
                            ? "selected"
                            : ""
                    }
                >
                    NEW
                </option>

                <option
                    value="INVESTIGATING"
                    ${
                        status === "INVESTIGATING"
                            ? "selected"
                            : ""
                    }
                >
                    INVESTIGATING
                </option>

                <option
                    value="RESOLVED"
                    ${
                        status === "RESOLVED"
                            ? "selected"
                            : ""
                    }
                >
                    RESOLVED
                </option>

                <option
                    value="FALSE_POSITIVE"
                    ${
                        status === "FALSE_POSITIVE"
                            ? "selected"
                            : ""
                    }
                >
                    FALSE POSITIVE
                </option>

            </select>

        </div>


        <button
            type="button"
            id="updateAlertStatusButton"
            class="update-status-button"
            onclick="updateAlertStatus('${escapeHTML(
                alert.alert_id
            )}')"
        >
            Update Status
        </button>

    </div>


    <div
        id="statusUpdateMessage"
        class="status-update-message"
    ></div>


    <div class="analyst-info-grid">

        <div class="investigation-field">

            <span>
                Investigation Started
            </span>

            <strong>
                ${escapeHTML(
                    alert.investigation_started_at ||
                    "Not started"
                )}
            </strong>

        </div>

        <div class="investigation-field">

            <span>
                Resolved At
            </span>

            <strong>
                ${escapeHTML(
                    alert.resolved_at ||
                    "Not resolved"
                )}
            </strong>

        </div>

    </div>

</section>
        <!-- =================================================
             NOTES PREVIEW
        ================================================== -->

        <section class="investigation-section">

            <div class="investigation-section-title">
                ANALYST NOTES
            </div>

            <div class="existing-notes">

                ${
                    alert.analyst_notes
                        ? escapeHTML(
                            alert.analyst_notes
                        )
                        : "No analyst notes have been added yet."
                }

            </div>

        </section>

    `;

    updateStatusWorkflow(
        status
    );
}


/* ============================================================
   STATUS WORKFLOW VISUAL STATE
   ============================================================ */

function updateStatusWorkflow(
    status
) {

    const normalized =
        String(
            status || "NEW"
        ).toUpperCase();

    const order = [
        "NEW",
        "INVESTIGATING",
        "RESOLVED",
    ];

    const currentIndex =
        order.indexOf(
            normalized
        );

    document
        .querySelectorAll(
            ".status-step"
        )
        .forEach(step => {

            const stepStatus =
                step.dataset.statusStep;

            const stepIndex =
                order.indexOf(
                    stepStatus
                );

            step.classList.remove(
                "active",
                "completed"
            );

            if (
                normalized ===
                "FALSE_POSITIVE"
            ) {

                if (
                    stepStatus === "NEW"
                ) {
                    step.classList.add(
                        "completed"
                    );
                }

                if (
                    stepStatus ===
                    "INVESTIGATING"
                ) {
                    step.classList.add(
                        "completed"
                    );
                }

                return;
            }

            if (
                stepStatus === normalized
            ) {
                step.classList.add(
                    "active"
                );

            } else if (
                stepIndex >= 0 &&
                stepIndex <
                    currentIndex
            ) {
                step.classList.add(
                    "completed"
                );
            }
        });
}


/* ============================================================
   UPDATE ALERT STATUS
   ============================================================ */

async function updateAlertStatus(
    alertId
) {

    const select =
        document.getElementById(
            "alertStatusSelect"
        );

    const button =
        document.getElementById(
            "updateAlertStatusButton"
        );

    const message =
        document.getElementById(
            "statusUpdateMessage"
        );

    if (
        !select ||
        !button ||
        !message
    ) {
        return;
    }

    const newStatus =
        select.value;

    const originalText =
        button.textContent;

    button.disabled = true;

    button.textContent =
        "Updating...";

    message.className =
        "status-update-message";

    message.textContent =
        "Saving status...";

    try {

        const response =
            await fetch(
                `${API_BASE}/api/alerts/${encodeURIComponent(
                    alertId
                )}/status`,
                {
                    method: "PUT",

                    headers: {
                        "Content-Type":
                            "application/json",
                    },

                    body: JSON.stringify({
                        status:
                            newStatus,
                    }),
                }
            );

        const data =
            await response.json();

        if (!response.ok) {

            const detail =
                data.detail;

            if (
                typeof detail ===
                "object"
            ) {
                throw new Error(
                    detail.message ||
                    "Unable to update status."
                );
            }

            throw new Error(
                detail ||
                "Unable to update status."
            );
        }

        message.className =
            "status-update-message success";

        message.textContent =
            `Status updated to ${newStatus}.`;

        /*
         * Reload investigation so all
         * timestamps and status fields
         * are synchronized with backend.
         */

        await refreshInvestigation(
            alertId
        );

        /*
         * Refresh dashboard tables
         * after successful update.
         */

        await loadDashboard();

    } catch (error) {

        console.error(
            "Status update failed:",
            error
        );

        message.className =
            "status-update-message error";

        message.textContent =
            error.message;

    } finally {

        button.disabled = false;

        button.textContent =
            originalText;
    }
}

/* ============================================================
   REFRESH INVESTIGATION
   ============================================================ */

async function refreshInvestigation(
    alertId
) {

    try {

        const data =
            await fetchJSON(
                `/api/alerts/${encodeURIComponent(
                    alertId
                )}`
            );

        if (
            !data ||
            !data.alert
        ) {
            throw new Error(
                "Unable to refresh alert."
            );
        }

        renderInvestigation(
            data.alert
        );

    } catch (error) {

        console.error(
            "Investigation refresh failed:",
            error
        );
    }
}

/* ============================================================
   CLOSE INVESTIGATION
   ============================================================ */

function closeInvestigation() {

    const modal =
        document.getElementById(
            "investigationModal"
        );

    if (!modal) {
        return;
    }

    modal.classList.remove(
        "active"
    );

    document.body.classList.remove(
        "modal-open"
    );
}


/* ============================================================
   INVESTIGATION MODAL EVENTS
   ============================================================ */

document.addEventListener(
    "click",
    event => {

        if (
            event.target.matches(
                "[data-close-investigation]"
            )
        ) {
            closeInvestigation();
        }

        if (
            event.target.classList.contains(
                "investigation-modal"
            )
        ) {
            closeInvestigation();
        }
    }
);


document.addEventListener(
    "keydown",
    event => {

        if (
            event.key === "Escape"
        ) {
            closeInvestigation();
        }
    }
);

/* ============================================================
   INCIDENT TABLE
   ============================================================ */

async function loadIncidents() {

    const data =
        await fetchJSON(
            "/api/incidents?limit=15"
        );

    const table =
        document.getElementById(
            "incidentTable"
        );

    if (!data.incidents.length) {

        table.innerHTML =
            `<tr>

                <td
                    colspan="6"
                    class="loading-cell"
                >
                    No incidents
                </td>

            </tr>`;

        return;
    }

    table.innerHTML =
        data.incidents
            .map(
                incident => {

                    const priority =
                        String(
                            incident.priority ||
                            ""
                        ).toLowerCase();

                    const status =
                        String(
                            incident.status ||
                            ""
                        ).toLowerCase();

                    return `

                        <tr>

                            <td>

                                <strong>

                                    ${escapeHTML(
                                        incident.incident_id
                                    )}

                                </strong>

                            </td>

                            <td>
                                ${escapeHTML(
                                    incident.alert_id
                                )}
                            </td>

                            <td>
                                ${escapeHTML(
                                    incident.scenario_type
                                )}
                            </td>

                            <td>

                                <span class="risk-number">

                                    ${formatRisk(
                                        incident.risk_score
                                    )}

                                </span>

                            </td>

                            <td>

                                <span
                                    class="badge badge-${priority}"
                                >

                                    ${escapeHTML(
                                        incident.priority
                                    )}

                                </span>

                            </td>

                            <td>

                                <span
                                    class="badge ${
                                        status === "open"
                                            ? "badge-open"
                                            : "badge-low"
                                    }"
                                >

                                    ${escapeHTML(
                                        incident.status
                                    )}

                                </span>

                            </td>

                        </tr>

                    `;

                }
            )
            .join("");
}


/* ============================================================
   TRAFFIC ANALYTICS
   ============================================================ */

function destroyTrafficCharts() {

    Object.keys(
        trafficCharts
    ).forEach(
        key => {

            if (
                trafficCharts[key]
            ) {

                trafficCharts[key].destroy();

                trafficCharts[key] = null;

            }

        }
    );
}


function baseTrafficOptions({
    beginAtZero = true,
    legendDisplay = false,
} = {}) {

    return {

        responsive: true,

        maintainAspectRatio: false,

        interaction: {

            intersect: false,

            mode: "index",

        },

        animation: {

            duration: 500,

        },

        plugins: {

            legend: {

                display:
                    legendDisplay,

                labels: {

                    color:
                        trafficChartColors.text,

                    usePointStyle: true,

                    padding: 16,

                },

            },

            tooltip: {

                backgroundColor:
                    "rgba(2, 6, 23, 0.94)",

                borderColor:
                    "rgba(56, 189, 248, 0.20)",

                borderWidth: 1,

                titleColor:
                    "#f8fafc",

                bodyColor:
                    "#cbd5e1",

                padding: 12,

            },

        },

        scales: {

            x: {

                grid: {

                    color:
                        trafficChartColors.grid,

                    drawBorder: false,

                },

                ticks: {

                    color:
                        trafficChartColors.muted,

                    maxTicksLimit: 7,

                    maxRotation: 0,

                },

            },

            y: {

                beginAtZero,

                grid: {

                    color:
                        trafficChartColors.grid,

                    drawBorder: false,

                },

                ticks: {

                    color:
                        trafficChartColors.muted,

                },

            },

        },

    };
}


function createTrafficLineChart(
    canvasId,
    labels,
    values,
    label,
    borderColor,
    fillColor
) {

    const canvas =
        document.getElementById(
            canvasId
        );

    if (!canvas) {

        return null;

    }

    return new Chart(
        canvas,
        {

            type: "line",

            data: {

                labels,

                datasets: [

                    {

                        label,

                        data: values,

                        borderColor,

                        backgroundColor:
                            fillColor,

                        borderWidth: 2,

                        pointRadius: 2,

                        pointHoverRadius: 5,

                        pointBackgroundColor:
                            borderColor,

                        pointBorderWidth: 0,

                        fill: true,

                        tension: 0.35,

                    }

                ]

            },

            options:
                baseTrafficOptions(),

        }
    );
}


function renderTrafficSummary(
    summary
) {

    const packets =
        document.getElementById(
            "trafficPacketsPerSecond"
        );

    const bytes =
        document.getElementById(
            "trafficBytesPerSecond"
        );

    const connections =
        document.getElementById(
            "trafficConnectionsPerMinute"
        );

    const failed =
        document.getElementById(
            "trafficFailedConnections"
        );


    if (packets) {

        packets.textContent =
            formatNumber(
                Number(
                    summary.average_packets_per_second ||
                    0
                ).toFixed(2)
            );

    }


    if (bytes) {

        bytes.textContent =
            formatBytesPerSecond(
                Number(
                    summary.average_bytes_per_second ||
                    0
                )
            );

    }


    if (connections) {

        connections.textContent =
            formatNumber(
                Number(
                    summary.total_connections ||
                    0
                )
            );

    }


    if (failed) {

        failed.textContent =
            formatNumber(
                Number(
                    summary.total_failed_connections ||
                    0
                )
            );

    }
}


function renderTrafficTimeline(
    data
) {

    const timeline =
        data.traffic_timeline ||
        [];

    const labels =
        timeline.map(
            item =>
                compactTrafficLabel(
                    item.timestamp
                )
        );


    trafficCharts.packetsPerSecond =
        createTrafficLineChart(

            "packetsPerSecondChart",

            labels,

            timeline.map(
                item =>
                    Number(
                        item.packets_per_second ||
                        0
                    )
            ),

            "Packets/sec",

            trafficChartColors.primary,

            "rgba(56,189,248,0.10)"
        );


    trafficCharts.bytesPerSecond =
        createTrafficLineChart(

            "bytesPerSecondChart",

            labels,

            timeline.map(
                item =>
                    Number(
                        item.bytes_per_second ||
                        0
                    )
            ),

            "Bytes/sec",

            trafficChartColors.secondary,

            "rgba(129,140,248,0.10)"
        );


    trafficCharts.connectionsPerMinute =
        createTrafficLineChart(

            "connectionsPerMinuteChart",

            labels,

            timeline.map(
                item =>
                    Number(
                        item.connections_per_minute ||
                        0
                    )
            ),

            "Connections/min",

            trafficChartColors.success,

            "rgba(34,197,94,0.08)"
        );


    const failedCanvas =
        document.getElementById(
            "failedConnectionsChart"
        );


    if (failedCanvas) {

        trafficCharts.failedConnections =
            new Chart(
                failedCanvas,
                {

                    type: "bar",

                    data: {

                        labels,

                        datasets: [

                            {

                                label:
                                    "Failed Connections",

                                data:
                                    timeline.map(
                                        item =>
                                            Number(
                                                item.failed_connections ||
                                                0
                                            )
                                    ),

                                backgroundColor:
                                    "rgba(239,68,68,0.58)",

                                borderColor:
                                    trafficChartColors.danger,

                                borderWidth: 1,

                                borderRadius: 5,

                                maxBarThickness: 22,

                            }

                        ]

                    },

                    options:
                        baseTrafficOptions(),

                }
            );

    }
}


function renderProtocolDistribution(
    data
) {

    const canvas =
        document.getElementById(
            "protocolDistributionChart"
        );

    if (!canvas) {
        return;
    }


    const distribution =
        data.protocol_distribution ||
        [];


    trafficCharts.protocolDistribution =
        new Chart(
            canvas,
            {

                type: "doughnut",

                data: {

                    labels:
                        distribution.map(
                            item =>
                                item.protocol
                        ),

                    datasets: [

                        {

                            data:
                                distribution.map(
                                    item =>
                                        Number(
                                            item.count ||
                                            0
                                        )
                                ),

                            backgroundColor: [

                                "#38bdf8",
                                "#818cf8",
                                "#22c55e",
                                "#f97316",
                                "#a78bfa",
                                "#eab308",
                                "#ef4444",

                            ],

                            borderColor:
                                "#0b1220",

                            borderWidth: 3,

                            hoverOffset: 8,

                        }

                    ]

                },

                options: {

                    responsive: true,

                    maintainAspectRatio:
                        false,

                    cutout: "66%",

                    plugins: {

                        legend: {

                            position:
                                "bottom",

                            labels: {

                                color:
                                    trafficChartColors.text,

                                usePointStyle:
                                    true,

                                padding: 14,

                            }

                        }

                    }

                }

            }
        );
}


function renderPortDistribution(
    data
) {

    const canvas =
        document.getElementById(
            "portDistributionChart"
        );

    if (!canvas) {
        return;
    }


    const distribution =
        data.port_distribution ||
        [];


    trafficCharts.portDistribution =
        new Chart(
            canvas,
            {

                type: "bar",

                data: {

                    labels:
                        distribution.map(
                            item =>
                                String(
                                    item.port
                                )
                        ),

                    datasets: [

                        {

                            label:
                                "Flows",

                            data:
                                distribution.map(
                                    item =>
                                        Number(
                                            item.count ||
                                            0
                                        )
                                ),

                            backgroundColor:
                                "rgba(167,139,250,0.58)",

                            borderColor:
                                trafficChartColors.purple,

                            borderWidth: 1,

                            borderRadius: 5,

                            maxBarThickness: 28,

                        }

                    ]

                },

                options:
                    baseTrafficOptions(),

            }
        );
}


function renderAlertTimeline(
    data
) {

    const canvas =
        document.getElementById(
            "alertTimelineChart"
        );

    if (!canvas) {
        return;
    }


    const timeline =
        data.alert_timeline ||
        [];


    trafficCharts.alertTimeline =
        new Chart(
            canvas,
            {

                type: "line",

                data: {

                    labels:
                        timeline.map(
                            item =>
                                compactTrafficLabel(
                                    item.timestamp
                                )
                        ),

                    datasets: [

                        {

                            label:
                                "Alerts",

                            data:
                                timeline.map(
                                    item =>
                                        Number(
                                            item.alert_count ||
                                            0
                                        )
                                ),

                            borderColor:
                                trafficChartColors.warning,

                            backgroundColor:
                                "rgba(249,115,22,0.10)",

                            borderWidth: 2,

                            pointRadius: 2,

                            pointHoverRadius: 5,

                            pointBackgroundColor:
                                trafficChartColors.warning,

                            fill: true,

                            tension: 0.35,

                        }

                    ]

                },

                options:
                    baseTrafficOptions(),

            }
        );
}


function renderRiskTimeline(
    data
) {

    const canvas =
        document.getElementById(
            "riskTimelineChart"
        );

    if (!canvas) {
        return;
    }


    const timeline =
        data.risk_timeline ||
        [];


    trafficCharts.riskTimeline =
        new Chart(
            canvas,
            {

                type: "line",

                data: {

                    labels:
                        timeline.map(
                            item =>
                                compactTrafficLabel(
                                    item.timestamp
                                )
                        ),

                    datasets: [

                        {

                            label:
                                "Average Risk",

                            data:
                                timeline.map(
                                    item =>
                                        Number(
                                            item.risk_score ||
                                            0
                                        )
                                ),

                            borderColor:
                                trafficChartColors.danger,

                            backgroundColor:
                                "rgba(239,68,68,0.08)",

                            borderWidth: 2,

                            pointRadius: 2,

                            pointHoverRadius: 5,

                            pointBackgroundColor:
                                trafficChartColors.danger,

                            fill: true,

                            tension: 0.35,

                        }

                    ]

                },

                options: {

                    ...baseTrafficOptions(),

                    scales: {

                        ...baseTrafficOptions()
                            .scales,

                        y: {

                            ...baseTrafficOptions()
                                .scales.y,

                            min: 0,

                            max: 100,

                        }

                    }

                }

            }
        );
}


async function loadTrafficAnalytics() {

    try {

        const data =
            await fetchJSON(
                "/api/dashboard/traffic?limit=120"
            );


        destroyTrafficCharts();


        renderTrafficSummary(
            data.summary || {}
        );


        renderTrafficTimeline(
            data
        );


        renderProtocolDistribution(
            data
        );


        renderPortDistribution(
            data
        );


        renderAlertTimeline(
            data
        );


        renderRiskTimeline(
            data
        );

    } catch (error) {

        console.error(
            "Traffic analytics loading failed:",
            error
        );

    }
}


/* ============================================================
   LOAD EVERYTHING
   ============================================================ */

async function loadDashboard() {

    try {

        await loadHealth();

        await Promise.all([

            loadSummary(),

            loadRiskChart(),

            loadSources(),

            loadAlerts(),

            loadIncidents(),

            loadTrafficAnalytics(),

        ]);

    } catch (error) {

        console.error(
            "Dashboard loading failed:",
            error
        );

    }
}


/* ============================================================
   REFRESH
   ============================================================ */

document
    .getElementById(
        "refreshButton"
    )
    .addEventListener(
        "click",
        loadDashboard
    );


/* ============================================================
   INITIAL LOAD
   ============================================================ */

loadDashboard();


/* ============================================================
   AUTO REFRESH
   ============================================================ */

setInterval(
    loadDashboard,
    30000
);