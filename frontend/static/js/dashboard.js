/**
 * NexIDS Dashboard Frontend Logic
 * Polling, real-time telemetry updates, controls, and alert detail modal.
 */

// State
let isRunning = false;
let pollingTimer = null;
const POLL_INTERVAL_MS = 3000;

// On load
document.addEventListener("DOMContentLoaded", () => {
    manualRefresh();
    startPolling();

    // Close modal on Escape key
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            closeModal();
        }
    });
});

function startPolling() {
    if (pollingTimer) clearInterval(pollingTimer);
    pollingTimer = setInterval(pollUpdates, POLL_INTERVAL_MS);
}

async function pollUpdates() {
    try {
        await Promise.all([
            fetchStatus(),
            fetchStats(),
            fetchPriorityAlerts()
        ]);
    } catch (err) {
        console.debug("Background poll sync issue:", err);
    }
}

async function manualRefresh() {
    showNotification("Refreshing telemetry...", "info", 1500);
    await pollUpdates();
}

// -----------------------------------------------------------------------------
// API Calls: Status & Stats
// -----------------------------------------------------------------------------

async function fetchStatus() {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();

    isRunning = Boolean(data.is_running);
    const dot = document.getElementById("status-dot");
    const statusText = document.getElementById("status-text");
    const demoBadge = document.getElementById("demo-indicator");
    const btnStart = document.getElementById("btn-start");
    const btnStop = document.getElementById("btn-stop");

    if (isRunning) {
        dot.className = "dot dot-active";
        statusText.textContent = "ACTIVE";
        btnStart.disabled = true;
        btnStop.disabled = false;
    } else {
        dot.className = "dot dot-stopped";
        statusText.textContent = "STOPPED";
        btnStart.disabled = false;
        btnStop.disabled = true;
    }

    if (data.is_demo_mode) {
        demoBadge.classList.remove("hidden");
    } else {
        demoBadge.classList.add("hidden");
    }
}

async function fetchStats() {
    const res = await fetch("/api/stats");
    if (!res.ok) return;
    const stats = await res.json();

    document.getElementById("val-packets").textContent = (stats.packets_inspected || 0).toLocaleString();
    document.getElementById("val-elapsed").textContent = `Elapsed: ${stats.elapsed_seconds || 0}s`;
    document.getElementById("val-total-alerts").textContent = stats.total_alerts || 0;
    document.getElementById("val-prioritized-count").textContent = `${stats.total_prioritized_alerts || 0} Prioritized`;

    const sevs = stats.severity_counts || {};
    document.getElementById("val-crit-count").textContent = sevs.CRITICAL || 0;
    document.getElementById("val-high-count").textContent = sevs.HIGH || 0;
    document.getElementById("val-med-count").textContent = sevs.MEDIUM || 0;
    document.getElementById("val-low-count").textContent = (sevs.LOW || 0) + (sevs.INFO || 0);
}

// -----------------------------------------------------------------------------
// API Calls: Priority Alerts Table
// -----------------------------------------------------------------------------

async function fetchPriorityAlerts() {
    const res = await fetch("/api/alerts/priority");
    if (!res.ok) return;
    const data = await res.json();
    renderAlertsTable(data.prioritized_alerts || []);
}

function renderAlertsTable(alerts) {
    const tbody = document.getElementById("alerts-tbody");
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="10">
                    <div class="empty-state">
                        <div class="empty-icon">&#128737;</div>
                        <div class="empty-title">No alerts detected</div>
                        <div class="empty-subtitle">Traffic monitoring is passive. Start monitoring or click 'Load Demo Data' to view sample prioritized alerts.</div>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    const rowsHtml = alerts.map((a, idx) => {
        const rank = a.rank || `#${idx + 1}`;
        const pLevel = escapeHtml(a.priority_level || a.priority || "P4_LOW");
        const pBadgeClass = `badge-pri-${pLevel.toLowerCase()}`;
        const pScore = a.priority_score ? Number(a.priority_score).toFixed(1) : "0.0";
        const sev = escapeHtml(a.severity || "MEDIUM");
        const sevBadgeClass = `badge-sev-${sev.toLowerCase()}`;
        const dType = escapeHtml(a.detection_type || "Unknown Alert");
        const conf = a.confidence_pct || (a.confidence ? `${Math.round(a.confidence * 100)}%` : "N/A");
        const src = escapeHtml(a.source || "—");
        const dst = escapeHtml(a.destination || "—");
        const occ = a.occurrence_count || a.event_count || 1;
        const firstSeen = escapeHtml(a.first_seen_formatted || "—");
        const lastSeen = escapeHtml(a.last_seen_formatted || "—");
        const alertId = escapeHtml(a.alert_id || "");

        return `
            <tr class="alert-row" onclick="openAlertDetail('${alertId}')" title="Click to view full incident details">
                <td><span class="rank-pill">${rank}</span></td>
                <td><span class="badge ${pBadgeClass}">${pLevel} (${pScore})</span></td>
                <td><strong>${dType}</strong></td>
                <td><span class="badge ${sevBadgeClass}">${sev}</span></td>
                <td>${conf}</td>
                <td class="mono">${src}</td>
                <td class="mono">${dst}</td>
                <td class="mono">${occ}</td>
                <td class="text-muted">${firstSeen}</td>
                <td class="text-muted">${lastSeen}</td>
            </tr>
        `;
    }).join("");

    tbody.innerHTML = rowsHtml;
}

// -----------------------------------------------------------------------------
// Monitoring Controls
// -----------------------------------------------------------------------------

async function startMonitoring() {
    try {
        const res = await fetch("/api/monitor/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({})
        });
        const data = await res.json();
        if (data.success) {
            showNotification(data.message || "Monitoring started successfully.", "success");
        } else {
            showNotification(data.message || "Could not start live capture. Try Demo Mode.", "warning");
        }
        await pollUpdates();
    } catch (err) {
        showNotification("Failed to communicate with monitoring engine.", "error");
    }
}

async function stopMonitoring() {
    try {
        const res = await fetch("/api/monitor/stop", {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await res.json();
        showNotification(data.message || "Monitoring stopped.", "info");
        await pollUpdates();
    } catch (err) {
        showNotification("Failed to stop monitoring.", "error");
    }
}

async function generateDemoData() {
    try {
        showNotification("Generating synthetic network traffic and detections...", "info");
        const res = await fetch("/api/demo/generate", {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await res.json();
        showNotification(data.message || "Demo data loaded.", "success");
        await pollUpdates();
    } catch (err) {
        showNotification("Failed to generate demo data.", "error");
    }
}

// -----------------------------------------------------------------------------
// Report Generation
// -----------------------------------------------------------------------------

async function generateReport(format) {
    try {
        const endpoint = format === "html" ? "/api/report/html" : "/api/report/json";
        showNotification(`Generating ${format.toUpperCase()} report...`, "info");

        const res = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await res.json();

        if (data.success && data.download_url) {
            showNotification(
                `Report generated: <strong>${escapeHtml(data.filename)}</strong> &nbsp;<a href="${data.download_url}" target="_blank" style="color: #38bdf8; text-decoration: underline;">[ Download File ]</a>`,
                "success",
                8000
            );
        } else {
            showNotification("Failed to generate report file.", "error");
        }
    } catch (err) {
        showNotification("Error requesting report generation.", "error");
    }
}

// -----------------------------------------------------------------------------
// Alert Details Modal
// -----------------------------------------------------------------------------

async function openAlertDetail(alertId) {
    if (!alertId) return;

    try {
        const res = await fetch(`/api/alerts/${encodeURIComponent(alertId)}`);
        if (!res.ok) {
            showNotification(`Could not fetch details for alert ${alertId}.`, "error");
            return;
        }

        const data = await res.json();
        const alert = data.alert;
        if (!alert) return;

        // Populate modal fields
        document.getElementById("modal-rank").textContent = alert.rank || "—";
        document.getElementById("modal-title").textContent = alert.detection_type || "Security Alert";

        const pLevel = alert.priority_level || alert.priority || "P4_LOW";
        const priBadge = document.getElementById("modal-priority-badge");
        priBadge.textContent = `${pLevel} (${alert.priority_score ? Number(alert.priority_score).toFixed(1) : 0} pts)`;
        priBadge.className = `badge badge-pri-${pLevel.toLowerCase()}`;

        const sev = alert.severity || "MEDIUM";
        const sevBadge = document.getElementById("modal-severity-badge");
        sevBadge.textContent = sev;
        sevBadge.className = `badge badge-sev-${sev.toLowerCase()}`;

        document.getElementById("modal-id").textContent = alert.alert_id || "—";
        document.getElementById("modal-detector").textContent = alert.detector || "—";
        document.getElementById("modal-source").textContent = alert.source || "—";
        document.getElementById("modal-dest").textContent = alert.destination || "—";
        document.getElementById("modal-protocol").textContent = alert.protocol || "—";
        document.getElementById("modal-confidence").textContent = alert.confidence_pct || (alert.confidence ? `${Math.round(alert.confidence * 100)}%` : "—");
        document.getElementById("modal-count").textContent = alert.occurrence_count || alert.event_count || 1;
        document.getElementById("modal-status").textContent = alert.status || "NEW";
        document.getElementById("modal-first-seen").textContent = alert.first_seen_formatted || "—";
        document.getElementById("modal-last-seen").textContent = alert.last_seen_formatted || "—";

        document.getElementById("modal-desc").textContent = alert.description || "No description provided.";
        document.getElementById("modal-risk").textContent = alert.risk_reason || alert.risk_context || "No risk assessment recorded.";

        // Evidence
        const evidenceEl = document.getElementById("modal-evidence");
        if (alert.evidence && Object.keys(alert.evidence).length > 0) {
            evidenceEl.textContent = JSON.stringify(alert.evidence, null, 2);
        } else {
            evidenceEl.textContent = "No raw telemetry evidence recorded.";
        }

        // Recommendations
        const recsList = document.getElementById("modal-recs");
        const recs = alert.recommendations || alert.recommendation || [];
        if (recs && recs.length > 0) {
            recsList.innerHTML = recs.map(r => `<li>${escapeHtml(r)}</li>`).join("");
        } else {
            recsList.innerHTML = "<li>No specific recommendations recorded for this event.</li>";
        }

        // Show modal
        document.getElementById("alert-modal").classList.remove("hidden");
    } catch (err) {
        showNotification("Failed to load alert details.", "error");
    }
}

function closeModal() {
    document.getElementById("alert-modal").classList.add("hidden");
}

function handleBackdropClick(event) {
    if (event.target.id === "alert-modal") {
        closeModal();
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

function showNotification(msg, type = "info", duration = 4000) {
    const banner = document.getElementById("notification-banner");
    const msgEl = document.getElementById("notification-message");

    msgEl.innerHTML = msg;
    banner.classList.remove("hidden");

    if (banner._timer) clearTimeout(banner._timer);
    if (duration > 0) {
        banner._timer = setTimeout(() => {
            banner.classList.add("hidden");
        }, duration);
    }
}

function dismissNotification() {
    document.getElementById("notification-banner").classList.add("hidden");
}

function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
