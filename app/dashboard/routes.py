"""
NexIDS Dashboard Routes (Phase 7)
=================================
Flask REST API and web endpoints connecting the browser interface
to the NexIDS detection and alert prioritization pipeline.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from flask import Blueprint, abort, current_app, jsonify, render_template, request, send_from_directory

from app.dashboard.service import DashboardService
from app.utils.constants import PROJECT_NAME, VERSION
from app.utils.logger import get_logger

log = get_logger(__name__)

bp = Blueprint("dashboard", __name__)


def get_service() -> DashboardService:
    """Retrieve the DashboardService instance attached to the Flask app."""
    return current_app.config["DASHBOARD_SERVICE"]


# ---------------------------------------------------------------------------
# UI View
# ---------------------------------------------------------------------------


@bp.route("/")
def index():
    """Render the main SOC dashboard interface."""
    service = get_service()
    status = service.get_status()
    stats = service.get_stats()
    return render_template(
        "index.html",
        project_name=PROJECT_NAME,
        version=VERSION,
        status=status,
        stats=stats,
    )


# ---------------------------------------------------------------------------
# Telemetry & Status API
# ---------------------------------------------------------------------------


@bp.route("/api/status", methods=["GET"])
def api_status():
    """Return live monitoring engine status."""
    service = get_service()
    return jsonify(service.get_status())


@bp.route("/api/stats", methods=["GET"])
def api_stats():
    """Return packet inspection metrics and alert distributions."""
    service = get_service()
    return jsonify(service.get_stats())


# ---------------------------------------------------------------------------
# Alerts & Prioritization API
# ---------------------------------------------------------------------------


@bp.route("/api/alerts", methods=["GET"])
def api_alerts():
    """Return all detected alerts."""
    service = get_service()
    alerts = service.get_alerts()
    return jsonify({
        "alerts": alerts,
        "count": len(alerts),
    })


@bp.route("/api/alerts/priority", methods=["GET"])
def api_priority_alerts():
    """Return prioritized alerts sorted in descending order of risk score."""
    service = get_service()
    prioritized = service.get_prioritized_alerts()
    return jsonify({
        "prioritized_alerts": prioritized,
        "count": len(prioritized),
    })


@bp.route("/api/alerts/<alert_id>", methods=["GET"])
def api_alert_detail(alert_id: str):
    """Retrieve full detail, evidence, and recommendations for a single alert."""
    if not alert_id or not isinstance(alert_id, str):
        return jsonify({"error": "Invalid alert ID", "found": False}), 400

    service = get_service()
    alert_detail = service.get_alert_by_id(alert_id)
    if not alert_detail:
        return jsonify({"error": f"Alert with ID '{alert_id}' was not found.", "found": False}), 404

    return jsonify({
        "alert": alert_detail,
        "found": True,
    })


# ---------------------------------------------------------------------------
# Monitoring Control API
# ---------------------------------------------------------------------------


@bp.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    """Start passive traffic monitoring or demo session."""
    data = request.get_json(silent=True) or {}
    interface = data.get("interface")
    bpf_filter = data.get("bpf_filter", "")
    demo = bool(data.get("demo", False))

    service = get_service()
    try:
        result = service.start_monitoring(interface=interface, bpf_filter=bpf_filter, demo=demo)
        return jsonify(result)
    except Exception as exc:
        log.error("Failed to start monitoring: %s", exc)
        return jsonify({
            "success": False,
            "message": f"Unable to start monitoring session: {exc}",
            "is_running": False,
        }), 500


@bp.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    """Stop active traffic monitoring."""
    service = get_service()
    try:
        result = service.stop_monitoring()
        return jsonify(result)
    except Exception as exc:
        log.error("Failed to stop monitoring: %s", exc)
        return jsonify({
            "success": False,
            "message": f"Error stopping monitoring session: {exc}",
            "is_running": False,
        }), 500


# ---------------------------------------------------------------------------
# Demo / Synthetic Mode API
# ---------------------------------------------------------------------------


@bp.route("/api/demo/generate", methods=["POST"])
def api_demo_generate():
    """Inject synthetic traffic and detection events for demonstration."""
    service = get_service()
    try:
        result = service.load_demo_data()
        return jsonify(result)
    except Exception as exc:
        log.error("Failed to generate demo data: %s", exc)
        return jsonify({
            "success": False,
            "message": f"Failed to generate synthetic demo events: {exc}",
            "is_demo_mode": False,
        }), 500


# ---------------------------------------------------------------------------
# Report Generation & Download API
# ---------------------------------------------------------------------------


@bp.route("/api/report/json", methods=["POST"])
def api_report_json():
    """Generate a structured JSON security audit report."""
    service = get_service()
    try:
        result = service.generate_report(report_type="json")
        return jsonify(result)
    except Exception as exc:
        log.error("Failed to generate JSON report: %s", exc)
        return jsonify({
            "success": False,
            "error": "Failed to generate structured JSON report.",
        }), 500


@bp.route("/api/report/html", methods=["POST"])
def api_report_html():
    """Generate a standalone HTML security audit report."""
    service = get_service()
    try:
        result = service.generate_report(report_type="html")
        return jsonify(result)
    except Exception as exc:
        log.error("Failed to generate HTML report: %s", exc)
        return jsonify({
            "success": False,
            "error": "Failed to generate standalone HTML report.",
        }), 500


@bp.route("/api/reports/download/<path:filename>", methods=["GET"])
def api_download_report(filename: str):
    """Safely stream a generated report file to the client."""
    service = get_service()
    try:
        reports_dir = service.reports_dir.resolve()

        # Prevent directory traversal attacks
        safe_filename = os.path.basename(filename)
        target_path = (reports_dir / safe_filename).resolve()

        if not target_path.exists() or not str(target_path).startswith(str(reports_dir)):
            abort(404, description="Report file not found.")

        return send_from_directory(
            directory=str(reports_dir),
            path=safe_filename,
            as_attachment=True,
        )
    except Exception as exc:
        if getattr(exc, "code", None) == 404:
            raise
        log.error("Download error for %s: %s", filename, exc)
        abort(404, description="Report file could not be accessed.")

