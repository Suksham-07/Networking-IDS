"""
NexIDS Report Generator (Phase 6)
=================================
Generates structured JSON and standalone, professional HTML security reports
from NexIDS detection alerts and prioritized alerts.
"""

from __future__ import annotations

import html
import json
import time
from collections import Counter
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.alert_engine.alert_model import Alert
from app.prioritizer.engine import AlertPrioritizer
from app.prioritizer.models import PrioritizedAlert
from app.utils.constants import (
    PRIORITY_ORDER,
    PRIORITY_P1,
    PRIORITY_P2,
    PRIORITY_P3,
    PRIORITY_P4,
    PROJECT_NAME,
    REPORTS_DIR,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    VERSION,
)
from app.utils.logger import get_logger

log = get_logger(__name__)


def _format_time(ts: float | str | None) -> str:
    """Format a unix timestamp or string into a standard UTC string."""
    if ts is None or ts == 0 or ts == 0.0 or ts == "":
        return "N/A"
    if isinstance(ts, str):
        return ts
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError, OverflowError):
        return str(ts)


def _safe_serialize_dict(item: Any) -> dict[str, Any]:
    """Safely convert an Alert, PrioritizedAlert, dataclass, or dict into a dictionary."""
    if item is None:
        return {}
    if hasattr(item, "to_dict") and callable(item.to_dict):
        try:
            return item.to_dict()
        except Exception:
            pass
    if is_dataclass(item):
        try:
            return asdict(item)
        except Exception:
            pass
    if isinstance(item, dict):
        return dict(item)
    return {"raw_value": str(item)}


class ReportGenerator:
    """Generates structured JSON and standalone HTML security audit reports.

    Parameters
    ----------
    output_dir:
        Directory path where generated report files are stored. Defaults to ``reports/``.
    report_title:
        Title of the report shown in audit metadata and headers.
    """

    def __init__(
        self,
        output_dir: str | Path = REPORTS_DIR,
        report_title: str = f"{PROJECT_NAME} Security Audit & Incident Report",
    ) -> None:
        self.output_dir = Path(output_dir)
        self.report_title = report_title
        self._ensure_output_dir()

    def _ensure_output_dir(self) -> None:
        """Create the reports output directory if it does not already exist."""
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            log.warning("Could not create reports directory %s: %s", self.output_dir, exc)

    def _get_unique_path(self, base_filename: str, extension: str) -> Path:
        """Return a unique file path in ``output_dir`` that will not overwrite existing files."""
        self._ensure_output_dir()
        ext = extension.lstrip(".")
        target = self.output_dir / f"{base_filename}.{ext}"
        if not target.exists():
            return target

        counter = 1
        while True:
            candidate = self.output_dir / f"{base_filename}_{counter}.{ext}"
            if not candidate.exists():
                return candidate
            counter += 1

    def build_report_data(
        self,
        alerts: list[Alert | dict[str, Any]] | None = None,
        prioritized_alerts: list[PrioritizedAlert | dict[str, Any]] | None = None,
        session_start: float | str | None = None,
        session_end: float | str | None = None,
        packets_observed: int | None = None,
        report_title: str | None = None,
    ) -> dict[str, Any]:
        """Assemble a complete, structured data dictionary for the security report.

        Parameters
        ----------
        alerts:
            List of Alert objects or alert dicts. If omitted and prioritized_alerts is provided,
            underlying alerts are extracted automatically.
        prioritized_alerts:
            List of PrioritizedAlert objects or prioritized alert dicts. If omitted and alerts is
            provided, alerts are prioritized automatically.
        session_start:
            Unix epoch or formatted start time of the capture/monitoring session.
        session_end:
            Unix epoch or formatted end time of the capture/monitoring session.
        packets_observed:
            Total packet count captured/processed during the session.
        report_title:
            Optional title override for this report.

        Returns
        -------
        dict[str, Any]
            Unified report structure containing metadata, summary, alerts, and prioritized_alerts.
        """
        now = time.time()
        title = report_title or self.report_title

        raw_alerts: list[Alert | dict[str, Any]] = list(alerts) if alerts is not None else []
        raw_prioritized: list[PrioritizedAlert | dict[str, Any]] = (
            list(prioritized_alerts) if prioritized_alerts is not None else []
        )

        # Cross-populate alerts & prioritized_alerts if only one is supplied
        if not raw_alerts and raw_prioritized:
            for item in raw_prioritized:
                if isinstance(item, PrioritizedAlert):
                    raw_alerts.append(item.alert)
                elif isinstance(item, dict) and "alert" in item:
                    raw_alerts.append(item["alert"])
                else:
                    raw_alerts.append(item)
        elif raw_alerts and not raw_prioritized:
            # Automatic prioritization if only raw alerts supplied
            alert_objs: list[Alert] = []
            dict_alerts: list[dict[str, Any]] = []
            for a in raw_alerts:
                if isinstance(a, Alert):
                    alert_objs.append(a)
                elif isinstance(a, dict):
                    cleaned = dict(a)
                    if cleaned.get("evidence") is None:
                        cleaned["evidence"] = {}
                    if cleaned.get("recommendations") is None:
                        cleaned["recommendations"] = []
                    if cleaned.get("severity") is None:
                        cleaned["severity"] = SEVERITY_MEDIUM
                    try:
                        alert_objs.append(Alert.from_dict(cleaned))
                    except Exception:
                        dict_alerts.append(cleaned)
            if alert_objs:
                prioritizer = AlertPrioritizer()
                raw_prioritized = list(prioritizer.prioritize_alerts(alert_objs))
            for da in dict_alerts:
                raw_prioritized.append(da)

        # Serialize to clean dictionaries
        serialized_alerts: list[dict[str, Any]] = [
            _safe_serialize_dict(a) for a in raw_alerts
        ]
        serialized_prioritized: list[dict[str, Any]] = []

        for pa in raw_prioritized:
            p_dict = _safe_serialize_dict(pa)
            # Ensure all canonical fields required by the report spec are present
            if "priority" not in p_dict and "priority_level" in p_dict:
                p_dict["priority"] = p_dict["priority_level"]

            # Occurrence count
            if "occurrence_count" not in p_dict:
                p_dict["occurrence_count"] = p_dict.get("event_count", 1)

            # Recommendations
            recs = p_dict.get("recommendations")
            if recs is None and "recommendation" in p_dict:
                recs = p_dict["recommendation"]
            if recs is None:
                recs = []
            elif not isinstance(recs, list):
                recs = [str(recs)]
            p_dict["recommendations"] = recs
            p_dict["recommendation"] = recs

            # Risk reason
            risk_context = p_dict.get("risk_context") or ""
            priority_reasons = p_dict.get("priority_reasons") or p_dict.get("reasons") or []
            if isinstance(priority_reasons, list) and priority_reasons:
                reasons_str = "; ".join(str(r) for r in priority_reasons)
                risk_reason = f"{risk_context} (Prioritization reasons: {reasons_str})" if risk_context else reasons_str
            else:
                risk_reason = risk_context or "No risk reason recorded."
            p_dict["risk_reason"] = risk_reason

            # Formatted dates
            first_seen_val = p_dict.get("first_seen") or p_dict.get("timestamp")
            last_seen_val = p_dict.get("last_seen") or p_dict.get("timestamp")
            p_dict["first_seen_formatted"] = _format_time(first_seen_val)
            p_dict["last_seen_formatted"] = _format_time(last_seen_val)

            serialized_prioritized.append(p_dict)

        # Build Alert Summary
        summary = self._compute_summary(serialized_alerts, serialized_prioritized)

        # Build Audit Metadata
        metadata: dict[str, Any] = {
            "report_title": title,
            "nexids_version": VERSION,
            "project_name": PROJECT_NAME,
            "report_timestamp": now,
            "report_timestamp_formatted": _format_time(now),
            "session_start": session_start,
            "session_start_formatted": _format_time(session_start),
            "session_end": session_end,
            "session_end_formatted": _format_time(session_end),
            "total_packets_observed": packets_observed if packets_observed is not None else "N/A",
            "total_alerts": len(serialized_alerts),
            "total_prioritized_alerts": len(serialized_prioritized),
        }

        return {
            "metadata": metadata,
            "summary": summary,
            "alerts": serialized_alerts,
            "prioritized_alerts": serialized_prioritized,
        }

    def _compute_summary(
        self,
        alerts: list[dict[str, Any]],
        prioritized_alerts: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Compute severity distributions, priority distributions, and offender metrics."""
        # Severity counts: ensure HIGH, MEDIUM, LOW, INFO are explicitly present
        severity_counts: dict[str, int] = {
            SEVERITY_CRITICAL: 0,
            SEVERITY_HIGH: 0,
            SEVERITY_MEDIUM: 0,
            SEVERITY_LOW: 0,
            "INFO": 0,
        }

        for a in alerts:
            sev = str(a.get("severity") or "INFO").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["INFO"] += 1

        # Priority distribution counts
        priority_distribution: dict[str, int] = {
            PRIORITY_P1: 0,
            PRIORITY_P2: 0,
            PRIORITY_P3: 0,
            PRIORITY_P4: 0,
        }

        scores: list[float] = []
        for pa in prioritized_alerts:
            plevel = str(pa.get("priority_level") or pa.get("priority") or PRIORITY_P4)
            if plevel in priority_distribution:
                priority_distribution[plevel] += 1
            else:
                priority_distribution[PRIORITY_P4] += 1

            pscore = pa.get("priority_score")
            if isinstance(pscore, (int, float)):
                scores.append(float(pscore))

        # Protocol distribution
        proto_counts = Counter(
            str(a.get("protocol") or "UNKNOWN").upper() for a in alerts
        )

        # Detection types distribution
        detection_counts = Counter(
            str(a.get("detection_type") or "Unknown") for a in alerts
        )

        return {
            "total_alerts": len(alerts),
            "total_prioritized_alerts": len(prioritized_alerts),
            "severity_counts": severity_counts,
            "priority_distribution": priority_distribution,
            "average_priority_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
            "max_priority_score": round(max(scores), 2) if scores else 0.0,
            "protocol_breakdown": dict(proto_counts),
            "detection_type_breakdown": dict(detection_counts),
        }

    # ------------------------------------------------------------------
    # JSON Report Generation
    # ------------------------------------------------------------------

    def render_json(self, report_data: dict[str, Any], indent: int = 2) -> str:
        """Render report data dictionary to a clean, formatted JSON string."""
        return json.dumps(report_data, indent=indent, default=str)

    def generate_json_report(
        self,
        alerts: list[Alert | dict[str, Any]] | None = None,
        prioritized_alerts: list[PrioritizedAlert | dict[str, Any]] | None = None,
        filename: str | None = None,
        session_start: float | str | None = None,
        session_end: float | str | None = None,
        packets_observed: int | None = None,
        report_title: str | None = None,
    ) -> Path:
        """Generate and save a structured JSON security report.

        Returns
        -------
        Path
            Absolute path to the created JSON report file.
        """
        data = self.build_report_data(
            alerts=alerts,
            prioritized_alerts=prioritized_alerts,
            session_start=session_start,
            session_end=session_end,
            packets_observed=packets_observed,
            report_title=report_title,
        )

        if filename:
            target_path = self.output_dir / filename
            if target_path.exists():
                stem = target_path.stem
                suffix = target_path.suffix
                target_path = self._get_unique_path(stem, suffix)
        else:
            ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
            target_path = self._get_unique_path(f"nexids_report_{ts_str}", "json")

        content = self.render_json(data)
        target_path.write_text(content, encoding="utf-8")
        log.info("Saved NexIDS JSON report to %s", target_path)
        return target_path

    # ------------------------------------------------------------------
    # HTML Report Generation
    # ------------------------------------------------------------------

    def render_html(self, report_data: dict[str, Any]) -> str:
        """Render report data dictionary to a standalone, responsive HTML report string."""
        meta = report_data.get("metadata", {})
        summary = report_data.get("summary", {})
        prioritized_alerts = report_data.get("prioritized_alerts", [])
        alerts = report_data.get("alerts", [])

        title = html.escape(str(meta.get("report_title") or "NexIDS Security Audit Report"))
        version = html.escape(str(meta.get("nexids_version") or VERSION))
        report_ts = html.escape(str(meta.get("report_timestamp_formatted") or "N/A"))
        session_start = html.escape(str(meta.get("session_start_formatted") or "N/A"))
        session_end = html.escape(str(meta.get("session_end_formatted") or "N/A"))
        total_packets = html.escape(str(meta.get("total_packets_observed") or "N/A"))
        total_alerts = summary.get("total_alerts", 0)
        total_prioritized = summary.get("total_prioritized_alerts", 0)

        sev_counts = summary.get("severity_counts", {})
        crit_count = sev_counts.get(SEVERITY_CRITICAL, 0)
        high_count = sev_counts.get(SEVERITY_HIGH, 0)
        med_count = sev_counts.get(SEVERITY_MEDIUM, 0)
        low_count = sev_counts.get(SEVERITY_LOW, 0)
        info_count = sev_counts.get("INFO", 0)

        p_dist = summary.get("priority_distribution", {})
        p1_count = p_dist.get(PRIORITY_P1, 0)
        p2_count = p_dist.get(PRIORITY_P2, 0)
        p3_count = p_dist.get(PRIORITY_P3, 0)
        p4_count = p_dist.get(PRIORITY_P4, 0)

        avg_score = summary.get("average_priority_score", 0.0)
        max_score = summary.get("max_priority_score", 0.0)

        crit_pct = f"{crit_count / total_alerts * 100:.1f}%" if total_alerts else "0.0%"
        high_pct = f"{high_count / total_alerts * 100:.1f}%" if total_alerts else "0.0%"
        med_pct = f"{med_count / total_alerts * 100:.1f}%" if total_alerts else "0.0%"
        low_pct = f"{low_count / total_alerts * 100:.1f}%" if total_alerts else "0.0%"
        info_pct = f"{info_count / total_alerts * 100:.1f}%" if total_alerts else "0.0%"

        # Generate Prioritized Alert Cards / Rows HTML
        prioritized_cards_html = []
        if not prioritized_alerts:
            prioritized_cards_html.append(
                """
                <div class="empty-state">
                    <p><strong>No prioritized alerts recorded.</strong></p>
                    <p class="text-muted">No security events met alert trigger thresholds during this monitoring period.</p>
                </div>
                """
            )
        else:
            for rank, pa in enumerate(prioritized_alerts, start=1):
                p_level = html.escape(str(pa.get("priority_level") or pa.get("priority") or PRIORITY_P4))
                p_score = pa.get("priority_score", 0.0)
                sev = html.escape(str(pa.get("severity") or "MEDIUM"))
                alert_id = html.escape(str(pa.get("alert_id") or "N/A"))
                dtype = html.escape(str(pa.get("detection_type") or "Unknown Event"))
                src = html.escape(str(pa.get("source") or "N/A"))
                dst = html.escape(str(pa.get("destination") or "N/A"))
                proto = html.escape(str(pa.get("protocol") or "UNKNOWN"))
                conf = pa.get("confidence", 0.0)
                conf_pct = f"{float(conf) * 100:.0f}%" if isinstance(conf, (int, float)) else str(conf)
                count = pa.get("occurrence_count", pa.get("event_count", 1))
                first_seen = html.escape(str(pa.get("first_seen_formatted") or _format_time(pa.get("first_seen"))))
                last_seen = html.escape(str(pa.get("last_seen_formatted") or _format_time(pa.get("last_seen"))))
                desc = html.escape(str(pa.get("description") or "No description available."))
                risk_reason = html.escape(str(pa.get("risk_reason") or "No risk reasoning recorded."))
                status = html.escape(str(pa.get("status") or "NEW"))
                detector = html.escape(str(pa.get("detector") or "Unknown Detector"))

                # Evidence rendering
                evidence_dict = pa.get("evidence") or {}
                if isinstance(evidence_dict, dict) and evidence_dict:
                    evidence_json = html.escape(json.dumps(evidence_dict, indent=2))
                    evidence_html = f"<pre><code>{evidence_json}</code></pre>"
                else:
                    evidence_html = "<p class='text-muted'>No additional evidence dictionary recorded.</p>"

                # Recommendations rendering
                recs = pa.get("recommendations") or pa.get("recommendation") or []
                if isinstance(recs, list) and recs:
                    rec_items = "".join(f"<li>{html.escape(str(r))}</li>" for r in recs)
                    recs_html = f"<ul class='recommendations-list'>{rec_items}</ul>"
                else:
                    recs_html = "<p class='text-muted'>No specific recommendations provided.</p>"

                # CSS badge classes
                sev_badge_class = f"badge-sev-{sev.lower()}"
                p_badge_class = f"badge-pri-{p_level.lower()}"

                card_html = f"""
                <div class="alert-card priority-{p_level.lower()}">
                    <div class="alert-card-header">
                        <div class="alert-header-left">
                            <span class="rank-indicator">#{rank}</span>
                            <span class="badge {p_badge_class}">{p_level} ({p_score:.1f} pts)</span>
                            <span class="badge {sev_badge_class}">{sev}</span>
                            <span class="alert-title">{dtype}</span>
                        </div>
                        <div class="alert-header-right">
                            <span class="badge badge-status">{status}</span>
                            <span class="alert-id mono text-muted">ID: {alert_id}</span>
                        </div>
                    </div>
                    <div class="alert-card-body">
                        <div class="alert-meta-grid">
                            <div><span class="meta-label">Source:</span> <span class="meta-value mono">{src}</span></div>
                            <div><span class="meta-label">Destination:</span> <span class="meta-value mono">{dst}</span></div>
                            <div><span class="meta-label">Protocol:</span> <span class="meta-value">{proto}</span></div>
                            <div><span class="meta-label">Confidence:</span> <span class="meta-value">{conf_pct}</span></div>
                            <div><span class="meta-label">Detector:</span> <span class="meta-value">{detector}</span></div>
                            <div><span class="meta-label">Occurrences:</span> <span class="meta-value">{count}</span></div>
                            <div><span class="meta-label">Observation Window:</span> <span class="meta-value">{first_seen} &rarr; {last_seen}</span></div>
                        </div>

                        <div class="alert-section">
                            <div class="section-subtitle">Observation Summary</div>
                            <p class="section-text">{desc}</p>
                        </div>

                        <div class="alert-section">
                            <div class="section-subtitle">Risk & Prioritization Reason</div>
                            <p class="section-text">{risk_reason}</p>
                        </div>

                        <div class="alert-section">
                            <div class="section-subtitle">Evidence & Telemetry</div>
                            {evidence_html}
                        </div>

                        <div class="alert-section">
                            <div class="section-subtitle">Actionable Recommendations</div>
                            {recs_html}
                        </div>
                    </div>
                </div>
                """
                prioritized_cards_html.append(card_html)

        prioritized_content = "\n".join(prioritized_cards_html)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --surface-color: #131b2e;
            --surface-border: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-blue: #38bdf8;
            --accent-cyan: #06b6d4;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #3b82f6;
            --success: #10b981;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem 1.5rem;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        /* Header */
        header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1.5rem;
        }}

        .brand-title {{
            font-size: 1.8rem;
            font-weight: 700;
            letter-spacing: -0.5px;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}

        .brand-badge {{
            background: rgba(56, 189, 248, 0.15);
            color: var(--accent-blue);
            font-size: 0.8rem;
            font-weight: 600;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            border: 1px solid rgba(56, 189, 248, 0.3);
        }}

        .report-subtitle {{
            color: var(--text-secondary);
            font-size: 0.95rem;
            margin-top: 0.25rem;
        }}

        .header-meta {{
            text-align: right;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}

        .header-meta strong {{
            color: var(--text-primary);
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: var(--surface-color);
            border: 1px solid var(--surface-border);
            border-radius: 10px;
            padding: 1.25rem 1.5rem;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }}

        .stat-label {{
            font-size: 0.85rem;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
        }}

        .stat-value {{
            font-size: 2.2rem;
            font-weight: 700;
            margin-top: 0.5rem;
            color: var(--text-primary);
        }}

        .stat-subtext {{
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }}

        /* Summary Section */
        .summary-section {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}

        @media (max-width: 800px) {{
            .summary-section {{
                grid-template-columns: 1fr;
            }}
            .header-meta {{
                text-align: left;
            }}
        }}

        .summary-card {{
            background: var(--surface-color);
            border: 1px solid var(--surface-border);
            border-radius: 10px;
            padding: 1.5rem;
        }}

        .summary-title {{
            font-size: 1.15rem;
            font-weight: 600;
            margin-bottom: 1.25rem;
            color: var(--text-primary);
            border-bottom: 1px solid var(--surface-border);
            padding-bottom: 0.75rem;
        }}

        .distribution-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}

        .distribution-table th, .distribution-table td {{
            padding: 0.6rem 0.5rem;
            text-align: left;
        }}

        .distribution-table th {{
            color: var(--text-secondary);
            font-weight: 600;
            border-bottom: 1px solid var(--surface-border);
        }}

        .distribution-table td {{
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .text-right {{
            text-align: right !important;
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.55rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .badge-sev-critical {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid #ef4444; }}
        .badge-sev-high {{ background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid #f97316; }}
        .badge-sev-medium {{ background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid #eab308; }}
        .badge-sev-low {{ background: rgba(14, 165, 233, 0.2); color: #7dd3fc; border: 1px solid #0ea5e9; }}
        .badge-sev-info {{ background: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid #64748b; }}

        .badge-pri-p1_critical {{ background: rgba(239, 68, 68, 0.25); color: #ff8080; border: 1px solid #ef4444; }}
        .badge-pri-p2_high {{ background: rgba(249, 115, 22, 0.25); color: #ffad66; border: 1px solid #f97316; }}
        .badge-pri-p3_medium {{ background: rgba(234, 179, 8, 0.25); color: #ffe066; border: 1px solid #eab308; }}
        .badge-pri-p4_low {{ background: rgba(14, 165, 233, 0.25); color: #80d4ff; border: 1px solid #0ea5e9; }}

        .badge-status {{ background: rgba(255, 255, 255, 0.08); color: var(--text-secondary); border: 1px solid rgba(255, 255, 255, 0.15); }}

        /* Alert Cards */
        .section-header {{
            font-size: 1.4rem;
            font-weight: 700;
            margin-bottom: 1.25rem;
            color: var(--text-primary);
        }}

        .alert-card {{
            background: var(--surface-color);
            border: 1px solid var(--surface-border);
            border-radius: 10px;
            margin-bottom: 1.5rem;
            overflow: hidden;
            transition: border-color 0.2s;
        }}

        .alert-card.priority-p1_critical {{ border-left: 5px solid #ef4444; }}
        .alert-card.priority-p2_high {{ border-left: 5px solid #f97316; }}
        .alert-card.priority-p3_medium {{ border-left: 5px solid #eab308; }}
        .alert-card.priority-p4_low {{ border-left: 5px solid #0ea5e9; }}

        .alert-card-header {{
            background: rgba(255, 255, 255, 0.02);
            border-bottom: 1px solid var(--surface-border);
            padding: 1rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.75rem;
        }}

        .alert-header-left {{
            display: flex;
            align-items: center;
            gap: 0.6rem;
            flex-wrap: wrap;
        }}

        .rank-indicator {{
            font-size: 0.95rem;
            font-weight: 700;
            color: var(--accent-blue);
        }}

        .alert-title {{
            font-size: 1.05rem;
            font-weight: 600;
            color: var(--text-primary);
        }}

        .alert-card-body {{
            padding: 1.25rem;
        }}

        .alert-meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.75rem;
            background: rgba(0, 0, 0, 0.2);
            padding: 0.85rem 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            margin-bottom: 1.25rem;
        }}

        .meta-label {{
            color: var(--text-secondary);
            font-weight: 500;
        }}

        .meta-value {{
            color: var(--text-primary);
            font-weight: 600;
        }}

        .mono {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        }}

        .alert-section {{
            margin-top: 1rem;
        }}

        .section-subtitle {{
            font-size: 0.85rem;
            text-transform: uppercase;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 0.35rem;
            letter-spacing: 0.5px;
        }}

        .section-text {{
            font-size: 0.92rem;
            color: var(--text-primary);
            line-height: 1.5;
        }}

        pre {{
            background: #080c14;
            border: 1px solid var(--surface-border);
            border-radius: 6px;
            padding: 0.75rem 1rem;
            overflow-x: auto;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.82rem;
            color: #38bdf8;
            margin-top: 0.25rem;
        }}

        .recommendations-list {{
            margin-left: 1.25rem;
            font-size: 0.92rem;
            color: var(--text-primary);
            margin-top: 0.25rem;
        }}

        .recommendations-list li {{
            margin-bottom: 0.35rem;
        }}

        .empty-state {{
            background: var(--surface-color);
            border: 1px dashed var(--surface-border);
            border-radius: 10px;
            padding: 3rem 1.5rem;
            text-align: center;
        }}

        .text-muted {{
            color: var(--text-muted);
        }}

        footer {{
            margin-top: 3rem;
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
            border-top: 1px solid var(--surface-border);
            padding-top: 1.5rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <div>
                <div class="brand-title">
                    <span>{PROJECT_NAME}</span>
                    <span class="brand-badge">v{version}</span>
                </div>
                <div class="report-subtitle">{title}</div>
            </div>
            <div class="header-meta">
                <div>Generated: <strong>{report_ts}</strong></div>
                <div>Monitoring: <strong>{session_start} &rarr; {session_end}</strong></div>
            </div>
        </header>

        <!-- Stats Overview -->
        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-label">Packets Inspected</span>
                <span class="stat-value">{total_packets}</span>
                <span class="stat-subtext">Total raw traffic volume</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Total Alerts</span>
                <span class="stat-value">{total_alerts}</span>
                <span class="stat-subtext">Detection events triggered</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Prioritized Alerts</span>
                <span class="stat-value">{total_prioritized}</span>
                <span class="stat-subtext">Triaged incidents</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Max Risk Score</span>
                <span class="stat-value">{max_score:.1f}</span>
                <span class="stat-subtext">Avg: {avg_score:.1f} / 100.0</span>
            </div>
        </div>

        <!-- Summary Tables -->
        <div class="summary-section">
            <div class="summary-card">
                <div class="summary-title">Alert Severity Distribution</div>
                <table class="distribution-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th class="text-right">Count</th>
                            <th class="text-right">Share</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><span class="badge badge-sev-critical">CRITICAL</span></td>
                            <td class="text-right mono">{crit_count}</td>
                            <td class="text-right text-muted">{crit_pct}</td>
                        </tr>
                        <tr>
                            <td><span class="badge badge-sev-high">HIGH</span></td>
                            <td class="text-right mono">{high_count}</td>
                            <td class="text-right text-muted">{high_pct}</td>
                        </tr>
                        <tr>
                            <td><span class="badge badge-sev-medium">MEDIUM</span></td>
                            <td class="text-right mono">{med_count}</td>
                            <td class="text-right text-muted">{med_pct}</td>
                        </tr>
                        <tr>
                            <td><span class="badge badge-sev-low">LOW</span></td>
                            <td class="text-right mono">{low_count}</td>
                            <td class="text-right text-muted">{low_pct}</td>
                        </tr>
                        <tr>
                            <td><span class="badge badge-sev-info">INFO</span></td>
                            <td class="text-right mono">{info_count}</td>
                            <td class="text-right text-muted">{info_pct}</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="summary-card">
                <div class="summary-title">Priority Triage Distribution</div>
                <table class="distribution-table">
                    <thead>
                        <tr>
                            <th>Priority Tier</th>
                            <th class="text-right">Count</th>
                            <th class="text-right">Action Tier</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><span class="badge badge-pri-p1_critical">P1 (Critical)</span></td>
                            <td class="text-right mono">{p1_count}</td>
                            <td class="text-right text-muted">Immediate response</td>
                        </tr>
                        <tr>
                            <td><span class="badge badge-pri-p2_high">P2 (High)</span></td>
                            <td class="text-right mono">{p2_count}</td>
                            <td class="text-right text-muted">Prompt review</td>
                        </tr>
                        <tr>
                            <td><span class="badge badge-pri-p3_medium">P3 (Medium)</span></td>
                            <td class="text-right mono">{p3_count}</td>
                            <td class="text-right text-muted">Standard triage</td>
                        </tr>
                        <tr>
                            <td><span class="badge badge-pri-p4_low">P4 (Low)</span></td>
                            <td class="text-right mono">{p4_count}</td>
                            <td class="text-right text-muted">Routine log review</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Priority Alerts Section -->
        <div class="section-header">Prioritized Security Incidents ({total_prioritized})</div>
        {prioritized_content}

        <!-- Footer -->
        <footer>
            {PROJECT_NAME} v{version} &bull; Defensive Network Intrusion Detection System &bull; Authorised Monitoring Only
        </footer>
    </div>
</body>
</html>
"""
        return html_template

    def generate_html_report(
        self,
        alerts: list[Alert | dict[str, Any]] | None = None,
        prioritized_alerts: list[PrioritizedAlert | dict[str, Any]] | None = None,
        filename: str | None = None,
        session_start: float | str | None = None,
        session_end: float | str | None = None,
        packets_observed: int | None = None,
        report_title: str | None = None,
    ) -> Path:
        """Generate and save a standalone, styled HTML security audit report.

        Returns
        -------
        Path
            Absolute path to the created HTML report file.
        """
        data = self.build_report_data(
            alerts=alerts,
            prioritized_alerts=prioritized_alerts,
            session_start=session_start,
            session_end=session_end,
            packets_observed=packets_observed,
            report_title=report_title,
        )

        if filename:
            target_path = self.output_dir / filename
            if target_path.exists():
                stem = target_path.stem
                suffix = target_path.suffix
                target_path = self._get_unique_path(stem, suffix)
        else:
            ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
            target_path = self._get_unique_path(f"nexids_report_{ts_str}", "html")

        html_content = self.render_html(data)
        target_path.write_text(html_content, encoding="utf-8")
        log.info("Saved NexIDS HTML report to %s", target_path)
        return target_path

    def generate_reports(
        self,
        alerts: list[Alert | dict[str, Any]] | None = None,
        prioritized_alerts: list[PrioritizedAlert | dict[str, Any]] | None = None,
        base_filename: str | None = None,
        session_start: float | str | None = None,
        session_end: float | str | None = None,
        packets_observed: int | None = None,
        report_title: str | None = None,
    ) -> dict[str, Path]:
        """Generate both structured JSON and standalone HTML reports simultaneously.

        Returns
        -------
        dict[str, Path]
            Dictionary mapping ``"json"`` and ``"html"`` to their respective file paths.
        """
        data = self.build_report_data(
            alerts=alerts,
            prioritized_alerts=prioritized_alerts,
            session_start=session_start,
            session_end=session_end,
            packets_observed=packets_observed,
            report_title=report_title,
        )

        stem = base_filename or f"nexids_report_{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H%M%S')}"
        json_path = self._get_unique_path(stem, "json")
        html_path = self._get_unique_path(stem, "html")

        json_path.write_text(self.render_json(data), encoding="utf-8")
        html_path.write_text(self.render_html(data), encoding="utf-8")

        log.info("Generated reports: JSON -> %s, HTML -> %s", json_path, html_path)
        return {
            "json": json_path,
            "html": html_path,
        }
