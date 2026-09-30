"""
NexIDS Dashboard Service (Phase 7)
==================================
Coordinates the backend monitoring lifecycle, detection pipeline, alert
prioritization, and report generation for the web dashboard.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.alert_engine.alert_manager import AlertManager
from app.alert_engine.alert_model import Alert
from app.capture.packet_capture import PacketCapture
from app.detection.engine import DetectionEngine
from app.detection.models import DetectionEvent
from app.prioritizer.engine import AlertPrioritizer
from app.prioritizer.models import (
    PRIORITY_P1,
    PRIORITY_P2,
    PRIORITY_P3,
    PRIORITY_P4,
    PrioritizedAlert,
)
from app.reporter.report_generator import ReportGenerator, _format_time
from app.utils.constants import (
    ALERT_ARP_ANOMALY,
    ALERT_ICMP_ANOMALY,
    ALERT_PORT_SCAN,
    ALERT_TRAFFIC_ANOMALY,
    DEFAULT_CAPTURE_COUNT,
    DEFAULT_CAPTURE_TIMEOUT,
    DEFAULT_INTERFACE,
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


class DashboardService:
    """Singleton-ready service managing IDS capture, detection, alerts, and reporting.

    Parameters
    ----------
    reports_dir:
        Directory where generated reports are stored.
    """

    def __init__(self, reports_dir: str | Path = REPORTS_DIR) -> None:
        self.reports_dir = Path(reports_dir)
        self.lock = threading.Lock()

        # Monitoring state
        self.is_running = False
        self.is_demo_mode = False
        self.interface: str | None = None
        self.bpf_filter: str = ""
        self.start_time: float | None = None
        self.stop_time: float | None = None
        self.packets_inspected: int = 0
        self.status_message: str = "Monitoring stopped."
        self.live_capture_available: bool = True

        # Pipeline components
        self.capture: PacketCapture | None = None
        self.detection_engine = DetectionEngine()
        self.alert_manager = AlertManager()
        self.prioritizer = AlertPrioritizer()
        self.reporter = ReportGenerator(output_dir=self.reports_dir)

    # ------------------------------------------------------------------
    # Monitoring Controls
    # ------------------------------------------------------------------

    def start_monitoring(
        self,
        interface: str | None = None,
        bpf_filter: str = "",
        demo: bool = False,
    ) -> dict[str, Any]:
        """Start network traffic monitoring or demo session."""
        with self.lock:
            if self.is_running:
                return {
                    "success": False,
                    "message": "Monitoring is already active.",
                    "is_running": True,
                }

            if demo:
                # Start demo mode
                self.is_running = True
                self.is_demo_mode = True
                self.interface = "demo-virtual"
                self.bpf_filter = bpf_filter
                self.start_time = time.time()
                self.stop_time = None
                self.status_message = "Demo monitoring active (DEMO MODE)."
                log.info("Started demo monitoring mode.")
                return {
                    "success": True,
                    "message": self.status_message,
                    "is_running": True,
                    "is_demo_mode": True,
                }

            # Attempt live capture
            self.interface = interface
            self.bpf_filter = bpf_filter
            try:
                self.capture = PacketCapture(
                    interface=interface,
                    bpf_filter=bpf_filter,
                    on_packet=self._handle_packet,
                )
                self.capture.start()
                self.is_running = True
                self.is_demo_mode = False
                self.start_time = time.time()
                self.stop_time = None
                self.status_message = "Live network monitoring active."
                self.live_capture_available = True
                log.info("Live packet capture started on interface=%s", interface or "auto")
                return {
                    "success": True,
                    "message": self.status_message,
                    "is_running": True,
                    "is_demo_mode": False,
                }
            except Exception as exc:
                self.is_running = False
                self.capture = None
                self.live_capture_available = False
                self.status_message = (
                    f"Live packet capture is unavailable ({exc}). Demo mode can be used."
                )
                log.warning("Capture start failure: %s", exc)
                return {
                    "success": False,
                    "message": self.status_message,
                    "is_running": False,
                    "live_capture_available": False,
                }

    def stop_monitoring(self) -> dict[str, Any]:
        """Stop active network monitoring."""
        with self.lock:
            if not self.is_running:
                return {
                    "success": True,
                    "message": "Monitoring was not active.",
                    "is_running": False,
                }

            if self.capture and self.capture.is_running():
                try:
                    self.capture.stop()
                except Exception as exc:
                    log.warning("Error stopping capture: %s", exc)

            self.is_running = False
            self.stop_time = time.time()
            self.status_message = "Monitoring stopped."
            log.info("Network monitoring stopped.")
            return {
                "success": True,
                "message": self.status_message,
                "is_running": False,
            }

    def _handle_packet(self, parsed_pkt: dict[str, Any]) -> None:
        """Callback invoked by PacketCapture for each captured packet."""
        with self.lock:
            self.packets_inspected += 1
            try:
                events = self.detection_engine.inspect(parsed_pkt)
                if events:
                    self.alert_manager.process_events(events)
            except Exception as exc:
                log.error("Error inspecting packet: %s", exc)

    # ------------------------------------------------------------------
    # Demo Data Generation
    # ------------------------------------------------------------------

    def load_demo_data(self) -> dict[str, Any]:
        """Inject realistic synthetic security events and alerts for demonstration."""
        with self.lock:
            self.is_demo_mode = True
            now = time.time()
            demo_events = [
                DetectionEvent(
                    detection_type=ALERT_ARP_ANOMALY,
                    source="192.168.1.150",
                    destination="192.168.1.1",
                    protocol="ARP",
                    confidence=0.95,
                    description="Host 192.168.1.150 claimed hardware address of default gateway 192.168.1.1.",
                    evidence={
                        "ip_address": "192.168.1.1",
                        "previous_mac": "00:11:22:33:44:55",
                        "observed_mac": "aa:bb:cc:dd:ee:ff",
                        "anomaly_subtype": "arp_mapping_change",
                    },
                    detector="ARPAnomalyDetector",
                    timestamp=now - 45,
                ),
                DetectionEvent(
                    detection_type=ALERT_PORT_SCAN,
                    source="192.168.1.150",
                    destination="192.168.1.1",
                    protocol="TCP",
                    confidence=0.92,
                    description="Host 192.168.1.150 probed 42 distinct destination ports on gateway 192.168.1.1.",
                    evidence={
                        "distinct_ports": 42,
                        "scanned_ports": [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080],
                        "duration_sec": 6.8,
                    },
                    detector="PortScanDetector",
                    timestamp=now - 30,
                ),
                DetectionEvent(
                    detection_type=ALERT_TRAFFIC_ANOMALY,
                    source="192.168.1.200",
                    destination="10.0.0.10",
                    protocol="UDP",
                    confidence=0.87,
                    description="Anomalous traffic burst: 6,500 packets/sec observed (12.8 MB/s).",
                    evidence={
                        "pps": 6500.0,
                        "bps": 12_800_000.0,
                        "violations": {
                            "packets_per_second": {"observed": 6500.0, "threshold": 1000.0}
                        },
                    },
                    detector="TrafficAnomalyDetector",
                    timestamp=now - 15,
                ),
                DetectionEvent(
                    detection_type=ALERT_ICMP_ANOMALY,
                    source="10.0.0.88",
                    destination="192.168.1.254",
                    protocol="ICMP",
                    confidence=0.75,
                    description="Ping sweep pattern observed: 55 ICMP echo requests targeting subnet.",
                    evidence={
                        "packet_count": 55,
                        "possible_reconnaissance": True,
                        "pattern": "reconnaissance",
                    },
                    detector="ICMPAnomalyDetector",
                    timestamp=now - 5,
                ),
            ]

            self.alert_manager.process_events(demo_events)
            self.packets_inspected += 18450
            self.status_message = "Demo traffic and alerts loaded (DEMO MODE)."
            log.info("Demo data loaded: 4 synthetic security alerts created.")

            return {
                "success": True,
                "message": self.status_message,
                "alerts_added": len(demo_events),
                "is_demo_mode": True,
            }

    # ------------------------------------------------------------------
    # Telemetry, Status & Alert Queries
    # ------------------------------------------------------------------

    def get_status(self) -> dict[str, Any]:
        """Return current monitoring state and metadata."""
        with self.lock:
            elapsed = 0.0
            if self.is_running and self.start_time:
                elapsed = round(time.time() - self.start_time, 1)
            elif self.start_time and self.stop_time:
                elapsed = round(self.stop_time - self.start_time, 1)

            return {
                "is_running": self.is_running,
                "is_demo_mode": self.is_demo_mode,
                "interface": self.interface or "N/A",
                "bpf_filter": self.bpf_filter or "all",
                "start_time": self.start_time,
                "start_time_formatted": _format_time(self.start_time),
                "elapsed_seconds": elapsed,
                "live_capture_available": self.live_capture_available,
                "status_message": self.status_message,
                "project_name": PROJECT_NAME,
                "version": VERSION,
            }

    def get_stats(self) -> dict[str, Any]:
        """Return high-level summary counts, severity distribution, and priority metrics."""
        with self.lock:
            alerts = self.alert_manager.get_alerts()
            prioritized = self.prioritizer.prioritize_alerts(alerts)

            sev_counts: dict[str, int] = {
                SEVERITY_CRITICAL: 0,
                SEVERITY_HIGH: 0,
                SEVERITY_MEDIUM: 0,
                SEVERITY_LOW: 0,
                "INFO": 0,
            }
            for a in alerts:
                sev = (a.severity or "INFO").upper()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                else:
                    sev_counts["INFO"] += 1

            pri_counts: dict[str, int] = {
                PRIORITY_P1: 0,
                PRIORITY_P2: 0,
                PRIORITY_P3: 0,
                PRIORITY_P4: 0,
            }
            scores: list[float] = []
            for pa in prioritized:
                lvl = pa.priority_level
                if lvl in pri_counts:
                    pri_counts[lvl] += 1
                else:
                    pri_counts[PRIORITY_P4] += 1
                scores.append(pa.priority_score)

            elapsed = 0.0
            if self.is_running and self.start_time:
                elapsed = round(time.time() - self.start_time, 1)
            elif self.start_time and self.stop_time:
                elapsed = round(self.stop_time - self.start_time, 1)

            return {
                "packets_inspected": self.packets_inspected,
                "total_alerts": len(alerts),
                "total_prioritized_alerts": len(prioritized),
                "severity_counts": sev_counts,
                "priority_distribution": pri_counts,
                "average_priority_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
                "max_priority_score": round(max(scores), 2) if scores else 0.0,
                "elapsed_seconds": elapsed,
                "is_running": self.is_running,
                "is_demo_mode": self.is_demo_mode,
            }

    def get_alerts(self) -> list[dict[str, Any]]:
        """Return list of all current alerts in dictionary format."""
        with self.lock:
            alerts = self.alert_manager.get_alerts()
            return [a.to_dict() for a in alerts]

    def get_prioritized_alerts(self) -> list[dict[str, Any]]:
        """Return all alerts prioritized, sorted by priority score, with rankings."""
        with self.lock:
            alerts = self.alert_manager.get_alerts()
            prioritized = self.prioritizer.prioritize_alerts(alerts)

            result: list[dict[str, Any]] = []
            for rank, pa in enumerate(prioritized, start=1):
                p_dict = pa.to_dict()
                p_dict["rank"] = f"#{rank}"
                p_dict["confidence_pct"] = f"{int(pa.confidence * 100)}%"
                p_dict["first_seen_formatted"] = _format_time(pa.first_seen)
                p_dict["last_seen_formatted"] = _format_time(pa.last_seen)
                p_dict["risk_reason"] = (
                    pa.risk_context
                    if pa.risk_context
                    else "; ".join(pa.reasons) or "No risk reasoning recorded."
                )
                p_dict["recommendation"] = pa.recommendations
                p_dict["occurrence_count"] = pa.event_count
                result.append(p_dict)

            return result

    def get_alert_by_id(self, alert_id: str) -> dict[str, Any] | None:
        """Find a specific alert by ID and return its detailed prioritization profile."""
        with self.lock:
            alerts = self.alert_manager.get_alerts()
            target_alert: Alert | None = None
            for a in alerts:
                if a.alert_id == alert_id:
                    target_alert = a
                    break

            if not target_alert:
                return None

            pa = self.prioritizer.prioritize_alert(target_alert, context_alerts=alerts)
            detail = pa.to_dict()
            detail["confidence_pct"] = f"{int(pa.confidence * 100)}%"
            detail["first_seen_formatted"] = _format_time(pa.first_seen)
            detail["last_seen_formatted"] = _format_time(pa.last_seen)
            detail["risk_reason"] = (
                pa.risk_context
                if pa.risk_context
                else "; ".join(pa.reasons) or "No risk reasoning recorded."
            )
            detail["recommendation"] = pa.recommendations
            detail["occurrence_count"] = pa.event_count
            return detail

    # ------------------------------------------------------------------
    # Report Generation
    # ------------------------------------------------------------------

    def generate_report(self, report_type: str = "json") -> dict[str, Any]:
        """Generate a JSON or HTML security audit report using the Phase 6 reporter."""
        with self.lock:
            alerts = self.alert_manager.get_alerts()
            prioritized = self.prioritizer.prioritize_alerts(alerts)

            if report_type.lower() == "html":
                path = self.reporter.generate_html_report(
                    alerts=alerts,
                    prioritized_alerts=prioritized,
                    session_start=self.start_time,
                    session_end=self.stop_time or time.time(),
                    packets_observed=self.packets_inspected,
                )
            else:
                path = self.reporter.generate_json_report(
                    alerts=alerts,
                    prioritized_alerts=prioritized,
                    session_start=self.start_time,
                    session_end=self.stop_time or time.time(),
                    packets_observed=self.packets_inspected,
                )

            return {
                "success": True,
                "filename": path.name,
                "path": str(path),
                "report_type": report_type.lower(),
                "download_url": f"/api/reports/download/{path.name}",
            }

    def reset_state(self) -> None:
        """Reset all alerts, detectors, and monitoring counters."""
        with self.lock:
            if self.capture and self.capture.is_running():
                try:
                    self.capture.stop()
                except Exception:
                    pass
            self.is_running = False
            self.is_demo_mode = False
            self.start_time = None
            self.stop_time = None
            self.packets_inspected = 0
            self.status_message = "Monitoring reset."
            self.detection_engine.reset()
            self.alert_manager.clear()
            self.capture = None
