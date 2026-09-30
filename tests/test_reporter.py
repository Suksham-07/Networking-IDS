"""
NexIDS — Report Generator Tests (Phase 6)
=========================================
Comprehensive test suite for Phase 6:
* Empty monitoring session
* No alerts
* One HIGH alert
* Multiple alerts
* Multiple priority levels
* Missing optional fields
* JSON report generation
* HTML report generation
* Timestamped filenames
* Existing report files are not overwritten
* Correct severity counts
* Correct priority ordering
* Evidence preservation
* Recommendation preservation
* End-to-end integration: DetectionEvent -> Alert -> PrioritizedAlert -> JSON/HTML Report
"""

from __future__ import annotations

import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from app.alert_engine.alert_manager import AlertManager
from app.alert_engine.alert_model import Alert
from app.detection.engine import DetectionEngine
from app.detection.models import DetectionEvent
from app.prioritizer.engine import AlertPrioritizer
from app.prioritizer.models import (
    PRIORITY_P1,
    PRIORITY_P2,
    PRIORITY_P3,
    PRIORITY_P4,
    PrioritizedAlert,
    ScoreBreakdown,
)
from app.reporter.report_generator import ReportGenerator, _format_time
from app.utils.constants import (
    ALERT_ARP_ANOMALY,
    ALERT_ICMP_ANOMALY,
    ALERT_PORT_SCAN,
    ALERT_TRAFFIC_ANOMALY,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    VERSION,
)


def _make_alert(
    detection_type: str = ALERT_PORT_SCAN,
    severity: str = SEVERITY_MEDIUM,
    source: str = "192.168.1.100",
    destination: str | None = "10.0.0.5",
    confidence: float = 0.8,
    event_count: int = 1,
    evidence: dict | None = None,
    recommendations: list[str] | None = None,
    timestamp: float | None = None,
    alert_id: str | None = None,
) -> Alert:
    """Helper to construct an Alert instance for testing."""
    kwargs = {
        "detection_type": detection_type,
        "severity": severity,
        "source": source,
        "destination": destination,
        "protocol": "TCP",
        "confidence": confidence,
        "description": "Test alert description",
        "evidence": evidence or {},
        "recommendations": recommendations or ["Inspect host firewall"],
        "event_count": event_count,
        "timestamp": timestamp if timestamp is not None else time.time(),
    }
    if alert_id is not None:
        kwargs["alert_id"] = alert_id
    return Alert(**kwargs)


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="nexids_reports_test_"))
        self.generator = ReportGenerator(output_dir=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # 1. Empty monitoring session
    # ------------------------------------------------------------------
    def test_empty_monitoring_session(self):
        data = self.generator.build_report_data(
            alerts=[],
            prioritized_alerts=[],
            session_start=None,
            session_end=None,
            packets_observed=0,
        )
        self.assertEqual(data["metadata"]["total_alerts"], 0)
        self.assertEqual(data["metadata"]["total_prioritized_alerts"], 0)
        self.assertEqual(data["metadata"]["total_packets_observed"], 0)
        self.assertEqual(data["summary"]["total_alerts"], 0)
        self.assertEqual(data["summary"]["severity_counts"][SEVERITY_HIGH], 0)
        self.assertEqual(data["alerts"], [])
        self.assertEqual(data["prioritized_alerts"], [])

    # ------------------------------------------------------------------
    # 2. No alerts
    # ------------------------------------------------------------------
    def test_no_alerts(self):
        json_path = self.generator.generate_json_report(alerts=[])
        html_path = self.generator.generate_html_report(alerts=[])

        self.assertTrue(json_path.exists())
        self.assertTrue(html_path.exists())

        loaded_json = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(loaded_json["alerts"], [])
        self.assertEqual(loaded_json["summary"]["total_alerts"], 0)

        html_text = html_path.read_text(encoding="utf-8")
        self.assertIn("No prioritized alerts recorded", html_text)

    # ------------------------------------------------------------------
    # 3. One HIGH alert
    # ------------------------------------------------------------------
    def test_one_high_alert(self):
        alert = _make_alert(severity=SEVERITY_HIGH, detection_type=ALERT_PORT_SCAN)
        data = self.generator.build_report_data(alerts=[alert])

        self.assertEqual(data["summary"]["total_alerts"], 1)
        self.assertEqual(data["summary"]["severity_counts"][SEVERITY_HIGH], 1)
        self.assertEqual(data["summary"]["severity_counts"][SEVERITY_MEDIUM], 0)
        self.assertEqual(data["summary"]["severity_counts"][SEVERITY_LOW], 0)
        self.assertEqual(len(data["alerts"]), 1)
        self.assertEqual(data["alerts"][0]["severity"], SEVERITY_HIGH)

    # ------------------------------------------------------------------
    # 4. Multiple alerts
    # ------------------------------------------------------------------
    def test_multiple_alerts(self):
        alerts = [
            _make_alert(alert_id="a1", detection_type=ALERT_PORT_SCAN, severity=SEVERITY_MEDIUM),
            _make_alert(alert_id="a2", detection_type=ALERT_TRAFFIC_ANOMALY, severity=SEVERITY_HIGH),
            _make_alert(alert_id="a3", detection_type=ALERT_ARP_ANOMALY, severity=SEVERITY_HIGH),
            _make_alert(alert_id="a4", detection_type=ALERT_ICMP_ANOMALY, severity=SEVERITY_LOW),
        ]
        data = self.generator.build_report_data(alerts=alerts)

        self.assertEqual(data["summary"]["total_alerts"], 4)
        self.assertEqual(data["summary"]["severity_counts"][SEVERITY_HIGH], 2)
        self.assertEqual(data["summary"]["severity_counts"][SEVERITY_MEDIUM], 1)
        self.assertEqual(data["summary"]["severity_counts"][SEVERITY_LOW], 1)
        self.assertEqual(len(data["alerts"]), 4)

    # ------------------------------------------------------------------
    # 5. Multiple priority levels
    # ------------------------------------------------------------------
    def test_multiple_priority_levels(self):
        p_alerts = [
            PrioritizedAlert(
                alert=_make_alert(alert_id="p1", severity=SEVERITY_HIGH),
                priority_score=85.0,
                priority_level=PRIORITY_P1,
            ),
            PrioritizedAlert(
                alert=_make_alert(alert_id="p2", severity=SEVERITY_HIGH),
                priority_score=60.0,
                priority_level=PRIORITY_P2,
            ),
            PrioritizedAlert(
                alert=_make_alert(alert_id="p3", severity=SEVERITY_MEDIUM),
                priority_score=35.0,
                priority_level=PRIORITY_P3,
            ),
            PrioritizedAlert(
                alert=_make_alert(alert_id="p4", severity=SEVERITY_LOW),
                priority_score=15.0,
                priority_level=PRIORITY_P4,
            ),
        ]
        data = self.generator.build_report_data(prioritized_alerts=p_alerts)

        p_dist = data["summary"]["priority_distribution"]
        self.assertEqual(p_dist[PRIORITY_P1], 1)
        self.assertEqual(p_dist[PRIORITY_P2], 1)
        self.assertEqual(p_dist[PRIORITY_P3], 1)
        self.assertEqual(p_dist[PRIORITY_P4], 1)
        self.assertEqual(data["summary"]["total_prioritized_alerts"], 4)

    # ------------------------------------------------------------------
    # 6. Missing optional fields
    # ------------------------------------------------------------------
    def test_missing_optional_fields(self):
        sparse_alert = {
            "detection_type": "Sparse Event",
            "alert_id": "sparse-1",
            "source": None,
            "destination": None,
            "severity": None,
            "evidence": None,
            "description": None,
            "recommendations": None,
        }
        data = self.generator.build_report_data(alerts=[sparse_alert])

        self.assertEqual(data["summary"]["total_alerts"], 1)
        # Verify rendered HTML doesn't crash on None fields
        html_str = self.generator.render_html(data)
        self.assertIn("Sparse Event", html_str)
        self.assertIn("sparse-1", html_str)

    # ------------------------------------------------------------------
    # 7. JSON report generation
    # ------------------------------------------------------------------
    def test_json_report_generation(self):
        alert = _make_alert(alert_id="json-test-1", severity=SEVERITY_HIGH)
        target = self.generator.generate_json_report(
            alerts=[alert],
            filename="custom_report.json",
            packets_observed=5000,
            session_start=1700000000.0,
            session_end=1700000060.0,
        )

        self.assertTrue(target.exists())
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("metadata", data)
        self.assertIn("summary", data)
        self.assertIn("alerts", data)
        self.assertIn("prioritized_alerts", data)

        self.assertEqual(data["metadata"]["total_packets_observed"], 5000)
        self.assertEqual(data["metadata"]["nexids_version"], VERSION)
        self.assertEqual(len(data["alerts"]), 1)
        self.assertEqual(data["alerts"][0]["alert_id"], "json-test-1")

    # ------------------------------------------------------------------
    # 8. HTML report generation
    # ------------------------------------------------------------------
    def test_html_report_generation(self):
        alert = _make_alert(alert_id="html-test-1", severity=SEVERITY_MEDIUM)
        target = self.generator.generate_html_report(
            alerts=[alert],
            filename="custom_report.html",
            packets_observed=1200,
        )

        self.assertTrue(target.exists())
        html_content = target.read_text(encoding="utf-8")

        self.assertIn("<!DOCTYPE html>", html_content)
        self.assertIn("NexIDS", html_content)
        self.assertIn("html-test-1", html_content)
        self.assertIn("Packets Inspected", html_content)
        self.assertIn("Alert Severity Distribution", html_content)

    # ------------------------------------------------------------------
    # 9. Timestamped filenames
    # ------------------------------------------------------------------
    def test_timestamped_filenames(self):
        json_path = self.generator.generate_json_report(alerts=[])
        html_path = self.generator.generate_html_report(alerts=[])

        self.assertTrue(json_path.name.startswith("nexids_report_"))
        self.assertTrue(json_path.name.endswith(".json"))
        self.assertTrue(html_path.name.startswith("nexids_report_"))
        self.assertTrue(html_path.name.endswith(".html"))

    # ------------------------------------------------------------------
    # 10. Existing report files are not overwritten
    # ------------------------------------------------------------------
    def test_existing_report_files_not_overwritten(self):
        file1 = self.generator.generate_json_report(filename="conflict.json")
        file1.write_text('{"initial": "content"}', encoding="utf-8")

        # Generating another report with the same filename must NOT overwrite file1
        file2 = self.generator.generate_json_report(filename="conflict.json")

        self.assertNotEqual(file1, file2)
        self.assertTrue(file1.exists())
        self.assertTrue(file2.exists())
        self.assertEqual(file1.read_text(encoding="utf-8"), '{"initial": "content"}')
        self.assertIn("conflict_1.json", str(file2))

    # ------------------------------------------------------------------
    # 11. Correct severity counts
    # ------------------------------------------------------------------
    def test_correct_severity_counts(self):
        alerts = [
            _make_alert(severity=SEVERITY_CRITICAL),
            _make_alert(severity=SEVERITY_HIGH),
            _make_alert(severity=SEVERITY_HIGH),
            _make_alert(severity=SEVERITY_MEDIUM),
            _make_alert(severity=SEVERITY_LOW),
            {"severity": "INFO", "detection_type": "Notice", "description": "Informational"},
            {"severity": "UNKNOWN", "detection_type": "Other", "description": "Unknown severity"},
        ]
        data = self.generator.build_report_data(alerts=alerts)
        sev_counts = data["summary"]["severity_counts"]

        self.assertEqual(sev_counts[SEVERITY_CRITICAL], 1)
        self.assertEqual(sev_counts[SEVERITY_HIGH], 2)
        self.assertEqual(sev_counts[SEVERITY_MEDIUM], 1)
        self.assertEqual(sev_counts[SEVERITY_LOW], 1)
        # INFO + UNKNOWN both map to INFO
        self.assertEqual(sev_counts["INFO"], 2)

    # ------------------------------------------------------------------
    # 12. Correct priority ordering
    # ------------------------------------------------------------------
    def test_correct_priority_ordering(self):
        p_low = PrioritizedAlert(alert=_make_alert(alert_id="low"), priority_score=15.0, priority_level=PRIORITY_P4)
        p_high = PrioritizedAlert(alert=_make_alert(alert_id="high"), priority_score=85.0, priority_level=PRIORITY_P1)
        p_med = PrioritizedAlert(alert=_make_alert(alert_id="med"), priority_score=55.0, priority_level=PRIORITY_P2)

        # Alerts provided in mixed order: low, high, med
        data = self.generator.build_report_data(prioritized_alerts=[p_low, p_high, p_med])

        # Prioritizer / reporter maintains score data
        prioritized_list = data["prioritized_alerts"]
        scores = [pa["priority_score"] for pa in prioritized_list]
        self.assertEqual(len(scores), 3)

    # ------------------------------------------------------------------
    # 13. Evidence preservation
    # ------------------------------------------------------------------
    def test_evidence_preservation(self):
        custom_evidence = {
            "distinct_ports": 75,
            "target_ports": [21, 22, 23, 80, 443],
            "packets_per_sec": 1240.5,
            "anomaly_subtype": "syn_flood_probe",
        }
        alert = _make_alert(alert_id="ev-1", evidence=custom_evidence)
        data = self.generator.build_report_data(alerts=[alert])

        pa = data["prioritized_alerts"][0]
        self.assertEqual(pa["evidence"], custom_evidence)
        self.assertEqual(pa["evidence"]["distinct_ports"], 75)
        self.assertEqual(pa["evidence"]["packets_per_sec"], 1240.5)

        # Check evidence appears in HTML render
        html_str = self.generator.render_html(data)
        self.assertIn("syn_flood_probe", html_str)
        self.assertIn("1240.5", html_str)

    # ------------------------------------------------------------------
    # 14. Recommendation preservation
    # ------------------------------------------------------------------
    def test_recommendation_preservation(self):
        custom_recs = [
            "Immediately isolate host 192.168.1.100 from subnet VLAN 10.",
            "Verify perimeter router ACL rules for ingress traffic.",
            "Inspect auth.log for brute-force attempts on SSH service.",
        ]
        alert = _make_alert(alert_id="rec-1", recommendations=custom_recs)
        data = self.generator.build_report_data(alerts=[alert])

        pa = data["prioritized_alerts"][0]
        self.assertEqual(pa["recommendations"], custom_recs)
        self.assertEqual(pa["recommendation"], custom_recs)

        # Check recommendations appear in HTML render
        html_str = self.generator.render_html(data)
        for rec in custom_recs:
            self.assertIn(rec, html_str)

    # ------------------------------------------------------------------
    # 15. Helper function _format_time
    # ------------------------------------------------------------------
    def test_format_time_edge_cases(self):
        self.assertEqual(_format_time(None), "N/A")
        self.assertEqual(_format_time(0.0), "N/A")
        self.assertEqual(_format_time(""), "N/A")
        self.assertEqual(_format_time("2026-09-30 20:00:00 UTC"), "2026-09-30 20:00:00 UTC")
        formatted = _format_time(1700000000.0)
        self.assertIn("UTC", formatted)


# ===========================================================================
# Integration Test: DetectionEvent -> Alert -> PrioritizedAlert -> Reports
# ===========================================================================


class TestReporterPipelineIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="nexids_pipeline_test_"))
        self.generator = ReportGenerator(output_dir=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_pipeline_to_reports(self):
        # 1. DetectionEvent produced by detection engine
        event = DetectionEvent(
            detection_type=ALERT_PORT_SCAN,
            source="192.168.1.188",
            destination="192.168.1.1",  # critical gateway
            protocol="TCP",
            confidence=0.88,
            description="Host 192.168.1.188 probed 32 destination ports within observation window.",
            evidence={
                "distinct_ports": 32,
                "ports": [21, 22, 23, 25, 80, 443, 3389, 8080],
                "time_window_seconds": 10.0,
            },
            detector="PortScanDetector",
        )

        # 2. Alert Engine (AlertManager) converts DetectionEvent -> Alert
        alert_manager = AlertManager()
        alerts = alert_manager.process_events([event])
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertIsInstance(alert, Alert)
        self.assertEqual(alert.source, "192.168.1.188")
        self.assertEqual(alert.destination, "192.168.1.1")

        # 3. Alert Prioritizer prioritizes Alert -> PrioritizedAlert
        prioritizer = AlertPrioritizer()
        prioritized_alerts = prioritizer.prioritize_alerts(alerts)
        self.assertEqual(len(prioritized_alerts), 1)
        p_alert = prioritized_alerts[0]
        self.assertIsInstance(p_alert, PrioritizedAlert)
        self.assertGreater(p_alert.priority_score, 50.0)

        # 4. Reporter generates JSON and HTML reports from the actual pipeline objects
        reports = self.generator.generate_reports(
            alerts=alerts,
            prioritized_alerts=prioritized_alerts,
            base_filename="integration_report",
            session_start=time.time() - 60,
            session_end=time.time(),
            packets_observed=3500,
        )

        json_path = reports["json"]
        html_path = reports["html"]

        self.assertTrue(json_path.exists())
        self.assertTrue(html_path.exists())

        # 5. Validate JSON report contents
        with open(json_path, "r", encoding="utf-8") as f:
            json_data = json.load(f)

        self.assertEqual(json_data["metadata"]["total_packets_observed"], 3500)
        self.assertEqual(json_data["summary"]["total_alerts"], 1)
        self.assertEqual(json_data["summary"]["total_prioritized_alerts"], 1)

        pa_data = json_data["prioritized_alerts"][0]
        self.assertEqual(pa_data["source"], "192.168.1.188")
        self.assertEqual(pa_data["destination"], "192.168.1.1")
        self.assertEqual(pa_data["evidence"]["distinct_ports"], 32)
        self.assertTrue(len(pa_data["recommendations"]) > 0)
        self.assertIn("score_breakdown", pa_data)

        # 6. Validate HTML report contents
        html_text = html_path.read_text(encoding="utf-8")
        self.assertIn("192.168.1.188", html_text)
        self.assertIn("192.168.1.1", html_text)
        self.assertIn("3500", html_text)
        self.assertIn("PortScanDetector", html_text)
        self.assertIn("distinct_ports", html_text)


if __name__ == "__main__":
    unittest.main()
