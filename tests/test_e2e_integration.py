"""
NexIDS End-to-End Integration & System Hardening Tests (Phase 8)
================================================================
Comprehensive end-to-end integration tests verifying the entire pipeline:
Packet Capture/Parsing -> Detection Engine -> Alert Engine -> Prioritizer ->
Dashboard APIs -> Reporting (JSON & HTML).

Validates:
1. Complete flow from synthetic Scapy packets to final security reports.
2. Cross-stage consistency of alert fields across all components.
3. System error resilience (empty sessions, corrupted packets, missing dirs).
4. Performance under burst traffic loads.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
import unittest

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from app.alert_engine.alert_manager import AlertManager
from app.alert_engine.alert_model import Alert
from app.capture.packet_parser import parse_packet
from app.dashboard.app import create_app
from app.dashboard.service import DashboardService
from app.detection.engine import DetectionEngine
from app.detection.models import DetectionEvent
from app.prioritizer.engine import AlertPrioritizer
from app.prioritizer.models import PrioritizedAlert
from app.reporter.report_generator import ReportGenerator
from app.utils.config import NexIDSConfig, get_config
from app.utils.constants import (
    ALERT_ARP_ANOMALY,
    ALERT_ICMP_ANOMALY,
    ALERT_PORT_SCAN,
    ALERT_TRAFFIC_ANOMALY,
    PRIORITY_P1,
    PRIORITY_P2,
    PRIORITY_P3,
    PRIORITY_P4,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)


class TestEndToEndPipeline(unittest.TestCase):
    """Validates the complete NexIDS defensive pipeline from packets to reports."""

    def setUp(self) -> None:
        self.test_reports_dir = Path("reports_test_e2e")
        self.test_reports_dir.mkdir(parents=True, exist_ok=True)
        self.service = DashboardService(reports_dir=self.test_reports_dir)
        self.app = create_app(service=self.service)
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.service.reset_state()
        if self.test_reports_dir.exists():
            for f in self.test_reports_dir.glob("*"):
                try:
                    f.unlink()
                except OSError:
                    pass
            try:
                self.test_reports_dir.rmdir()
            except OSError:
                pass

    def test_full_pipeline_synthetic_scapy_packets(self) -> None:
        """Stage 1-8: Trace synthetic Scapy packets through detection, alert engine,

        prioritization, dashboard REST API, and final report generation.
        """
        engine = DetectionEngine()
        manager = AlertManager()
        prioritizer = AlertPrioritizer()
        reporter = ReportGenerator(output_dir=self.test_reports_dir)

        # 1. Synthesize Scapy Port Scan (probes to 20 distinct ports from single source)
        now = time.time()
        parsed_packets = []
        for port in range(100, 120):
            pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=50000, dport=port, flags="S")
            parsed = parse_packet(pkt)
            self.assertIsNotNone(parsed)
            parsed["timestamp"] = now
            parsed_packets.append(parsed)

        # 2. Feed packets through Detection Engine -> produce DetectionEvents
        events: list[DetectionEvent] = []
        for p in parsed_packets:
            evts = engine.inspect(p)
            if evts:
                events.extend(evts)

        self.assertGreater(len(events), 0, "DetectionEngine should trigger port scan event")
        self.assertEqual(events[0].detection_type, ALERT_PORT_SCAN)
        self.assertEqual(events[0].source, "192.168.1.100")

        # 3. Alert Engine converts DetectionEvents -> Alert
        alerts = self.service.alert_manager.process_events(events)
        self.assertGreaterEqual(len(alerts), 1, "AlertManager must create at least one alert")
        alert = alerts[0]
        self.assertEqual(alert.detection_type, ALERT_PORT_SCAN)
        self.assertEqual(alert.source, "192.168.1.100")
        self.assertEqual(alert.destination, "192.168.1.1")

        # 4. Prioritizer produces Prioritized Alert
        prioritized = prioritizer.prioritize_alerts(self.service.alert_manager.get_alerts())
        self.assertGreaterEqual(len(prioritized), 1)
        top_pa = prioritized[0]
        self.assertEqual(top_pa.alert_id, alert.alert_id)
        self.assertGreater(top_pa.priority_score, 0.0)
        self.assertIn(top_pa.priority_level, [PRIORITY_P1, PRIORITY_P2, PRIORITY_P3, PRIORITY_P4])

        # 5. Dashboard Service & APIs expose the data consistently
        self.service.packets_inspected = len(parsed_packets)

        # Test GET /api/stats
        stats_resp = self.client.get("/api/stats")
        self.assertEqual(stats_resp.status_code, 200)
        stats_data = stats_resp.get_json()
        self.assertEqual(stats_data["packets_inspected"], 20)
        self.assertEqual(stats_data["total_alerts"], 1)

        # Test GET /api/alerts/priority
        priority_resp = self.client.get("/api/alerts/priority")
        self.assertEqual(priority_resp.status_code, 200)
        p_list = priority_resp.get_json()["prioritized_alerts"]
        self.assertEqual(len(p_list), 1)
        self.assertEqual(p_list[0]["alert_id"], alert.alert_id)
        self.assertEqual(p_list[0]["detection_type"], ALERT_PORT_SCAN)

        # Test GET /api/alerts/<alert_id>
        detail_resp = self.client.get(f"/api/alerts/{alert.alert_id}")
        self.assertEqual(detail_resp.status_code, 200)
        detail_data = detail_resp.get_json()
        self.assertTrue(detail_data["found"])
        self.assertEqual(detail_data["alert"]["source"], "192.168.1.100")

        # 6. Generate JSON Report
        json_path = reporter.generate_json_report(
            alerts=self.service.alert_manager.get_alerts(),
            prioritized_alerts=prioritized,
            packets_observed=len(parsed_packets),
            session_start=now - 10,
            session_end=now,
        )
        self.assertTrue(json_path.exists())
        with open(json_path, encoding="utf-8") as jf:
            report_json = json.load(jf)

        self.assertIn("metadata", report_json)
        self.assertIn("summary", report_json)
        self.assertEqual(report_json["metadata"]["total_packets_observed"], 20)
        self.assertEqual(report_json["metadata"]["total_alerts"], 1)
        self.assertEqual(report_json["alerts"][0]["alert_id"], alert.alert_id)
        self.assertEqual(report_json["prioritized_alerts"][0]["alert_id"], alert.alert_id)

        # 7. Generate HTML Report
        html_path = reporter.generate_html_report(
            alerts=self.service.alert_manager.get_alerts(),
            prioritized_alerts=prioritized,
            packets_observed=len(parsed_packets),
            session_start=now - 10,
            session_end=now,
        )
        self.assertTrue(html_path.exists())
        html_content = html_path.read_text(encoding="utf-8")
        self.assertIn("NexIDS", html_content)
        self.assertIn(alert.alert_id, html_content)
        self.assertIn("Potential Port Scan", html_content)
        self.assertIn("192.168.1.100", html_content)

    def test_cross_component_field_consistency(self) -> None:
        """Section 8: Verify that Dashboard, Alert Engine, Prioritizer, JSON Report,

        and HTML Report represent exactly identical underlying alert values.
        """
        now = time.time()
        test_event = DetectionEvent(
            detection_type=ALERT_ARP_ANOMALY,
            source="192.168.1.99",
            destination="192.168.1.1",
            protocol="ARP",
            confidence=0.91,
            description="Potential ARP Anomaly: duplicate IP binding.",
            evidence={"observed_mac": "00:aa:bb:cc:dd:ee", "original_mac": "11:22:33:44:55:66"},
            detector="ARPAnomalyDetector",
            timestamp=now,
        )

        alerts = self.service.alert_manager.process_events([test_event])
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]

        prioritizer = AlertPrioritizer()
        prioritized = prioritizer.prioritize_alerts(alerts)
        self.assertEqual(len(prioritized), 1)
        pa = prioritized[0]

        detail = self.service.get_alert_by_id(alert.alert_id)
        self.assertIsNotNone(detail)

        # Generate Reports
        reporter = ReportGenerator(output_dir=self.test_reports_dir)
        json_path = reporter.generate_json_report(alerts, prioritized)
        html_path = reporter.generate_html_report(alerts, prioritized)

        with open(json_path, encoding="utf-8") as jf:
            json_data = json.load(jf)

        json_pa = json_data["prioritized_alerts"][0]
        html_text = html_path.read_text(encoding="utf-8")

        # Consistency Assertions
        # 1. Alert Type
        self.assertEqual(alert.detection_type, pa.detection_type)
        self.assertEqual(detail["detection_type"], pa.detection_type)
        self.assertEqual(json_pa["detection_type"], pa.detection_type)
        self.assertIn(alert.detection_type, html_text)

        # 2. Severity
        self.assertEqual(alert.severity, pa.severity)
        self.assertEqual(detail["severity"], pa.severity)
        self.assertEqual(json_pa["severity"], pa.severity)
        self.assertIn(alert.severity, html_text)

        # 3. Source & Destination
        self.assertEqual(alert.source, pa.source)
        self.assertEqual(detail["source"], "192.168.1.99")
        self.assertEqual(json_pa["source"], "192.168.1.99")
        self.assertIn("192.168.1.99", html_text)

        self.assertEqual(alert.destination, pa.destination)
        self.assertEqual(detail["destination"], "192.168.1.1")
        self.assertEqual(json_pa["destination"], "192.168.1.1")
        self.assertIn("192.168.1.1", html_text)

        # 4. Protocol
        self.assertEqual(alert.protocol, pa.protocol)
        self.assertEqual(detail["protocol"], "ARP")
        self.assertEqual(json_pa["protocol"], "ARP")

        # 5. Priority Tier & Score
        self.assertEqual(detail["priority_level"], pa.priority_level)
        self.assertEqual(json_pa["priority_level"], pa.priority_level)
        self.assertEqual(detail["priority_score"], round(pa.priority_score, 2))
        self.assertEqual(json_pa["priority_score"], round(pa.priority_score, 2))


class TestSystemErrorResilience(unittest.TestCase):
    """Section 4: Validates graceful handling of boundary conditions and faults."""

    def setUp(self) -> None:
        self.reports_dir = Path("reports_test_resilience")
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.service = DashboardService(reports_dir=self.reports_dir)
        self.app = create_app(service=self.service)
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.service.reset_state()
        if self.reports_dir.exists():
            for f in self.reports_dir.glob("*"):
                try:
                    f.unlink()
                except OSError:
                    pass
            try:
                self.reports_dir.rmdir()
            except OSError:
                pass

    def test_empty_monitoring_session(self) -> None:
        """Gracefully handle empty session (0 packets, 0 alerts)."""
        stats = self.service.get_stats()
        self.assertEqual(stats["total_alerts"], 0)
        self.assertEqual(stats["packets_inspected"], 0)

        # Generates reports without crashing
        res_json = self.service.generate_report("json")
        self.assertTrue(res_json["success"])
        res_html = self.service.generate_report("html")
        self.assertTrue(res_html["success"])

    def test_malformed_packets_handling(self) -> None:
        """Detection engine and packet parser must discard or safely process corrupt packets."""
        engine = DetectionEngine()
        # Non-packet input
        res1 = parse_packet(None)
        self.assertIsNone(res1)
        res2 = parse_packet("not a scapy packet")
        self.assertIsNone(res2)

        # Empty packet dictionary
        evts = engine.inspect({})
        self.assertEqual(evts, [])

    def test_missing_alert_fields_in_report_generator(self) -> None:
        """Reporter must safely format alerts with missing or None fields."""
        reporter = ReportGenerator(output_dir=self.reports_dir)
        raw_alert = {
            "alert_id": "malformed-1",
            "detection_type": "Unknown Event",
            "severity": None,
            "confidence": None,
            "source": None,
            "destination": None,
            "protocol": None,
            "evidence": None,
            "recommendations": None,
            "first_seen": None,
            "last_seen": None,
        }
        json_path = reporter.generate_json_report(alerts=[raw_alert])
        self.assertTrue(json_path.exists())
        html_path = reporter.generate_html_report(alerts=[raw_alert])
        self.assertTrue(html_path.exists())

    def test_invalid_dashboard_api_requests(self) -> None:
        """API endpoints must return proper error codes without leaking Python stack traces."""
        # Non-existent alert
        resp = self.client.get("/api/alerts/non-existent-id-9999")
        self.assertEqual(resp.status_code, 404)
        data = resp.get_json()
        self.assertFalse(data["found"])
        self.assertIn("error", data)

        # Non-existent report download
        resp_dl = self.client.get("/api/reports/download/non_existent.json")
        self.assertEqual(resp_dl.status_code, 404)

        # Directory traversal attempt
        resp_trav = self.client.get("/api/reports/download/../../etc/passwd")
        self.assertEqual(resp_trav.status_code, 404)

    def test_burst_traffic_sanity_check(self) -> None:
        """Section 16: Verify that a rapid burst of synthetic packets is processed quickly and cleanly."""
        engine = DetectionEngine()
        start = time.time()
        for i in range(1000):
            mock_pkt = {
                "timestamp": start + (i * 0.001),
                "protocol": "TCP",
                "src_ip": f"10.0.0.{i % 20}",
                "dst_ip": "192.168.1.1",
                "src_port": 40000 + i,
                "dst_port": 80,
                "length": 64,
                "flags": "S",
            }
            engine.inspect(mock_pkt)

        elapsed = time.time() - start
        # 1000 packets should be processed in well under 1 second
        self.assertLess(elapsed, 2.0, f"Processing 1000 packets took too long: {elapsed:.2f}s")


class TestConfigurationManagement(unittest.TestCase):
    """Section 2: Validates configuration loading and environment overrides."""

    def test_default_config_values(self) -> None:
        cfg = NexIDSConfig()
        self.assertEqual(cfg.port_scan_threshold, 15)
        self.assertEqual(cfg.icmp_flood_threshold, 50)
        self.assertEqual(cfg.traffic_bytes_threshold, 10_000_000)
        self.assertTrue(cfg.arp_spoof_mac_change)

        d = cfg.to_dict()
        self.assertIn("port_scan_threshold", d)
        self.assertIn("reports_dir", d)

    def test_env_overrides_and_coercion(self) -> None:
        import os
        from app.utils.config import _get_env_bool, _get_env_float, _get_env_int, _get_env_str

        # Safe defaults on non-existent keys
        self.assertEqual(_get_env_str("NON_EXISTENT_KEY_123", "default_val"), "default_val")
        self.assertEqual(_get_env_int("NON_EXISTENT_KEY_123", 42), 42)
        self.assertEqual(_get_env_float("NON_EXISTENT_KEY_123", 3.14), 3.14)
        self.assertFalse(_get_env_bool("NON_EXISTENT_KEY_123", False))

        # Overrides with valid and malformed values
        os.environ["TEST_NEXIDS_INT"] = "99"
        self.assertEqual(_get_env_int("TEST_NEXIDS_INT", 10), 99)
        os.environ["TEST_NEXIDS_INT"] = "invalid_int"
        self.assertEqual(_get_env_int("TEST_NEXIDS_INT", 10), 10)

        os.environ["TEST_NEXIDS_FLOAT"] = "8.75"
        self.assertEqual(_get_env_float("TEST_NEXIDS_FLOAT", 1.0), 8.75)
        os.environ["TEST_NEXIDS_FLOAT"] = "not_a_float"
        self.assertEqual(_get_env_float("TEST_NEXIDS_FLOAT", 1.0), 1.0)

        os.environ["TEST_NEXIDS_BOOL"] = "true"
        self.assertTrue(_get_env_bool("TEST_NEXIDS_BOOL", False))
        os.environ["TEST_NEXIDS_BOOL"] = "0"
        self.assertFalse(_get_env_bool("TEST_NEXIDS_BOOL", True))

        # Cleanup
        for k in ["TEST_NEXIDS_INT", "TEST_NEXIDS_FLOAT", "TEST_NEXIDS_BOOL"]:
            os.environ.pop(k, None)


if __name__ == "__main__":
    unittest.main()

