"""
NexIDS — Dashboard & Frontend Integration Tests (Phase 7)
=========================================================
Comprehensive test suite verifying:
* Dashboard UI route loading (GET /)
* API status endpoint (GET /api/status)
* API stats endpoint (GET /api/stats)
* API alerts list (GET /api/alerts)
* API prioritized alerts list (GET /api/alerts/priority)
* Alert detail endpoint (GET /api/alerts/<alert_id>)
* Empty alert state handling
* Monitoring start & stop endpoints
* Demo mode data injection
* JSON report generation via API
* HTML report generation via API
* Report file download security
* Safe API error handling (404, bad IDs)
* Robustness against missing fields
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from app.alert_engine.alert_model import Alert
from app.dashboard.app import create_app
from app.dashboard.service import DashboardService
from app.detection.models import DetectionEvent
from app.utils.constants import (
    ALERT_ARP_ANOMALY,
    ALERT_PORT_SCAN,
    PRIORITY_P1,
    PRIORITY_P2,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)


class TestDashboardIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="nexids_dash_test_"))
        self.service = DashboardService(reports_dir=self.temp_dir)
        self.app = create_app(service=self.service, test_config={"TESTING": True})
        self.client = self.app.test_client()

    def tearDown(self):
        self.service.stop_monitoring()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # 1. Dashboard UI loads
    # ------------------------------------------------------------------
    def test_dashboard_ui_loads(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html_text = res.get_data(as_text=True)
        self.assertIn("NexIDS", html_text)
        self.assertIn("Packets Inspected", html_text)
        self.assertIn("Prioritized Security Incidents", html_text)
        self.assertIn("Start Monitoring", html_text)

    # ------------------------------------------------------------------
    # 2. /api/status works
    # ------------------------------------------------------------------
    def test_api_status(self):
        res = self.client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("is_running", data)
        self.assertIn("is_demo_mode", data)
        self.assertIn("status_message", data)
        self.assertIn("version", data)
        self.assertFalse(data["is_running"])

    # ------------------------------------------------------------------
    # 3. /api/stats works
    # ------------------------------------------------------------------
    def test_api_stats(self):
        res = self.client.get("/api/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("packets_inspected", data)
        self.assertIn("total_alerts", data)
        self.assertIn("severity_counts", data)
        self.assertIn("priority_distribution", data)
        self.assertEqual(data["total_alerts"], 0)

    # ------------------------------------------------------------------
    # 4. /api/alerts works
    # ------------------------------------------------------------------
    def test_api_alerts(self):
        res = self.client.get("/api/alerts")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("alerts", data)
        self.assertIn("count", data)
        self.assertEqual(data["count"], 0)

    # ------------------------------------------------------------------
    # 5. /api/alerts/priority works
    # ------------------------------------------------------------------
    def test_api_alerts_priority(self):
        res = self.client.get("/api/alerts/priority")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("prioritized_alerts", data)
        self.assertIn("count", data)
        self.assertEqual(data["count"], 0)

    # ------------------------------------------------------------------
    # 6. Alert detail works
    # ------------------------------------------------------------------
    def test_api_alert_detail(self):
        # Inject an alert into the alert manager
        event = DetectionEvent(
            detection_type=ALERT_PORT_SCAN,
            source="192.168.1.100",
            destination="192.168.1.1",
            protocol="TCP",
            confidence=0.85,
            description="Host 192.168.1.100 probed ports.",
            evidence={"distinct_ports": 20},
            detector="PortScanDetector",
        )
        alerts = self.service.alert_manager.process_events([event])
        alert_id = alerts[0].alert_id

        # Query detail endpoint
        res = self.client.get(f"/api/alerts/{alert_id}")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["found"])
        alert = data["alert"]
        self.assertEqual(alert["alert_id"], alert_id)
        self.assertEqual(alert["source"], "192.168.1.100")
        self.assertIn("score_breakdown", alert)
        self.assertIn("recommendations", alert)

    # ------------------------------------------------------------------
    # 7. Empty alert state works
    # ------------------------------------------------------------------
    def test_empty_alert_state(self):
        res_alerts = self.client.get("/api/alerts")
        res_priority = self.client.get("/api/alerts/priority")
        self.assertEqual(res_alerts.get_json()["alerts"], [])
        self.assertEqual(res_priority.get_json()["prioritized_alerts"], [])

    # ------------------------------------------------------------------
    # 8. Monitoring start works
    # ------------------------------------------------------------------
    def test_monitoring_start(self):
        res = self.client.post("/api/monitor/start", json={"demo": True})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["is_running"])

        # Check status reflects running
        status_res = self.client.get("/api/status")
        self.assertTrue(status_res.get_json()["is_running"])

    # ------------------------------------------------------------------
    # 9. Monitoring stop works
    # ------------------------------------------------------------------
    def test_monitoring_stop(self):
        self.client.post("/api/monitor/start", json={"demo": True})
        res = self.client.post("/api/monitor/stop")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertFalse(data["is_running"])

        status_res = self.client.get("/api/status")
        self.assertFalse(status_res.get_json()["is_running"])

    # ------------------------------------------------------------------
    # 10. Demo mode works
    # ------------------------------------------------------------------
    def test_demo_mode_data_generation(self):
        res = self.client.post("/api/demo/generate")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["is_demo_mode"])

        # Check stats & prioritized alerts updated
        stats = self.client.get("/api/stats").get_json()
        self.assertGreater(stats["packets_inspected"], 0)
        self.assertGreater(stats["total_alerts"], 0)

        pri_res = self.client.get("/api/alerts/priority").get_json()
        self.assertEqual(pri_res["count"], 4)
        first_alert = pri_res["prioritized_alerts"][0]
        self.assertIn("rank", first_alert)
        self.assertIn("priority_level", first_alert)

    # ------------------------------------------------------------------
    # 11. JSON report generation works
    # ------------------------------------------------------------------
    def test_api_report_json(self):
        self.client.post("/api/demo/generate")
        res = self.client.post("/api/report/json")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("nexids_report_", data["filename"])
        self.assertTrue(data["filename"].endswith(".json"))

        # Verify file exists on disk
        target_file = self.temp_dir / data["filename"]
        self.assertTrue(target_file.exists())
        with open(target_file, "r", encoding="utf-8") as f:
            content = json.load(f)
            self.assertIn("metadata", content)

    # ------------------------------------------------------------------
    # 12. HTML report generation works
    # ------------------------------------------------------------------
    def test_api_report_html(self):
        self.client.post("/api/demo/generate")
        res = self.client.post("/api/report/html")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("nexids_report_", data["filename"])
        self.assertTrue(data["filename"].endswith(".html"))

        target_file = self.temp_dir / data["filename"]
        self.assertTrue(target_file.exists())
        html_str = target_file.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", html_str)

    # ------------------------------------------------------------------
    # 13. API error handling works
    # ------------------------------------------------------------------
    def test_api_error_handling(self):
        # Non-existent alert returns 404 JSON
        res = self.client.get("/api/alerts/nonexistent-id-12345")
        self.assertEqual(res.status_code, 404)
        data = res.get_json()
        self.assertFalse(data["found"])
        self.assertIn("error", data)

        # Non-existent report download returns 404
        res_dl = self.client.get("/api/reports/download/missing_report.json")
        self.assertEqual(res_dl.status_code, 404)

        # Directory traversal attempt returns 404
        res_trav = self.client.get("/api/reports/download/../../etc/passwd")
        self.assertEqual(res_trav.status_code, 404)

    # ------------------------------------------------------------------
    # 14. Missing fields do not crash the UI/API
    # ------------------------------------------------------------------
    def test_missing_fields_robustness(self):
        # Inject an alert with None/missing fields directly into AlertManager
        sparse_alert = Alert(
            detection_type="Sparse Alert",
            source=None,
            destination=None,
            confidence=0.5,
            description="",
            evidence={},
            recommendations=[],
        )
        self.service.alert_manager._alerts.append(sparse_alert)
        self.service.alert_manager._alert_index[sparse_alert.alert_id] = sparse_alert

        res = self.client.get("/api/alerts/priority")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["count"], 1)
        pa = data["prioritized_alerts"][0]
        self.assertEqual(pa["detection_type"], "Sparse Alert")
        self.assertIn(pa["source"], [None, "—"])


if __name__ == "__main__":
    unittest.main()
