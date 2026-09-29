"""
NexIDS — Alert Engine Tests (Phase 4)
======================================
Comprehensive test suite for Phase 4:
* Alert model dataclass, serialization, clamping, and factory methods
* Risk assessment and defensive recommendation enrichment
* Base severity assignment logic
* AlertManager ingestion, confidence filtering, and lifecycle
* Alert aggregation / coalescing and cooldown throttling
* In-memory storage, querying, status updating, and FIFO eviction
* Notification callbacks dispatching
* End-to-end integration from DetectionEngine to AlertManager
"""

from __future__ import annotations

import json
import time
import unittest

from app.alert_engine.alert_manager import AlertEngine, AlertManager
from app.alert_engine.alert_model import (
    STATUS_ACKNOWLEDGED,
    STATUS_NEW,
    STATUS_RESOLVED,
    STATUS_SUPPRESSED,
    Alert,
    determine_base_severity,
    generate_recommendations,
    generate_risk_context,
)
from app.detection.engine import DetectionEngine
from app.detection.models import DetectionEvent
from app.utils.constants import (
    ALERT_ARP_ANOMALY,
    ALERT_ICMP_ANOMALY,
    ALERT_PORT_SCAN,
    ALERT_TRAFFIC_ANOMALY,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)


# ===========================================================================
# Helper factories
# ===========================================================================

def _make_event(
    detection_type: str = ALERT_PORT_SCAN,
    source: str = "192.168.1.50",
    destination: str | None = "10.0.0.1",
    protocol: str = "TCP",
    confidence: float = 0.75,
    evidence: dict | None = None,
    description: str = "Test detection event",
    detector: str = "TestDetector",
    ts: float | None = None,
) -> DetectionEvent:
    return DetectionEvent(
        detection_type=detection_type,
        source=source,
        destination=destination,
        protocol=protocol,
        confidence=confidence,
        evidence=evidence or {"distinct_ports": 20},
        description=description,
        detector=detector,
        timestamp=ts if ts is not None else time.time(),
    )


# ===========================================================================
# 1. Alert Model Tests
# ===========================================================================

class TestAlertModel(unittest.TestCase):
    """Unit tests for the Alert dataclass."""

    def test_default_construction(self):
        alert = Alert(detection_type=ALERT_PORT_SCAN)
        self.assertEqual(alert.detection_type, ALERT_PORT_SCAN)
        self.assertIsNotNone(alert.alert_id)
        self.assertTrue(len(alert.alert_id) > 0)
        self.assertEqual(alert.severity, SEVERITY_MEDIUM)
        self.assertEqual(alert.status, STATUS_NEW)
        self.assertEqual(alert.event_count, 1)
        self.assertAlmostEqual(alert.confidence, 0.5)
        self.assertGreater(alert.timestamp, 0)
        self.assertEqual(alert.first_seen, alert.timestamp)
        self.assertEqual(alert.last_seen, alert.timestamp)

    def test_confidence_clamping(self):
        alert_low = Alert(detection_type=ALERT_PORT_SCAN, confidence=-0.5)
        self.assertEqual(alert_low.confidence, 0.0)

        alert_high = Alert(detection_type=ALERT_PORT_SCAN, confidence=1.8)
        self.assertEqual(alert_high.confidence, 1.0)

    def test_invalid_severity_falls_back(self):
        alert = Alert(detection_type=ALERT_PORT_SCAN, severity="INVALID_SEVERITY")
        self.assertEqual(alert.severity, SEVERITY_MEDIUM)

    def test_invalid_status_falls_back(self):
        alert = Alert(detection_type=ALERT_PORT_SCAN, status="INVALID_STATUS")
        self.assertEqual(alert.status, STATUS_NEW)

    def test_to_dict_and_to_json(self):
        alert = Alert(
            detection_type=ALERT_PORT_SCAN,
            source="10.1.1.1",
            destination="10.1.1.2",
            protocol="TCP",
            confidence=0.85,
            evidence={"distinct_ports": 30},
            description="Probed 30 ports",
            risk_context="Scan observed",
            recommendations=["Check firewall rules"],
        )
        d = alert.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["detection_type"], ALERT_PORT_SCAN)
        self.assertEqual(d["source"], "10.1.1.1")
        self.assertEqual(d["confidence"], 0.85)
        self.assertEqual(d["evidence"]["distinct_ports"], 30)

        json_str = alert.to_json()
        self.assertIsInstance(json_str, str)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["alert_id"], alert.alert_id)
        self.assertEqual(parsed["source"], "10.1.1.1")

    def test_from_dict_roundtrip(self):
        original = Alert(
            detection_type=ALERT_ICMP_ANOMALY,
            source="172.16.0.5",
            severity=SEVERITY_LOW,
            confidence=0.6,
            evidence={"packet_count": 60},
        )
        d = original.to_dict()
        reconstructed = Alert.from_dict(d)
        self.assertEqual(reconstructed.alert_id, original.alert_id)
        self.assertEqual(reconstructed.detection_type, original.detection_type)
        self.assertEqual(reconstructed.source, original.source)
        self.assertEqual(reconstructed.severity, original.severity)
        self.assertEqual(reconstructed.evidence, original.evidence)

    def test_from_detection_event_auto_enrichment(self):
        event = _make_event(
            detection_type=ALERT_PORT_SCAN,
            source="192.168.1.100",
            destination="192.168.1.1",
            evidence={"distinct_ports": 25},
        )
        alert = Alert.from_detection_event(event)
        self.assertEqual(alert.detection_type, ALERT_PORT_SCAN)
        self.assertEqual(alert.source, "192.168.1.100")
        self.assertEqual(alert.destination, "192.168.1.1")
        self.assertEqual(alert.severity, SEVERITY_MEDIUM)
        self.assertTrue(len(alert.risk_context) > 0)
        self.assertTrue(len(alert.recommendations) > 0)
        self.assertIn("firewall", " ".join(alert.recommendations).lower())

    def test_from_detection_event_custom_overrides(self):
        event = _make_event(detection_type=ALERT_PORT_SCAN)
        custom_recs = ["Custom mitigation step 1"]
        alert = Alert.from_detection_event(
            event,
            severity=SEVERITY_CRITICAL,
            risk_context="Custom critical risk assessment",
            recommendations=custom_recs,
            alert_id="custom-id-123",
            status=STATUS_ACKNOWLEDGED,
        )
        self.assertEqual(alert.alert_id, "custom-id-123")
        self.assertEqual(alert.severity, SEVERITY_CRITICAL)
        self.assertEqual(alert.risk_context, "Custom critical risk assessment")
        self.assertEqual(alert.recommendations, custom_recs)
        self.assertEqual(alert.status, STATUS_ACKNOWLEDGED)


# ===========================================================================
# 2. Enrichment & Severity Logic Tests
# ===========================================================================

class TestEnrichmentLogic(unittest.TestCase):
    """Unit tests for risk assessment, recommendations, and base severity."""

    def test_base_severity_arp_mapping_change(self):
        evt = _make_event(
            detection_type=ALERT_ARP_ANOMALY,
            evidence={"subtype": "mapping_change", "old_mac": "aa", "new_mac": "bb"},
        )
        self.assertEqual(determine_base_severity(evt), SEVERITY_HIGH)

    def test_base_severity_arp_flood(self):
        evt = _make_event(
            detection_type=ALERT_ARP_ANOMALY,
            evidence={"subtype": "request_flood", "count": 50},
        )
        self.assertEqual(determine_base_severity(evt), SEVERITY_MEDIUM)

    def test_base_severity_port_scan(self):
        evt_med = _make_event(
            detection_type=ALERT_PORT_SCAN,
            evidence={"distinct_ports": 20},
        )
        self.assertEqual(determine_base_severity(evt_med), SEVERITY_MEDIUM)

        evt_high = _make_event(
            detection_type=ALERT_PORT_SCAN,
            evidence={"distinct_ports": 100},
        )
        self.assertEqual(determine_base_severity(evt_high), SEVERITY_HIGH)

    def test_base_severity_icmp(self):
        evt_flood = _make_event(
            detection_type=ALERT_ICMP_ANOMALY,
            evidence={"pattern": "flood", "packet_count": 80},
        )
        self.assertEqual(determine_base_severity(evt_flood), SEVERITY_LOW)

        evt_recon = _make_event(
            detection_type=ALERT_ICMP_ANOMALY,
            evidence={"pattern": "reconnaissance", "packet_count": 30},
        )
        self.assertEqual(determine_base_severity(evt_recon), SEVERITY_MEDIUM)

    def test_base_severity_traffic_anomaly(self):
        evt_norm = _make_event(
            detection_type=ALERT_TRAFFIC_ANOMALY,
            evidence={"pps": 1500, "bps": 2_000_000},
        )
        self.assertEqual(determine_base_severity(evt_norm), SEVERITY_MEDIUM)

        evt_extreme = _make_event(
            detection_type=ALERT_TRAFFIC_ANOMALY,
            evidence={"pps": 10000, "bps": 100_000_000},
        )
        self.assertEqual(determine_base_severity(evt_extreme), SEVERITY_HIGH)

    def test_risk_context_cautious_phrasing(self):
        for dtype in [
            ALERT_PORT_SCAN,
            ALERT_ICMP_ANOMALY,
            ALERT_ARP_ANOMALY,
            ALERT_TRAFFIC_ANOMALY,
            "UnknownType",
        ]:
            evt = _make_event(detection_type=dtype)
            risk = generate_risk_context(evt)
            self.assertIsInstance(risk, str)
            self.assertTrue(len(risk) > 10)
            # Ensure no unsupported aggressive attack assertions
            self.assertNotIn("confirmed attack", risk.lower())

    def test_recommendations_actionable_list(self):
        for dtype in [
            ALERT_PORT_SCAN,
            ALERT_ICMP_ANOMALY,
            ALERT_ARP_ANOMALY,
            ALERT_TRAFFIC_ANOMALY,
            "UnknownType",
        ]:
            evt = _make_event(detection_type=dtype)
            recs = generate_recommendations(evt)
            self.assertIsInstance(recs, list)
            self.assertGreaterEqual(len(recs), 2)
            for r in recs:
                self.assertIsInstance(r, str)
                self.assertTrue(len(r) > 5)


# ===========================================================================
# 3. AlertManager Core & Lifecycle Tests
# ===========================================================================

class TestAlertManagerCore(unittest.TestCase):
    """Unit tests for AlertManager core functionality."""

    def setUp(self):
        self.manager = AlertManager()

    def test_initial_state(self):
        self.assertEqual(len(self.manager.get_alerts()), 0)
        stats = self.manager.get_statistics()
        self.assertEqual(stats["total_alerts"], 0)
        self.assertEqual(stats["total_events_coalesced"], 0)

    def test_process_invalid_or_none_event(self):
        self.assertIsNone(self.manager.process_event(None))
        self.assertIsNone(self.manager.process_event("not-an-event"))  # type: ignore
        self.assertEqual(len(self.manager.get_alerts()), 0)

    def test_process_single_event(self):
        evt = _make_event(source="10.0.0.99")
        alert = self.manager.process_event(evt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.source, "10.0.0.99")
        self.assertEqual(alert.detection_type, ALERT_PORT_SCAN)
        self.assertEqual(len(self.manager.get_alerts()), 1)

    def test_confidence_threshold_filtering(self):
        strict_mgr = AlertManager(min_confidence=0.8)
        low_conf_evt = _make_event(confidence=0.5)
        high_conf_evt = _make_event(confidence=0.9)

        res_low = strict_mgr.process_event(low_conf_evt)
        self.assertIsNone(res_low)
        self.assertEqual(len(strict_mgr.get_alerts()), 0)

        res_high = strict_mgr.process_event(high_conf_evt)
        self.assertIsNotNone(res_high)
        self.assertEqual(len(strict_mgr.get_alerts()), 1)

    def test_process_events_batch(self):
        events = [
            _make_event(source=f"10.0.0.{i}", detection_type=ALERT_PORT_SCAN)
            for i in range(5)
        ]
        alerts = self.manager.process_events(events)
        self.assertEqual(len(alerts), 5)
        self.assertEqual(len(self.manager.get_alerts()), 5)

    def test_process_events_empty_batch(self):
        self.assertEqual(self.manager.process_events([]), [])

    def test_create_alert_without_storing(self):
        evt = _make_event(source="10.0.0.123")
        alert = self.manager.create_alert(evt)
        self.assertEqual(alert.source, "10.0.0.123")
        self.assertEqual(len(self.manager.get_alerts()), 0)


# ===========================================================================
# 4. Aggregation & Coalescing Tests
# ===========================================================================

class TestAlertAggregation(unittest.TestCase):
    """Tests for alert aggregation, coalescing, and cooldown."""

    def test_coalescing_same_source_and_type(self):
        mgr = AlertManager(enable_aggregation=True, aggregation_window_seconds=10.0)
        now = time.time()

        evt1 = _make_event(
            source="192.168.1.10",
            detection_type=ALERT_PORT_SCAN,
            confidence=0.6,
            evidence={"distinct_ports": 15},
            ts=now,
        )
        evt2 = _make_event(
            source="192.168.1.10",
            detection_type=ALERT_PORT_SCAN,
            confidence=0.8,
            evidence={"distinct_ports": 25},
            ts=now + 2.0,
        )

        alert1 = mgr.process_event(evt1)
        alert2 = mgr.process_event(evt2)

        # Should be coalesced into a single stored alert
        self.assertEqual(alert1.alert_id, alert2.alert_id)
        self.assertEqual(len(mgr.get_alerts()), 1)
        self.assertEqual(alert1.event_count, 2)
        self.assertEqual(alert1.confidence, 0.8)
        self.assertEqual(alert1.evidence["distinct_ports"], 25)
        self.assertEqual(alert1.first_seen, now)
        self.assertEqual(alert1.last_seen, now + 2.0)

    def test_different_sources_not_coalesced(self):
        mgr = AlertManager(enable_aggregation=True)
        evt1 = _make_event(source="192.168.1.10", detection_type=ALERT_PORT_SCAN)
        evt2 = _make_event(source="192.168.1.20", detection_type=ALERT_PORT_SCAN)

        mgr.process_event(evt1)
        mgr.process_event(evt2)

        self.assertEqual(len(mgr.get_alerts()), 2)

    def test_different_detection_types_not_coalesced(self):
        mgr = AlertManager(enable_aggregation=True)
        evt1 = _make_event(source="192.168.1.10", detection_type=ALERT_PORT_SCAN)
        evt2 = _make_event(source="192.168.1.10", detection_type=ALERT_ICMP_ANOMALY)

        mgr.process_event(evt1)
        mgr.process_event(evt2)

        self.assertEqual(len(mgr.get_alerts()), 2)

    def test_aggregation_disabled(self):
        mgr = AlertManager(enable_aggregation=False)
        evt1 = _make_event(source="192.168.1.10", detection_type=ALERT_PORT_SCAN)
        evt2 = _make_event(source="192.168.1.10", detection_type=ALERT_PORT_SCAN)

        alert1 = mgr.process_event(evt1)
        alert2 = mgr.process_event(evt2)

        self.assertNotEqual(alert1.alert_id, alert2.alert_id)
        self.assertEqual(len(mgr.get_alerts()), 2)

    def test_coalescing_outside_window_creates_new_alert(self):
        mgr = AlertManager(
            enable_aggregation=True,
            aggregation_window_seconds=5.0,
            cooldown_seconds=5.0,
        )
        now = time.time()
        evt1 = _make_event(source="192.168.1.10", ts=now)
        evt2 = _make_event(source="192.168.1.10", ts=now + 20.0)

        alert1 = mgr.process_event(evt1)
        alert2 = mgr.process_event(evt2)

        self.assertNotEqual(alert1.alert_id, alert2.alert_id)
        self.assertEqual(len(mgr.get_alerts()), 2)


# ===========================================================================
# 5. Query, Filter, Status & Eviction Tests
# ===========================================================================

class TestAlertStorageAndQuery(unittest.TestCase):
    """Tests for alert retrieval, filtering, status updates, and eviction."""

    def setUp(self):
        self.mgr = AlertManager(enable_aggregation=False)
        self.a1 = self.mgr.process_event(
            _make_event(
                detection_type=ALERT_PORT_SCAN,
                source="10.0.0.1",
                destination="192.168.1.1",
                confidence=0.9,
            )
        )
        self.a2 = self.mgr.process_event(
            _make_event(
                detection_type=ALERT_ICMP_ANOMALY,
                source="10.0.0.2",
                destination="192.168.1.2",
                confidence=0.6,
                evidence={"pattern": "flood"},
            )
        )
        self.a3 = self.mgr.process_event(
            _make_event(
                detection_type=ALERT_ARP_ANOMALY,
                source="10.0.0.1",
                destination=None,
                confidence=0.8,
                evidence={"subtype": "mapping_change"},
            )
        )

    def test_filter_by_severity(self):
        high_alerts = self.mgr.get_alerts(severity=SEVERITY_HIGH)
        self.assertEqual(len(high_alerts), 1)
        self.assertEqual(high_alerts[0].detection_type, ALERT_ARP_ANOMALY)

        low_alerts = self.mgr.get_alerts(severity=SEVERITY_LOW)
        self.assertEqual(len(low_alerts), 1)
        self.assertEqual(low_alerts[0].detection_type, ALERT_ICMP_ANOMALY)

    def test_filter_by_detection_type(self):
        ps_alerts = self.mgr.get_alerts(detection_type=ALERT_PORT_SCAN)
        self.assertEqual(len(ps_alerts), 1)
        self.assertEqual(ps_alerts[0].source, "10.0.0.1")

    def test_filter_by_source(self):
        src_alerts = self.mgr.get_alerts(source="10.0.0.1")
        self.assertEqual(len(src_alerts), 2)

    def test_filter_by_destination(self):
        dst_alerts = self.mgr.get_alerts(destination="192.168.1.2")
        self.assertEqual(len(dst_alerts), 1)
        self.assertEqual(dst_alerts[0].alert_id, self.a2.alert_id)

    def test_filter_by_min_confidence(self):
        high_conf = self.mgr.get_alerts(min_confidence=0.75)
        self.assertEqual(len(high_conf), 2)

    def test_query_limit(self):
        limited = self.mgr.get_alerts(limit=2)
        self.assertEqual(len(limited), 2)
        self.assertEqual(limited[-1].alert_id, self.a3.alert_id)

    def test_get_alert_by_id(self):
        found = self.mgr.get_alert_by_id(self.a1.alert_id)
        self.assertIsNotNone(found)
        self.assertEqual(found.alert_id, self.a1.alert_id)

        not_found = self.mgr.get_alert_by_id("non-existent-id")
        self.assertIsNone(not_found)

    def test_update_alert_status(self):
        ok = self.mgr.update_alert_status(self.a1.alert_id, STATUS_ACKNOWLEDGED)
        self.assertTrue(ok)
        self.assertEqual(self.a1.status, STATUS_ACKNOWLEDGED)

        # Invalid status
        bad_status = self.mgr.update_alert_status(self.a1.alert_id, "BAD_STATUS")
        self.assertFalse(bad_status)

        # Non-existent ID
        missing_id = self.mgr.update_alert_status("missing-id", STATUS_RESOLVED)
        self.assertFalse(missing_id)

    def test_fifo_eviction(self):
        small_mgr = AlertManager(max_stored_alerts=3, enable_aggregation=False)
        alerts = []
        for i in range(5):
            evt = _make_event(source=f"10.0.0.{i}")
            alerts.append(small_mgr.process_event(evt))

        stored = small_mgr.get_alerts()
        self.assertEqual(len(stored), 3)
        # Oldest 2 (index 0, 1) should be evicted
        self.assertIsNone(small_mgr.get_alert_by_id(alerts[0].alert_id))
        self.assertIsNone(small_mgr.get_alert_by_id(alerts[1].alert_id))
        self.assertIsNotNone(small_mgr.get_alert_by_id(alerts[4].alert_id))

    def test_statistics_breakdown(self):
        stats = self.mgr.get_statistics()
        self.assertEqual(stats["total_alerts"], 3)
        self.assertEqual(stats["unique_sources_count"], 2)
        self.assertEqual(stats["by_severity"][SEVERITY_HIGH], 1)
        self.assertEqual(stats["by_severity"][SEVERITY_MEDIUM], 1)
        self.assertEqual(stats["by_severity"][SEVERITY_LOW], 1)
        self.assertEqual(stats["by_detection_type"][ALERT_PORT_SCAN], 1)

    def test_clear_and_reset(self):
        self.mgr.clear()
        self.assertEqual(len(self.mgr.get_alerts()), 0)
        self.assertEqual(self.mgr.get_statistics()["total_alerts"], 0)


# ===========================================================================
# 6. Callback & Notification Tests
# ===========================================================================

class TestAlertCallbacks(unittest.TestCase):
    """Tests for AlertManager callback registration and dispatching."""

    def test_callback_invoked_on_new_alert(self):
        mgr = AlertManager(enable_aggregation=False)
        received_alerts: list[Alert] = []

        def my_callback(alert: Alert):
            received_alerts.append(alert)

        mgr.register_callback(my_callback)
        evt = _make_event(source="10.20.30.40")
        created = mgr.process_event(evt)

        self.assertEqual(len(received_alerts), 1)
        self.assertEqual(received_alerts[0].alert_id, created.alert_id)

    def test_unregister_callback(self):
        mgr = AlertManager(enable_aggregation=False)
        received: list[Alert] = []

        def cb(alert: Alert):
            received.append(alert)

        mgr.register_callback(cb)
        mgr.process_event(_make_event())
        self.assertEqual(len(received), 1)

        mgr.unregister_callback(cb)
        mgr.process_event(_make_event(source="1.2.3.4"))
        self.assertEqual(len(received), 1)  # unchanged

    def test_callback_exception_does_not_crash(self):
        mgr = AlertManager(enable_aggregation=False)

        def failing_cb(alert: Alert):
            raise RuntimeError("Callback boom!")

        mgr.register_callback(failing_cb)
        # Should not raise exception
        alert = mgr.process_event(_make_event())
        self.assertIsNotNone(alert)


# ===========================================================================
# 7. End-to-End Integration (DetectionEngine -> AlertManager)
# ===========================================================================

class TestEndToEndDetectionToAlert(unittest.TestCase):
    """Integration tests verifying flow from synthetic packets to DetectionEngine to AlertManager."""

    def setUp(self):
        self.detection_engine = DetectionEngine(
            port_scan_threshold=5,
            port_scan_window=10.0,
            icmp_threshold=5,
            icmp_window=10.0,
        )
        self.alert_manager = AlertManager()

    def _tcp_packet(self, src="192.168.1.100", dst="10.0.0.1", port=80, ts=None):
        return {
            "timestamp": ts or time.time(),
            "protocol": "TCP",
            "src_ip": src,
            "dst_ip": dst,
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "dst_mac": "11:22:33:44:55:66",
            "src_port": 50000,
            "dst_port": port,
            "length": 60,
            "flags": "S",
            "ttl": 64,
            "icmp_type": None,
            "icmp_code": None,
            "arp_op": None,
            "arp_psrc": None,
            "arp_pdst": None,
            "arp_hwsrc": None,
            "arp_hwdst": None,
            "raw": False,
        }

    def _arp_packet(self, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01", op=2):
        return {
            "timestamp": time.time(),
            "protocol": "ARP",
            "src_ip": None,
            "dst_ip": None,
            "src_mac": hwsrc,
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_port": None,
            "dst_port": None,
            "length": 42,
            "flags": "",
            "ttl": None,
            "icmp_type": None,
            "icmp_code": None,
            "arp_op": op,
            "arp_psrc": psrc,
            "arp_pdst": "192.168.1.100",
            "arp_hwsrc": hwsrc,
            "arp_hwdst": "ff:ff:ff:ff:ff:ff",
            "raw": False,
        }

    def test_port_scan_packets_trigger_alert(self):
        # Send 6 distinct destination ports from single source (threshold = 5)
        packets = [
            self._tcp_packet(src="192.168.1.50", port=p)
            for p in [21, 22, 80, 443, 8080, 8443]
        ]
        alerts = self.alert_manager.process_packets(packets, self.detection_engine)

        self.assertGreaterEqual(len(alerts), 1)
        ps_alert = alerts[0]
        self.assertEqual(ps_alert.detection_type, ALERT_PORT_SCAN)
        self.assertEqual(ps_alert.source, "192.168.1.50")
        self.assertIn("distinct_ports", ps_alert.evidence)
        self.assertGreaterEqual(ps_alert.evidence["distinct_ports"], 5)
        self.assertTrue(len(ps_alert.risk_context) > 0)
        self.assertTrue(len(ps_alert.recommendations) > 0)

    def test_arp_spoof_packets_trigger_alert(self):
        # Register initial mapping
        p1 = self._arp_packet(psrc="192.168.1.1", hwsrc="11:11:11:11:11:11")
        self.alert_manager.process_packet(p1, self.detection_engine)

        # Alter mapping (spoof simulation)
        p2 = self._arp_packet(psrc="192.168.1.1", hwsrc="22:22:22:22:22:22")
        alerts = self.alert_manager.process_packet(p2, self.detection_engine)

        self.assertEqual(len(alerts), 1)
        arp_alert = alerts[0]
        self.assertEqual(arp_alert.detection_type, ALERT_ARP_ANOMALY)
        self.assertEqual(arp_alert.severity, SEVERITY_HIGH)
        self.assertEqual(arp_alert.evidence["subtype"], "mapping_change")
        self.assertEqual(arp_alert.evidence["old_mac"], "11:11:11:11:11:11")
        self.assertEqual(arp_alert.evidence["new_mac"], "22:22:22:22:22:22")


if __name__ == "__main__":
    unittest.main()
