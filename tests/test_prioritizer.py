"""
NexIDS — Alert Prioritizer Tests (Phase 5)
==========================================
Comprehensive test suite for Phase 5:
* PrioritizationConfig defaults and custom settings
* Rule evaluations: Severity, Confidence, Recurrence, Asset Criticality, Correlation
* Clamping, score calculations, and priority level bands (P1, P2, P3, P4)
* ScoreBreakdown and PrioritizedAlert dataclasses, property forwarding, and comparisons
* Serialization to dict and JSON
* AlertPrioritizer single and batch prioritization
* Filtering utilities: by priority, min level, asset, and score range
* Triage summary metrics and top threats
* End-to-end integration: DetectionEngine -> AlertManager -> AlertPrioritizer
"""

from __future__ import annotations

import json
import time
import unittest

from app.alert_engine.alert_manager import AlertManager
from app.alert_engine.alert_model import Alert
from app.detection.engine import DetectionEngine
from app.detection.models import DetectionEvent
from app.prioritizer import (
    PRIORITY_LABELS,
    PRIORITY_ORDER,
    PRIORITY_P1,
    PRIORITY_P2,
    PRIORITY_P3,
    PRIORITY_P4,
    AlertPrioritizer,
    PrioritizationConfig,
    PrioritizationEngine,
    PrioritizedAlert,
    ScoreBreakdown,
    determine_priority_level,
    evaluate_asset_criticality,
    evaluate_confidence,
    evaluate_correlation,
    evaluate_recurrence,
    evaluate_severity,
    is_critical_asset,
)
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


def _make_alert(
    detection_type: str = ALERT_PORT_SCAN,
    severity: str = SEVERITY_MEDIUM,
    source: str = "192.168.1.100",
    destination: str | None = "10.0.0.5",
    confidence: float = 0.8,
    event_count: int = 1,
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
        "description": "Test alert",
        "event_count": event_count,
        "timestamp": timestamp if timestamp is not None else time.time(),
    }
    if alert_id is not None:
        kwargs["alert_id"] = alert_id
    return Alert(**kwargs)


# ===========================================================================
# 1. PrioritizationConfig Tests
# ===========================================================================


class TestPrioritizationConfig(unittest.TestCase):
    def test_default_config(self):
        cfg = PrioritizationConfig()
        self.assertEqual(cfg.severity_weights[SEVERITY_CRITICAL], 40.0)
        self.assertEqual(cfg.severity_weights[SEVERITY_HIGH], 30.0)
        self.assertEqual(cfg.severity_weights[SEVERITY_MEDIUM], 20.0)
        self.assertEqual(cfg.severity_weights[SEVERITY_LOW], 10.0)
        self.assertEqual(cfg.max_confidence_score, 20.0)
        self.assertEqual(cfg.max_recurrence_score, 15.0)
        self.assertEqual(cfg.max_asset_criticality_score, 15.0)
        self.assertEqual(cfg.max_correlation_score, 10.0)
        self.assertEqual(cfg.p1_threshold, 75.0)
        self.assertEqual(cfg.p2_threshold, 50.0)
        self.assertEqual(cfg.p3_threshold, 25.0)
        self.assertIn("192.168.1.1", cfg.critical_assets)
        self.assertIn("8.8.8.8", cfg.critical_assets)

    def test_custom_config(self):
        cfg = PrioritizationConfig(
            p1_threshold=80.0,
            critical_assets={"10.10.10.10"},
            asset_weights={"10.10.10.10": 12.0},
        )
        self.assertEqual(cfg.p1_threshold, 80.0)
        self.assertIn("10.10.10.10", cfg.critical_assets)
        self.assertEqual(cfg.asset_weights["10.10.10.10"], 12.0)


# ===========================================================================
# 2. Rule Evaluation Tests
# ===========================================================================


class TestRuleEvaluations(unittest.TestCase):
    def setUp(self):
        self.config = PrioritizationConfig()

    def test_evaluate_severity(self):
        alert_crit = _make_alert(severity=SEVERITY_CRITICAL)
        score, reason = evaluate_severity(alert_crit, self.config)
        self.assertEqual(score, 40.0)
        self.assertIn("CRITICAL", reason)

        alert_high = _make_alert(severity=SEVERITY_HIGH)
        score, reason = evaluate_severity(alert_high, self.config)
        self.assertEqual(score, 30.0)

        alert_med = _make_alert(severity=SEVERITY_MEDIUM)
        score, reason = evaluate_severity(alert_med, self.config)
        self.assertEqual(score, 20.0)

        alert_low = _make_alert(severity=SEVERITY_LOW)
        score, reason = evaluate_severity(alert_low, self.config)
        self.assertEqual(score, 10.0)

        # Fallback for unknown severity (Alert.__post_init__ normalises invalid to MEDIUM,
        # but if custom severity is set on the object, prioritizer falls back to 15.0)
        alert_unk = _make_alert()
        alert_unk.severity = "CUSTOM"
        score, _ = evaluate_severity(alert_unk, self.config)
        self.assertEqual(score, 15.0)

    def test_evaluate_confidence(self):
        alert_full = _make_alert(confidence=1.0)
        score, reason = evaluate_confidence(alert_full, self.config)
        self.assertEqual(score, 20.0)
        self.assertIn("1.00", reason)

        alert_half = _make_alert(confidence=0.5)
        score, _ = evaluate_confidence(alert_half, self.config)
        self.assertEqual(score, 10.0)

        alert_zero = _make_alert(confidence=0.0)
        score, _ = evaluate_confidence(alert_zero, self.config)
        self.assertEqual(score, 0.0)

    def test_evaluate_recurrence(self):
        alert_1 = _make_alert(event_count=1)
        score, reason = evaluate_recurrence(alert_1, self.config)
        self.assertEqual(score, 0.0)
        self.assertIsNone(reason)

        alert_2 = _make_alert(event_count=2)
        score, reason = evaluate_recurrence(alert_2, self.config)
        self.assertEqual(score, 5.0)
        self.assertIn("2", reason)

        alert_5 = _make_alert(event_count=5)
        score, reason = evaluate_recurrence(alert_5, self.config)
        self.assertEqual(score, 10.0)

        alert_12 = _make_alert(event_count=12)
        score, reason = evaluate_recurrence(alert_12, self.config)
        self.assertEqual(score, 15.0)

    def test_is_critical_asset(self):
        self.assertTrue(is_critical_asset("192.168.1.1", self.config))
        self.assertTrue(is_critical_asset("10.0.0.1", self.config))
        self.assertTrue(is_critical_asset("192.168.10.254", self.config))  # Suffix .254
        self.assertFalse(is_critical_asset("192.168.1.55", self.config))
        self.assertFalse(is_critical_asset(None, self.config))
        self.assertFalse(is_critical_asset("", self.config))

    def test_evaluate_asset_criticality(self):
        # Destination is critical asset
        alert_dst_crit = _make_alert(destination="192.168.1.1", source="192.168.1.50")
        score, reason = evaluate_asset_criticality(alert_dst_crit, self.config)
        self.assertEqual(score, 15.0)
        self.assertIn("Destination 192.168.1.1", reason)

        # Destination has gateway suffix
        alert_dst_gw = _make_alert(destination="10.50.0.1")
        score, reason = evaluate_asset_criticality(alert_dst_gw, self.config)
        self.assertEqual(score, 15.0)

        # Source is critical asset (e.g. gateway acting abnormal)
        alert_src_crit = _make_alert(destination="192.168.1.50", source="192.168.1.1")
        score, reason = evaluate_asset_criticality(alert_src_crit, self.config)
        self.assertEqual(score, 10.5)
        self.assertIn("Source 192.168.1.1", reason)

        # Custom asset weight
        custom_cfg = PrioritizationConfig(asset_weights={"10.0.0.99": 14.0})
        alert_custom = _make_alert(destination="10.0.0.99")
        score, reason = evaluate_asset_criticality(alert_custom, custom_cfg)
        self.assertEqual(score, 14.0)
        self.assertIn("custom asset criticality", reason)

        # Non-critical host
        alert_non_crit = _make_alert(destination="192.168.1.50", source="192.168.1.60")
        score, reason = evaluate_asset_criticality(alert_non_crit, self.config)
        self.assertEqual(score, 0.0)
        self.assertIsNone(reason)

    def test_evaluate_correlation(self):
        now = time.time()
        alert1 = _make_alert(
            alert_id="a1",
            detection_type=ALERT_PORT_SCAN,
            source="192.168.1.75",
            timestamp=now,
        )
        # Same source, different detection type within 60s
        alert2 = _make_alert(
            alert_id="a2",
            detection_type=ALERT_TRAFFIC_ANOMALY,
            source="192.168.1.75",
            timestamp=now + 10,
        )
        context = [alert1, alert2]

        score, reason = evaluate_correlation(alert1, context, self.config)
        self.assertEqual(score, 7.0)
        self.assertIn("Correlated activity", reason)
        self.assertIn(ALERT_TRAFFIC_ANOMALY, reason)

        # Multi-vector: 2 other distinct detection types
        alert3 = _make_alert(
            alert_id="a3",
            detection_type=ALERT_ARP_ANOMALY,
            source="192.168.1.75",
            timestamp=now + 20,
        )
        context_multi = [alert1, alert2, alert3]
        score, reason = evaluate_correlation(alert1, context_multi, self.config)
        self.assertEqual(score, 10.0)
        self.assertIn("Multi-vector attack chain", reason)

        # Context alert outside time window
        alert_expired = _make_alert(
            alert_id="a_exp",
            detection_type=ALERT_TRAFFIC_ANOMALY,
            source="192.168.1.75",
            timestamp=now + 500,  # exceeds default 300s window
        )
        score, reason = evaluate_correlation(alert1, [alert1, alert_expired], self.config)
        self.assertEqual(score, 0.0)
        self.assertIsNone(reason)


# ===========================================================================
# 3. Priority Level & Clamping Tests
# ===========================================================================


class TestPriorityLevelDetermination(unittest.TestCase):
    def setUp(self):
        self.config = PrioritizationConfig()

    def test_priority_bands(self):
        self.assertEqual(determine_priority_level(100.0, self.config), PRIORITY_P1)
        self.assertEqual(determine_priority_level(75.0, self.config), PRIORITY_P1)
        self.assertEqual(determine_priority_level(74.9, self.config), PRIORITY_P2)
        self.assertEqual(determine_priority_level(50.0, self.config), PRIORITY_P2)
        self.assertEqual(determine_priority_level(49.9, self.config), PRIORITY_P3)
        self.assertEqual(determine_priority_level(25.0, self.config), PRIORITY_P3)
        self.assertEqual(determine_priority_level(24.9, self.config), PRIORITY_P4)
        self.assertEqual(determine_priority_level(0.0, self.config), PRIORITY_P4)


# ===========================================================================
# 4. Models, Dataclasses & Serialisation Tests
# ===========================================================================


class TestPrioritizationModels(unittest.TestCase):
    def test_score_breakdown_dict(self):
        bd = ScoreBreakdown(
            base_severity_score=30.0,
            confidence_score=16.0,
            recurrence_boost=5.0,
            asset_criticality_boost=15.0,
            correlation_boost=7.0,
            total_score=73.0,
            priority_level=PRIORITY_P2,
            reasons=["Reason A", "Reason B"],
        )
        d = bd.to_dict()
        self.assertEqual(d["base_severity_score"], 30.0)
        self.assertEqual(d["total_score"], 73.0)
        self.assertEqual(d["priority_level"], PRIORITY_P2)
        self.assertEqual(len(d["reasons"]), 2)

    def test_prioritized_alert_properties_and_delegation(self):
        base_alert = _make_alert(
            alert_id="test-uuid-1",
            source="192.168.1.10",
            destination="10.0.0.1",
            severity=SEVERITY_HIGH,
            confidence=0.85,
        )
        p_alert = PrioritizedAlert(
            alert=base_alert,
            priority_score=68.5,
            priority_level=PRIORITY_P2,
            reasons=["High severity alert", "Critical destination"],
        )

        # Delegated properties
        self.assertEqual(p_alert.alert_id, "test-uuid-1")
        self.assertEqual(p_alert.source, "192.168.1.10")
        self.assertEqual(p_alert.destination, "10.0.0.1")
        self.assertEqual(p_alert.severity, SEVERITY_HIGH)
        self.assertEqual(p_alert.confidence, 0.85)
        self.assertEqual(p_alert.priority_score, 68.5)
        self.assertEqual(p_alert.priority_level, PRIORITY_P2)
        self.assertEqual(p_alert.priority_label, "P2 (High)")

    def test_prioritized_alert_comparisons(self):
        a1 = PrioritizedAlert(alert=_make_alert(alert_id="1"), priority_score=45.0)
        a2 = PrioritizedAlert(alert=_make_alert(alert_id="2"), priority_score=85.0)
        a3 = PrioritizedAlert(alert=_make_alert(alert_id="3"), priority_score=85.0)

        self.assertTrue(a1 < a2)
        self.assertTrue(a2 > a1)
        self.assertTrue(a1 <= a2)
        self.assertTrue(a2 >= a3)
        self.assertFalse(a1 == a2)

    def test_prioritized_alert_serialisation(self):
        base_alert = _make_alert(alert_id="ser-1")
        p_alert = PrioritizedAlert(
            alert=base_alert,
            priority_score=82.0,
            priority_level=PRIORITY_P1,
            reasons=["Critical severity", "High confidence"],
            score_breakdown=ScoreBreakdown(
                base_severity_score=40.0,
                confidence_score=16.0,
                total_score=82.0,
                priority_level=PRIORITY_P1,
            ),
        )

        d = p_alert.to_dict()
        self.assertEqual(d["alert_id"], "ser-1")
        self.assertEqual(d["priority_score"], 82.0)
        self.assertEqual(d["priority_level"], PRIORITY_P1)
        self.assertEqual(d["priority_label"], "P1 (Critical)")
        self.assertIn("score_breakdown", d)

        # Test to_json produces valid JSON
        j_str = p_alert.to_json()
        parsed = json.loads(j_str)
        self.assertEqual(parsed["alert_id"], "ser-1")
        self.assertEqual(parsed["priority_score"], 82.0)


# ===========================================================================
# 5. AlertPrioritizer Engine Tests
# ===========================================================================


class TestAlertPrioritizer(unittest.TestCase):
    def setUp(self):
        self.prioritizer = AlertPrioritizer()

    def test_prioritize_single_critical_p1_alert(self):
        # High severity (30) + high confidence 1.0 (20) + recurrence 12 (15) + critical dst (15) = 80 -> P1
        alert = _make_alert(
            severity=SEVERITY_HIGH,
            confidence=1.0,
            event_count=12,
            destination="192.168.1.1",  # critical gateway
            source="10.0.0.50",
        )
        p_alert = self.prioritizer.prioritize_alert(alert)

        self.assertEqual(p_alert.priority_level, PRIORITY_P1)
        self.assertGreaterEqual(p_alert.priority_score, 75.0)
        self.assertEqual(p_alert.score_breakdown.base_severity_score, 30.0)
        self.assertEqual(p_alert.score_breakdown.confidence_score, 20.0)
        self.assertEqual(p_alert.score_breakdown.recurrence_boost, 15.0)
        self.assertEqual(p_alert.score_breakdown.asset_criticality_boost, 15.0)
        self.assertGreaterEqual(len(p_alert.reasons), 3)

    def test_prioritize_low_p4_alert(self):
        # Low severity (10) + low confidence 0.2 (4.0) + count 1 (0) + non-critical = 14.0 -> P4
        alert = _make_alert(
            severity=SEVERITY_LOW,
            confidence=0.2,
            event_count=1,
            destination="10.0.0.200",
            source="10.0.0.50",
        )
        p_alert = self.prioritizer.prioritize(alert)

        self.assertEqual(p_alert.priority_level, PRIORITY_P4)
        self.assertLess(p_alert.priority_score, 25.0)

    def test_prioritize_batch_with_correlation(self):
        now = time.time()
        # Source 10.0.0.99 carries out both a Port Scan and an ARP Anomaly within the same window
        alert_scan = _make_alert(
            alert_id="ps-1",
            detection_type=ALERT_PORT_SCAN,
            severity=SEVERITY_MEDIUM,
            confidence=0.8,
            source="10.0.0.99",
            destination="10.0.0.5",
            timestamp=now,
        )
        alert_arp = _make_alert(
            alert_id="arp-1",
            detection_type=ALERT_ARP_ANOMALY,
            severity=SEVERITY_HIGH,
            confidence=0.9,
            source="10.0.0.99",
            destination="10.0.0.5",
            timestamp=now + 5,
        )

        prioritized = self.prioritizer.prioritize_alerts([alert_scan, alert_arp])
        self.assertEqual(len(prioritized), 2)

        # Both alerts should have received correlation boosts (+7.0 pts)
        for pa in prioritized:
            self.assertEqual(pa.score_breakdown.correlation_boost, 7.0)
            self.assertTrue(any("Correlated" in r or "Multi-vector" in r for r in pa.reasons))

        # First alert in sorted batch should be the higher scored alert (ARP High > Port Scan Med)
        self.assertGreaterEqual(prioritized[0].priority_score, prioritized[1].priority_score)
        self.assertEqual(prioritized[0].alert_id, "arp-1")

    def test_empty_alerts_returns_empty_list(self):
        self.assertEqual(self.prioritizer.prioritize_alerts([]), [])

    def test_aliased_class_name(self):
        # Ensure PrioritizationEngine is an alias for AlertPrioritizer
        engine = PrioritizationEngine()
        self.assertIsInstance(engine, AlertPrioritizer)


# ===========================================================================
# 6. Filtering & Triage Utilities Tests
# ===========================================================================


class TestPrioritizerTriageAndFiltering(unittest.TestCase):
    def setUp(self):
        self.prioritizer = AlertPrioritizer()
        self.p_alerts = [
            PrioritizedAlert(
                alert=_make_alert(alert_id="1", source="10.0.0.1", destination="192.168.1.1"),
                priority_score=85.0,
                priority_level=PRIORITY_P1,
            ),
            PrioritizedAlert(
                alert=_make_alert(alert_id="2", source="10.0.0.2", destination="10.0.0.5"),
                priority_score=60.0,
                priority_level=PRIORITY_P2,
            ),
            PrioritizedAlert(
                alert=_make_alert(alert_id="3", source="10.0.0.1", destination="10.0.0.6"),
                priority_score=40.0,
                priority_level=PRIORITY_P3,
            ),
            PrioritizedAlert(
                alert=_make_alert(alert_id="4", source="10.0.0.3", destination="10.0.0.7"),
                priority_score=15.0,
                priority_level=PRIORITY_P4,
            ),
        ]

    def test_filter_by_priority_min_level(self):
        # min_level P2 should return P1 and P2
        res = self.prioritizer.filter_by_priority(self.p_alerts, min_level=PRIORITY_P2)
        self.assertEqual(len(res), 2)
        self.assertTrue(all(a.priority_level in {PRIORITY_P1, PRIORITY_P2} for a in res))

    def test_filter_by_priority_exact_levels(self):
        res = self.prioritizer.filter_by_priority(self.p_alerts, levels=[PRIORITY_P3, PRIORITY_P4])
        self.assertEqual(len(res), 2)
        self.assertEqual({a.priority_level for a in res}, {PRIORITY_P3, PRIORITY_P4})

    def test_filter_by_asset(self):
        # Source 10.0.0.1 appears in alert 1 and alert 3
        res = self.prioritizer.filter_by_asset(self.p_alerts, "10.0.0.1")
        self.assertEqual(len(res), 2)
        self.assertEqual({a.alert_id for a in res}, {"1", "3"})

        # Destination 192.168.1.1 appears in alert 1
        res_dst = self.prioritizer.filter_by_asset(self.p_alerts, "192.168.1.1")
        self.assertEqual(len(res_dst), 1)
        self.assertEqual(res_dst[0].alert_id, "1")

        # Unknown asset returns empty
        res_none = self.prioritizer.filter_by_asset(self.p_alerts, "172.16.99.99")
        self.assertEqual(len(res_none), 0)

    def test_filter_by_score(self):
        res = self.prioritizer.filter_by_score(self.p_alerts, min_score=50.0, max_score=90.0)
        self.assertEqual(len(res), 2)
        self.assertEqual({a.alert_id for a in res}, {"1", "2"})

    def test_get_top_threats(self):
        top_2 = self.prioritizer.get_top_threats(self.p_alerts, limit=2)
        self.assertEqual(len(top_2), 2)
        self.assertEqual(top_2[0].alert_id, "1")  # Score 85.0
        self.assertEqual(top_2[1].alert_id, "2")  # Score 60.0

    def test_get_triage_summary_empty(self):
        summary = self.prioritizer.get_triage_summary([])
        self.assertEqual(summary["total_alerts"], 0)
        self.assertEqual(summary["critical_alert_count"], 0)
        self.assertEqual(summary["top_offenders"], [])
        self.assertIn("No alerts", summary["recommended_action"])

    def test_get_triage_summary_populated(self):
        summary = self.prioritizer.get_triage_summary(self.p_alerts)
        self.assertEqual(summary["total_alerts"], 4)
        self.assertEqual(summary["priority_counts"][PRIORITY_P1], 1)
        self.assertEqual(summary["priority_counts"][PRIORITY_P2], 1)
        self.assertEqual(summary["priority_counts"][PRIORITY_P3], 1)
        self.assertEqual(summary["priority_counts"][PRIORITY_P4], 1)
        self.assertEqual(summary["critical_alert_count"], 1)
        self.assertEqual(summary["max_score"], 85.0)
        self.assertEqual(summary["average_score"], 50.0)
        self.assertIn("URGENT", summary["recommended_action"])

        # Check top offenders (10.0.0.1 has 2 alerts)
        offenders = summary["top_offenders"]
        self.assertGreaterEqual(len(offenders), 1)
        self.assertEqual(offenders[0]["source"], "10.0.0.1")
        self.assertEqual(offenders[0]["alert_count"], 2)


# ===========================================================================
# 7. End-to-End Pipeline Integration: Detection -> Alert -> Prioritization
# ===========================================================================


class TestPrioritizerPipelineIntegration(unittest.TestCase):
    def test_end_to_end_detection_to_prioritizer(self):
        # 1. Create a simulated port scan detection event
        event = DetectionEvent(
            detection_type=ALERT_PORT_SCAN,
            source="192.168.1.150",
            destination="192.168.1.1",  # targeting gateway
            protocol="TCP",
            confidence=0.9,
            description="Host 192.168.1.150 probed 25 destination ports.",
            evidence={"distinct_ports": 25},
            detector="PortScanDetector",
        )

        # 2. Ingest through AlertManager
        alert_manager = AlertManager()
        alerts = alert_manager.process_events([event])
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]

        # 3. Prioritize via AlertPrioritizer
        prioritizer = AlertPrioritizer()
        p_alert = prioritizer.prioritize_alert(alert)

        # Verification
        self.assertEqual(p_alert.source, "192.168.1.150")
        self.assertEqual(p_alert.destination, "192.168.1.1")
        self.assertGreater(p_alert.priority_score, 50.0)  # At least P2 given medium severity + 0.9 conf + gateway target
        self.assertIn(p_alert.priority_level, {PRIORITY_P1, PRIORITY_P2})
        self.assertTrue(len(p_alert.reasons) >= 2)

        # Check summary produces correct report
        summary = prioritizer.get_triage_summary([p_alert])
        self.assertEqual(summary["total_alerts"], 1)
        self.assertEqual(summary["top_offenders"][0]["source"], "192.168.1.150")


if __name__ == "__main__":
    unittest.main()
