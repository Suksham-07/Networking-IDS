"""
NexIDS — Detection Module Tests (Phase 3)
==========================================
All tests use synthetic ``ParsedPacket`` dicts — no live network required.

Coverage
--------
* PortScanDetector   — threshold trigger, normal traffic, edge cases
* ICMPDetector       — threshold trigger, normal traffic, recon pattern
* ARPDetector        — mapping change, request flood, reply flood, stable
* TrafficAnomalyDetector — PPS trigger, BPS trigger, normal traffic
* DetectionEngine    — orchestration, batch, reset
* DetectionEvent     — schema, confidence clamping, to_dict
* Edge cases         — empty input, None fields, non-dict input, malformed
"""

from __future__ import annotations

import time
import unittest

# ---------------------------------------------------------------------------
# Synthetic packet factory
# ---------------------------------------------------------------------------

def _tcp(
    src_ip="192.168.1.10",
    dst_ip="10.0.0.1",
    dst_port=80,
    src_port=54321,
    flags="S",
    length=60,
    ts=None,
):
    return {
        "timestamp": ts if ts is not None else time.time(),
        "protocol": "TCP",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_mac": "aa:bb:cc:dd:ee:ff",
        "dst_mac": "11:22:33:44:55:66",
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "flags": flags,
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


def _udp(src_ip="192.168.1.10", dst_ip="10.0.0.1", dst_port=53, length=60, ts=None):
    p = _tcp(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, length=length, ts=ts)
    p["protocol"] = "UDP"
    p["flags"] = None
    return p


def _icmp(src_ip="192.168.1.10", dst_ip="10.0.0.1", icmp_type=8, icmp_code=0,
          length=64, ts=None):
    return {
        "timestamp": ts if ts is not None else time.time(),
        "protocol": "ICMP",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_mac": "aa:bb:cc:dd:ee:ff",
        "dst_mac": "11:22:33:44:55:66",
        "src_port": None,
        "dst_port": None,
        "length": length,
        "flags": None,
        "ttl": 64,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "arp_op": None,
        "arp_psrc": None,
        "arp_pdst": None,
        "arp_hwsrc": None,
        "arp_hwdst": None,
        "raw": False,
    }


def _arp(src_ip="192.168.1.10", dst_ip="192.168.1.1",
         src_mac="aa:bb:cc:dd:ee:ff", dst_mac="00:00:00:00:00:00",
         arp_op=1, ts=None):
    return {
        "timestamp": ts if ts is not None else time.time(),
        "protocol": "ARP",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "src_port": None,
        "dst_port": None,
        "length": 42,
        "flags": None,
        "ttl": None,
        "icmp_type": None,
        "icmp_code": None,
        "arp_op": arp_op,
        "arp_psrc": src_ip,
        "arp_pdst": dst_ip,
        "arp_hwsrc": src_mac,
        "arp_hwdst": dst_mac,
        "raw": False,
    }


# ---------------------------------------------------------------------------
# Helper: build a burst of packets within a 1-second window
# ---------------------------------------------------------------------------
def _port_scan_packets(src_ip, ports, base_ts=1000.0, spacing=0.3):
    """Return TCP packets from src_ip to each port, spread within window."""
    return [_tcp(src_ip=src_ip, dst_port=p, ts=base_ts + i * spacing)
            for i, p in enumerate(ports)]


# ---------------------------------------------------------------------------
# DetectionEvent model tests
# ---------------------------------------------------------------------------

class TestDetectionEvent(unittest.TestCase):

    def test_defaults_set(self):
        from app.detection.models import DetectionEvent
        ev = DetectionEvent(detection_type="Test Event")
        self.assertEqual(ev.detection_type, "Test Event")
        self.assertIsNone(ev.source)
        self.assertIsNone(ev.destination)
        self.assertEqual(ev.protocol, "UNKNOWN")
        self.assertEqual(ev.evidence, {})
        self.assertEqual(ev.confidence, 0.5)
        self.assertGreater(ev.timestamp, 0)

    def test_confidence_clamped_above_one(self):
        from app.detection.models import DetectionEvent
        ev = DetectionEvent(detection_type="T", confidence=5.0)
        self.assertLessEqual(ev.confidence, 1.0)

    def test_confidence_clamped_below_zero(self):
        from app.detection.models import DetectionEvent
        ev = DetectionEvent(detection_type="T", confidence=-1.0)
        self.assertGreaterEqual(ev.confidence, 0.0)

    def test_to_dict_returns_all_fields(self):
        from app.detection.models import DetectionEvent
        ev = DetectionEvent(
            detection_type="Potential Port Scan",
            source="1.2.3.4",
            evidence={"ports": [22, 80]},
        )
        d = ev.to_dict()
        self.assertIn("detection_type", d)
        self.assertIn("source", d)
        self.assertIn("evidence", d)
        self.assertIn("confidence", d)
        self.assertIn("timestamp", d)

    def test_evidence_dict_preserved(self):
        from app.detection.models import DetectionEvent
        ev = DetectionEvent(detection_type="T", evidence={"key": "value", "count": 42})
        self.assertEqual(ev.evidence["count"], 42)


# ---------------------------------------------------------------------------
# Port Scan Detector tests
# ---------------------------------------------------------------------------

class TestPortScanDetector(unittest.TestCase):

    def _det(self, threshold=5, window=10.0):
        from app.detection.port_scan import PortScanDetector
        return PortScanDetector(threshold=threshold, window_seconds=window)

    def _run_scan(self, det, ports, src="10.0.0.1", base_ts=1000.0, spacing=0.3):
        """Feed packets for each port; collect any triggered events."""
        events = []
        for i, port in enumerate(ports):
            ev = det.inspect(_tcp(src_ip=src, dst_port=port, ts=base_ts + i * spacing))
            if ev:
                events.append(ev)
        return events

    def test_threshold_triggered(self):
        """Scanning many distinct ports triggers an event."""
        det = self._det(threshold=5)
        events = self._run_scan(det, range(80, 92))   # 12 distinct ports
        self.assertGreaterEqual(len(events), 1)

    def test_normal_traffic_no_trigger(self):
        """Repeated connections to only 2 ports do not trigger."""
        det = self._det(threshold=15)
        for i in range(30):
            ev = det.inspect(_tcp(dst_port=80 if i % 2 == 0 else 443,
                                   ts=1000.0 + i * 0.2))
            self.assertIsNone(ev)

    def test_different_sources_tracked_independently(self):
        """Two scanners each trigger their own event."""
        det = self._det(threshold=5)
        triggered = set()
        for port in range(1, 10):
            for src in ("10.0.0.1", "10.0.0.2"):
                ev = det.inspect(_tcp(src_ip=src, dst_port=port,
                                       ts=1000.0 + port * 0.3))
                if ev:
                    triggered.add(ev.source)
        self.assertIn("10.0.0.1", triggered)
        self.assertIn("10.0.0.2", triggered)

    def test_non_tcp_udp_ignored(self):
        """ICMP packets are not counted towards port scan."""
        det = self._det(threshold=5)
        for _ in range(20):
            ev = det.inspect(_icmp())
            self.assertIsNone(ev)

    def test_event_has_required_evidence(self):
        det = self._det(threshold=3)
        events = self._run_scan(det, [22, 80, 443, 8080])
        self.assertGreaterEqual(len(events), 1)
        ev = events[0]
        self.assertIn("distinct_ports", ev.evidence)
        self.assertIn("ports_sample", ev.evidence)
        self.assertIn("threshold", ev.evidence)
        self.assertIn("window_seconds", ev.evidence)

    def test_event_detection_type(self):
        det = self._det(threshold=3)
        events = self._run_scan(det, [22, 80, 443, 8080])
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0].detection_type, "Potential Port Scan")

    def test_event_source_matches_scanner(self):
        det = self._det(threshold=3)
        src = "5.6.7.8"
        events = self._run_scan(det, [21, 22, 23, 25], src=src)
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0].source, src)

    def test_empty_input_batch(self):
        from app.detection.port_scan import PortScanDetector
        det = PortScanDetector()
        self.assertEqual(det.inspect_batch([]), [])

    def test_none_packet_ignored(self):
        from app.detection.port_scan import PortScanDetector
        det = PortScanDetector()
        self.assertIsNone(det.inspect(None))  # type: ignore

    def test_missing_src_ip_ignored(self):
        from app.detection.port_scan import PortScanDetector
        det = PortScanDetector(threshold=3)
        pkt = _tcp(dst_port=80)
        pkt["src_ip"] = None
        self.assertIsNone(det.inspect(pkt))

    def test_missing_dst_port_ignored(self):
        from app.detection.port_scan import PortScanDetector
        det = PortScanDetector(threshold=3)
        pkt = _tcp()
        pkt["dst_port"] = None
        self.assertIsNone(det.inspect(pkt))

    def test_reset_clears_state(self):
        det = self._det(threshold=3)
        self._run_scan(det, [22, 80, 443])
        det.reset()
        ev = det.inspect(_tcp(dst_port=22, ts=2000.0))
        self.assertIsNone(ev)

    def test_udp_triggers_port_scan(self):
        """UDP packets also contribute to port scan detection."""
        det = self._det(threshold=3)
        events = []
        for i, port in enumerate([53, 123, 161, 500]):
            ev = det.inspect(_udp(dst_port=port, ts=1000.0 + i * 0.3))
            if ev:
                events.append(ev)
        self.assertGreaterEqual(len(events), 1)

    def test_confidence_in_valid_range(self):
        det = self._det(threshold=3)
        events = self._run_scan(det, range(1, 20))
        self.assertGreaterEqual(len(events), 1)
        for ev in events:
            self.assertGreaterEqual(ev.confidence, 0.0)
            self.assertLessEqual(ev.confidence, 1.0)


# ---------------------------------------------------------------------------
# ICMP Detector tests
# ---------------------------------------------------------------------------

class TestICMPDetector(unittest.TestCase):

    def _det(self, threshold=10, window=5.0, recon_threshold=5):
        from app.detection.icmp_detection import ICMPDetector
        return ICMPDetector(threshold=threshold, window_seconds=window,
                            recon_threshold=recon_threshold)

    def test_threshold_triggered(self):
        det = self._det(threshold=5)
        src = "192.168.1.5"
        events = []
        for i in range(10):
            ev = det.inspect(_icmp(src_ip=src, ts=1000.0 + i * 0.1))
            if ev:
                events.append(ev)
        self.assertGreaterEqual(len(events), 1)

    def test_normal_icmp_no_trigger(self):
        det = self._det(threshold=50)
        for i in range(5):
            ev = det.inspect(_icmp(ts=1000.0 + i))
            self.assertIsNone(ev)

    def test_non_icmp_packets_ignored(self):
        det = self._det(threshold=5)
        for _ in range(20):
            self.assertIsNone(det.inspect(_tcp()))

    def test_event_detection_type(self):
        det = self._det(threshold=3)
        for i in range(5):
            ev = det.inspect(_icmp(ts=1000.0 + i * 0.1))
            if ev:
                self.assertEqual(ev.detection_type, "Unusual ICMP Activity")
                return
        self.fail("No ICMP event triggered")

    def test_event_has_required_evidence(self):
        det = self._det(threshold=3)
        for i in range(5):
            ev = det.inspect(_icmp(ts=1000.0 + i * 0.1))
            if ev:
                self.assertIn("packet_count", ev.evidence)
                self.assertIn("threshold", ev.evidence)
                self.assertIn("unique_destinations", ev.evidence)
                self.assertIn("window_seconds", ev.evidence)
                return
        self.fail("No ICMP event triggered")

    def test_reconnaissance_pattern_detected(self):
        """Many distinct destinations from one source flags recon."""
        # Use recon_threshold=3 and send to 6 distinct destinations
        det = self._det(threshold=3, window=30.0, recon_threshold=3)
        dsts = [f"10.0.0.{i}" for i in range(1, 10)]
        for i, dst in enumerate(dsts):
            ev = det.inspect(_icmp(dst_ip=dst, ts=1000.0 + i * 0.2))
            if ev:
                self.assertTrue(ev.evidence.get("possible_reconnaissance", False),
                                 f"Expected reconnaissance flag; got evidence={ev.evidence}")
                return
        self.fail("No ICMP event triggered for reconnaissance check")

    def test_empty_batch_returns_empty(self):
        from app.detection.icmp_detection import ICMPDetector
        self.assertEqual(ICMPDetector().inspect_batch([]), [])

    def test_none_packet_ignored(self):
        from app.detection.icmp_detection import ICMPDetector
        self.assertIsNone(ICMPDetector().inspect(None))  # type: ignore

    def test_missing_src_ip_ignored(self):
        from app.detection.icmp_detection import ICMPDetector
        det = ICMPDetector(threshold=3)
        pkt = _icmp()
        pkt["src_ip"] = None
        self.assertIsNone(det.inspect(pkt))

    def test_confidence_in_valid_range(self):
        det = self._det(threshold=3)
        for i in range(10):
            ev = det.inspect(_icmp(ts=1000.0 + i * 0.1))
            if ev:
                self.assertGreaterEqual(ev.confidence, 0.0)
                self.assertLessEqual(ev.confidence, 1.0)
                return
        self.fail("No event triggered")

    def test_reset_clears_state(self):
        det = self._det(threshold=3)
        for i in range(3):
            det.inspect(_icmp(ts=1000.0 + i * 0.1))
        det.reset()
        self.assertIsNone(det.inspect(_icmp(ts=2000.0)))

    def test_different_sources_tracked_independently(self):
        det = self._det(threshold=3)
        events_by_src = {"1.1.1.1": [], "2.2.2.2": []}
        for src in events_by_src:
            for i in range(5):
                ev = det.inspect(_icmp(src_ip=src, ts=1000.0 + i * 0.1))
                if ev:
                    events_by_src[src].append(ev)
        self.assertGreaterEqual(len(events_by_src["1.1.1.1"]), 1)
        self.assertGreaterEqual(len(events_by_src["2.2.2.2"]), 1)


# ---------------------------------------------------------------------------
# ARP Detector tests
# ---------------------------------------------------------------------------

class TestARPDetector(unittest.TestCase):

    def _det(self, req_thresh=10, rep_thresh=5, window=10.0):
        from app.detection.arp_detection import ARPDetector
        return ARPDetector(request_threshold=req_thresh,
                           reply_threshold=rep_thresh,
                           window_seconds=window)

    # -- Mapping change --

    def test_mac_mapping_change_detected(self):
        det = self._det()
        ip = "192.168.1.10"
        det.inspect(_arp(src_ip=ip, src_mac="aa:aa:aa:aa:aa:aa", ts=1000.0))
        events = det.inspect(_arp(src_ip=ip, src_mac="bb:bb:bb:bb:bb:bb", ts=1001.0))
        mc = [e for e in events if "mapping_change" in e.evidence.get("anomaly_subtype", "")]
        self.assertGreaterEqual(len(mc), 1)

    def test_stable_arp_mapping_no_event(self):
        det = self._det()
        ip, mac = "192.168.1.10", "aa:aa:aa:aa:aa:aa"
        for i in range(10):
            events = det.inspect(_arp(src_ip=ip, src_mac=mac, ts=1000.0 + i))
            mc = [e for e in events if "mapping_change" in e.evidence.get("anomaly_subtype", "")]
            self.assertEqual(mc, [])

    def test_mapping_change_evidence(self):
        det = self._det()
        ip = "10.0.0.5"
        det.inspect(_arp(src_ip=ip, src_mac="11:11:11:11:11:11", ts=1000.0))
        events = det.inspect(_arp(src_ip=ip, src_mac="22:22:22:22:22:22", ts=1001.0))
        mc = next((e for e in events if "mapping_change" in e.evidence.get("anomaly_subtype", "")), None)
        self.assertIsNotNone(mc)
        self.assertEqual(mc.evidence["previous_mac"], "11:11:11:11:11:11")
        self.assertEqual(mc.evidence["observed_mac"], "22:22:22:22:22:22")
        self.assertEqual(mc.source, ip)

    def test_mapping_event_type(self):
        det = self._det()
        ip = "10.0.0.9"
        det.inspect(_arp(src_ip=ip, src_mac="aa:aa:aa:aa:aa:aa", ts=1000.0))
        events = det.inspect(_arp(src_ip=ip, src_mac="bb:bb:bb:bb:bb:bb", ts=1001.0))
        for ev in events:
            if "mapping_change" in ev.evidence.get("anomaly_subtype", ""):
                self.assertEqual(ev.detection_type, "Potential ARP Anomaly")
                return
        self.fail("No mapping change event found")

    # -- ARP request flood --

    def test_arp_request_flood_detected(self):
        det = self._det(req_thresh=5)
        src = "192.168.1.99"
        events = []
        for i in range(10):
            for ev in det.inspect(_arp(src_ip=src, arp_op=1, ts=1000.0 + i * 0.1)):
                events.append(ev)
        flood = [e for e in events if "flood" in e.evidence.get("anomaly_subtype", "")]
        self.assertGreaterEqual(len(flood), 1)

    def test_normal_arp_requests_no_flood(self):
        det = self._det(req_thresh=50)
        src = "192.168.1.5"
        for i in range(5):
            events = det.inspect(_arp(src_ip=src, arp_op=1, ts=1000.0 + i))
            flood = [e for e in events if "flood" in e.evidence.get("anomaly_subtype", "")]
            self.assertEqual(flood, [])

    # -- ARP reply flood --

    def test_arp_reply_flood_detected(self):
        det = self._det(rep_thresh=3)
        src = "192.168.1.77"
        events = []
        for i in range(6):
            for ev in det.inspect(_arp(src_ip=src, arp_op=2, ts=1000.0 + i * 0.1)):
                events.append(ev)
        flood = [e for e in events if "reply_flood" in e.evidence.get("anomaly_subtype", "")]
        self.assertGreaterEqual(len(flood), 1)

    # -- Edge cases --

    def test_non_arp_packet_ignored(self):
        det = self._det()
        self.assertEqual(det.inspect(_tcp()), [])

    def test_none_packet_ignored(self):
        det = self._det()
        self.assertEqual(det.inspect(None), [])   # type: ignore

    def test_empty_batch(self):
        from app.detection.arp_detection import ARPDetector
        self.assertEqual(ARPDetector().inspect_batch([]), [])

    def test_missing_src_ip_handled(self):
        det = self._det()
        pkt = _arp()
        pkt["src_ip"] = None
        pkt["arp_psrc"] = None
        events = det.inspect(pkt)
        self.assertIsInstance(events, list)

    def test_ip_mac_table_populated(self):
        det = self._det()
        det.inspect(_arp(src_ip="10.0.0.1", src_mac="de:ad:be:ef:00:01"))
        self.assertEqual(det.ip_mac_table.get("10.0.0.1"), "de:ad:be:ef:00:01")

    def test_reset_clears_mapping_table(self):
        det = self._det()
        det.inspect(_arp(src_ip="10.0.0.1", src_mac="aa:aa:aa:aa:aa:aa"))
        det.reset()
        self.assertEqual(det.ip_mac_table, {})


# ---------------------------------------------------------------------------
# Traffic Anomaly Detector tests
# ---------------------------------------------------------------------------

class TestTrafficAnomalyDetector(unittest.TestCase):

    def _det(self, pps=100.0, bps=10_000.0, unique_dst=50,
             unique_port=100, window=1.0):
        from app.detection.traffic_anomaly import TrafficAnomalyDetector
        return TrafficAnomalyDetector(
            pps_threshold=pps, bps_threshold=bps,
            unique_dst_threshold=unique_dst,
            unique_port_threshold=unique_port,
            window_seconds=window,
        )

    def _burst(self, det, count=200, base_ts=1000.0, dst_vary=False):
        """Feed count packets spaced 1ms apart — ~1000 PPS."""
        events = []
        for i in range(count):
            dst = f"10.0.0.{i % 256}" if dst_vary else "10.0.0.1"
            ev = det.inspect(_tcp(dst_ip=dst, dst_port=80, length=100,
                                   ts=base_ts + i * 0.001))
            if ev:
                events.append(ev)
        return events

    def test_pps_threshold_triggered(self):
        det = self._det(pps=50.0, bps=999_999_999.0, window=1.0)
        events = self._burst(det, count=150)
        self.assertGreaterEqual(len(events), 1)

    def test_normal_rate_no_trigger(self):
        """One packet per second is well below any reasonable threshold."""
        det = self._det(pps=500.0, bps=500_000.0, window=5.0)
        for i in range(10):
            ev = det.inspect(_tcp(length=60, ts=1000.0 + i * 1.0))
            self.assertIsNone(ev)

    def test_event_detection_type(self):
        det = self._det(pps=50.0, bps=999_999_999.0, window=1.0)
        events = self._burst(det, count=150)
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0].detection_type, "Traffic Anomaly")

    def test_event_has_required_evidence(self):
        det = self._det(pps=50.0, bps=999_999_999.0, window=1.0)
        events = self._burst(det, count=150)
        self.assertGreaterEqual(len(events), 1)
        ev = events[0]
        self.assertIn("violations", ev.evidence)
        self.assertIn("total_packets_in_window", ev.evidence)
        self.assertIn("window_seconds", ev.evidence)

    def test_many_unique_destinations_triggered(self):
        """Flag when unique_dst threshold is crossed (PPS/BPS set very high)."""
        det = self._det(pps=999_999.0, bps=999_999_999.0,
                        unique_dst=5, window=60.0)
        events = []
        for i in range(12):
            ev = det.inspect(_tcp(dst_ip=f"10.0.{i}.1",
                                   ts=1000.0 + i * 2.0))   # spaced 2s apart
            if ev:
                events.append(ev)
        self.assertGreaterEqual(len(events), 1)
        violations = events[0].evidence.get("violations", {})
        self.assertIn("unique_destinations", violations)

    def test_empty_batch(self):
        from app.detection.traffic_anomaly import TrafficAnomalyDetector
        self.assertEqual(TrafficAnomalyDetector().inspect_batch([]), [])

    def test_none_packet_handled(self):
        from app.detection.traffic_anomaly import TrafficAnomalyDetector
        self.assertIsNone(TrafficAnomalyDetector().inspect(None))  # type: ignore

    def test_non_dict_handled(self):
        from app.detection.traffic_anomaly import TrafficAnomalyDetector
        self.assertIsNone(TrafficAnomalyDetector().inspect("not a packet"))  # type: ignore

    def test_reset_clears_window(self):
        det = self._det(pps=50.0, bps=999_999_999.0, window=1.0)
        self._burst(det, count=100)
        det.reset()
        # After reset, single packet 1s later must not trigger
        ev = det.inspect(_tcp(length=60, ts=2000.0))
        self.assertIsNone(ev)

    def test_confidence_in_range(self):
        det = self._det(pps=50.0, bps=999_999_999.0, window=1.0)
        events = self._burst(det, count=200)
        for ev in events:
            self.assertGreaterEqual(ev.confidence, 0.0)
            self.assertLessEqual(ev.confidence, 1.0)


# ---------------------------------------------------------------------------
# Detection Engine orchestration tests
# ---------------------------------------------------------------------------

class TestDetectionEngine(unittest.TestCase):

    def _engine(self):
        from app.detection.engine import DetectionEngine
        return DetectionEngine(
            port_scan_threshold=5, port_scan_window=10.0,
            icmp_threshold=5, icmp_window=5.0,
            arp_request_threshold=10, arp_reply_threshold=5, arp_window=10.0,
            traffic_pps_threshold=50.0, traffic_bps_threshold=999_999_999.0,
            traffic_window=1.0,
        )

    def test_empty_batch_returns_empty(self):
        self.assertEqual(self._engine().inspect_batch([]), [])

    def test_port_scan_via_engine(self):
        engine = self._engine()
        src = "10.0.0.1"
        events = []
        for i, port in enumerate(range(80, 95)):
            events.extend(engine.inspect(_tcp(src_ip=src, dst_port=port,
                                               ts=1000.0 + i * 0.3)))
        ps = [e for e in events if e.detection_type == "Potential Port Scan"]
        self.assertGreaterEqual(len(ps), 1)

    def test_icmp_anomaly_via_engine(self):
        engine = self._engine()
        src = "10.0.0.2"
        events = []
        for i in range(10):
            events.extend(engine.inspect(_icmp(src_ip=src, ts=1000.0 + i * 0.1)))
        icmp_evts = [e for e in events if e.detection_type == "Unusual ICMP Activity"]
        self.assertGreaterEqual(len(icmp_evts), 1)

    def test_arp_anomaly_via_engine(self):
        engine = self._engine()
        ip = "10.0.0.3"
        engine.inspect(_arp(src_ip=ip, src_mac="aa:aa:aa:aa:aa:aa", ts=1000.0))
        events = engine.inspect(_arp(src_ip=ip, src_mac="bb:bb:bb:bb:bb:bb", ts=1001.0))
        arp_evts = [e for e in events if e.detection_type == "Potential ARP Anomaly"]
        self.assertGreaterEqual(len(arp_evts), 1)

    def test_reset_clears_all_detectors(self):
        engine = self._engine()
        for i, port in enumerate(range(80, 90)):
            engine.inspect(_tcp(dst_port=port, ts=1000.0 + i * 0.3))
        engine.reset()
        events = engine.inspect(_tcp(dst_port=80, ts=2000.0))
        ps = [e for e in events if e.detection_type == "Potential Port Scan"]
        self.assertEqual(ps, [])

    def test_events_have_detector_field(self):
        engine = self._engine()
        for i, port in enumerate(range(1, 10)):
            events = engine.inspect(_tcp(dst_port=port, ts=1000.0 + i * 0.3))
            for ev in events:
                self.assertTrue(ev.detector)

    def test_batch_processes_all_packets(self):
        engine = self._engine()
        pkts = [_tcp(dst_port=p, ts=1000.0 + p * 0.3) for p in range(80, 90)]
        result = engine.inspect_batch(pkts)
        self.assertIsInstance(result, list)

    def test_non_dict_packet_ignored(self):
        engine = self._engine()
        events = engine.inspect("bad_input")  # type: ignore
        self.assertIsInstance(events, list)

    def test_mixed_packet_types(self):
        engine = self._engine()
        pkts = (
            [_tcp(dst_port=p, ts=1000.0 + p * 0.3) for p in range(1, 8)] +
            [_icmp(ts=1010.0 + i * 0.1) for i in range(8)] +
            [_arp(ts=1020.0)]
        )
        self.assertIsInstance(engine.inspect_batch(pkts), list)

    def test_detector_accessors(self):
        from app.detection.port_scan import PortScanDetector
        from app.detection.icmp_detection import ICMPDetector
        from app.detection.arp_detection import ARPDetector
        from app.detection.traffic_anomaly import TrafficAnomalyDetector
        engine = self._engine()
        self.assertIsInstance(engine.port_scan_detector, PortScanDetector)
        self.assertIsInstance(engine.icmp_detector, ICMPDetector)
        self.assertIsInstance(engine.arp_detector, ARPDetector)
        self.assertIsInstance(engine.traffic_detector, TrafficAnomalyDetector)


if __name__ == "__main__":
    unittest.main(verbosity=2)
