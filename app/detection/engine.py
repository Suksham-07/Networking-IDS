"""
NexIDS Detection Engine
=======================
Orchestrates all detection modules, feeding parsed packets through each
detector and collecting the resulting :class:`~app.detection.models.DetectionEvent`
objects.

This is the single entry point for the detection layer.  Callers pass
:data:`~app.capture.packet_parser.ParsedPacket` dicts (one at a time or in
batch) and receive a list of DetectionEvents ready for the Alert Engine
(Phase 4).

Architecture
------------
::

    ParsedPacket(s)
          ↓
    DetectionEngine.inspect() / inspect_batch()
          ├──▶ PortScanDetector
          ├──▶ ICMPDetector
          ├──▶ ARPDetector
          └──▶ TrafficAnomalyDetector
          ↓
    [DetectionEvent, ...]

Usage
-----
::

    from app.detection.engine import DetectionEngine

    engine = DetectionEngine()
    events = engine.inspect_batch(parsed_packets)
"""

from __future__ import annotations

from typing import Any

from app.detection.arp_detection import ARPDetector
from app.detection.icmp_detection import ICMPDetector
from app.detection.models import DetectionEvent
from app.detection.port_scan import PortScanDetector
from app.detection.traffic_anomaly import TrafficAnomalyDetector
from app.utils.logger import get_logger

log = get_logger(__name__)

ParsedPacket = dict[str, Any]


class DetectionEngine:
    """Facade that runs all active detectors against incoming packets.

    Parameters
    ----------
    port_scan_threshold:
        Passed to :class:`PortScanDetector`.
    port_scan_window:
        Passed to :class:`PortScanDetector`.
    icmp_threshold:
        Passed to :class:`ICMPDetector`.
    icmp_window:
        Passed to :class:`ICMPDetector`.
    arp_request_threshold:
        Passed to :class:`ARPDetector`.
    arp_reply_threshold:
        Passed to :class:`ARPDetector`.
    arp_window:
        Passed to :class:`ARPDetector`.
    traffic_pps_threshold:
        Passed to :class:`TrafficAnomalyDetector`.
    traffic_bps_threshold:
        Passed to :class:`TrafficAnomalyDetector`.
    traffic_window:
        Passed to :class:`TrafficAnomalyDetector`.
    """

    def __init__(
        self,
        port_scan_threshold: int = 15,
        port_scan_window: float = 10.0,
        icmp_threshold: int = 50,
        icmp_window: float = 5.0,
        arp_request_threshold: int = 20,
        arp_reply_threshold: int = 10,
        arp_window: float = 10.0,
        traffic_pps_threshold: float = 1_000.0,
        traffic_bps_threshold: float = 1_000_000.0,
        traffic_window: float = 10.0,
    ) -> None:
        self._port_scan = PortScanDetector(
            threshold=port_scan_threshold,
            window_seconds=port_scan_window,
        )
        self._icmp = ICMPDetector(
            threshold=icmp_threshold,
            window_seconds=icmp_window,
        )
        self._arp = ARPDetector(
            request_threshold=arp_request_threshold,
            reply_threshold=arp_reply_threshold,
            window_seconds=arp_window,
        )
        self._traffic = TrafficAnomalyDetector(
            pps_threshold=traffic_pps_threshold,
            bps_threshold=traffic_bps_threshold,
            window_seconds=traffic_window,
        )

        log.info("DetectionEngine initialised with %d detectors.", 4)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect(self, packet: ParsedPacket) -> list[DetectionEvent]:
        """Run all detectors against a single parsed packet.

        Parameters
        ----------
        packet:
            A parsed packet dict from :func:`~app.capture.packet_parser.parse_packet`.

        Returns
        -------
        list[DetectionEvent]
            Zero or more detection events triggered by this packet.
        """
        events: list[DetectionEvent] = []

        # Port scan (returns single event or None)
        ps_event = self._port_scan.inspect(packet)
        if ps_event:
            events.append(ps_event)

        # ICMP anomaly (returns single event or None)
        icmp_event = self._icmp.inspect(packet)
        if icmp_event:
            events.append(icmp_event)

        # ARP anomaly (returns a list — one packet can trigger multiple checks)
        arp_events = self._arp.inspect(packet)
        events.extend(arp_events)

        # Traffic anomaly (returns single event or None)
        traffic_event = self._traffic.inspect(packet)
        if traffic_event:
            events.append(traffic_event)

        return events

    def inspect_batch(self, packets: list[ParsedPacket]) -> list[DetectionEvent]:
        """Run all detectors against every packet in *packets*.

        Parameters
        ----------
        packets:
            List of parsed packet dicts.

        Returns
        -------
        list[DetectionEvent]
            Flat list of all triggered events, in arrival order.
        """
        if not packets:
            return []

        all_events: list[DetectionEvent] = []
        for pkt in packets:
            all_events.extend(self.inspect(pkt))

        log.info(
            "DetectionEngine processed %d packets → %d events.",
            len(packets), len(all_events),
        )
        return all_events

    def reset(self) -> None:
        """Reset all detector states (useful between monitoring sessions)."""
        self._port_scan.reset()
        self._icmp.reset()
        self._arp.reset()
        self._traffic.reset()
        log.debug("DetectionEngine: all detector states cleared.")

    # ------------------------------------------------------------------
    # Accessors (useful for testing / metrics)
    # ------------------------------------------------------------------

    @property
    def port_scan_detector(self) -> PortScanDetector:
        return self._port_scan

    @property
    def icmp_detector(self) -> ICMPDetector:
        return self._icmp

    @property
    def arp_detector(self) -> ARPDetector:
        return self._arp

    @property
    def traffic_detector(self) -> TrafficAnomalyDetector:
        return self._traffic
