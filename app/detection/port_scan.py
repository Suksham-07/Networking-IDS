"""
NexIDS Port Scan Detector
=========================
Detects potential port-scanning behaviour by tracking how many distinct
destination ports a single source IP contacts within a configurable
sliding time window.

Detection logic
---------------
For each incoming TCP or UDP packet, the detector records
``(src_ip, dst_port, timestamp)``.  At inspection time it counts the
number of *distinct* destination ports observed from each source within
the last ``window_seconds`` seconds.  If the count meets or exceeds
``threshold``, a :class:`~app.detection.models.DetectionEvent` with
type ``"Potential Port Scan"`` is generated.

Important notes
---------------
* The detector does **not** claim a scan is confirmed.  The event
  description and type use cautious language.
* Thresholds default to the project constants but are overridable per
  instance so tests can use tight values without touching global config.
* State is maintained in-memory; the detector is stateful and intended
  to be long-lived (created once, fed packets continuously).
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from app.detection.models import DetectionEvent
from app.utils.constants import (
    ALERT_PORT_SCAN,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    PROTO_TCP,
    PROTO_UDP,
)
from app.utils.logger import get_logger

log = get_logger(__name__)

# Type alias re-exported from packet_parser for clarity
ParsedPacket = dict[str, Any]

_DETECTOR_NAME = "PortScanDetector"


class PortScanDetector:
    """Stateful port scan detector.

    Parameters
    ----------
    threshold:
        Minimum number of distinct destination ports from one source
        within ``window_seconds`` to generate an event.
    window_seconds:
        Width of the sliding time window in seconds.
    """

    def __init__(
        self,
        threshold: int = PORT_SCAN_THRESHOLD,
        window_seconds: float = PORT_SCAN_WINDOW_SECONDS,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds

        # src_ip → list of (timestamp, dst_port) tuples
        self._observations: dict[str, list[tuple[float, int]]] = defaultdict(list)
        # Track which sources already have an open event (avoid duplicates
        # flooding the output for the same ongoing scan)
        self._reported: dict[str, float] = {}   # src_ip → last report time

        log.debug(
            "%s initialised — threshold=%d  window=%.1fs",
            _DETECTOR_NAME, threshold, window_seconds,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect(self, packet: ParsedPacket) -> DetectionEvent | None:
        """Inspect a single parsed packet and return an event if triggered.

        Parameters
        ----------
        packet:
            A :data:`~app.capture.packet_parser.ParsedPacket` dict.

        Returns
        -------
        DetectionEvent | None
            A detection event if the threshold is met; ``None`` otherwise.
        """
        if not self._is_relevant(packet):
            return None

        src_ip: str | None = packet.get("src_ip")
        dst_port: int | None = packet.get("dst_port")
        ts: float = packet.get("timestamp", time.time())

        if not src_ip or dst_port is None:
            return None

        # Record observation
        self._observations[src_ip].append((ts, dst_port))

        # Evict entries outside the window
        cutoff = ts - self.window_seconds
        self._observations[src_ip] = [
            (t, p) for t, p in self._observations[src_ip] if t >= cutoff
        ]

        # Count distinct ports in the window
        distinct_ports = {p for _, p in self._observations[src_ip]}
        port_count = len(distinct_ports)

        if port_count >= self.threshold:
            # Avoid re-reporting the same source more than once per window
            last_reported = self._reported.get(src_ip, 0.0)
            if ts - last_reported < self.window_seconds:
                return None   # already reported this source recently

            self._reported[src_ip] = ts
            sorted_ports = sorted(distinct_ports)

            confidence = min(1.0, port_count / (self.threshold * 2))

            event = DetectionEvent(
                detection_type=ALERT_PORT_SCAN,
                source=src_ip,
                destination=packet.get("dst_ip"),
                protocol=packet.get("protocol", PROTO_TCP),
                evidence={
                    "distinct_ports": port_count,
                    "ports_sample": sorted_ports[:20],   # cap sample size
                    "window_seconds": self.window_seconds,
                    "threshold": self.threshold,
                    "packet_count": len(self._observations[src_ip]),
                },
                description=(
                    f"Source {src_ip} contacted {port_count} distinct destination "
                    f"ports within {self.window_seconds}s "
                    f"(threshold: {self.threshold}). "
                    "This pattern is consistent with port-scanning activity."
                ),
                confidence=confidence,
                detector=_DETECTOR_NAME,
                timestamp=ts,
            )

            log.info(
                "%s triggered for %s — %d distinct ports in %.1fs",
                ALERT_PORT_SCAN, src_ip, port_count, self.window_seconds,
            )
            return event

        return None

    def inspect_batch(self, packets: list[ParsedPacket]) -> list[DetectionEvent]:
        """Inspect a list of packets and return all triggered events.

        Parameters
        ----------
        packets:
            Iterable of parsed packet dicts.

        Returns
        -------
        list[DetectionEvent]
            All events generated; may be empty.
        """
        if not packets:
            return []

        events: list[DetectionEvent] = []
        for pkt in packets:
            event = self.inspect(pkt)
            if event:
                events.append(event)
        return events

    def reset(self) -> None:
        """Clear all accumulated state (useful between test cases)."""
        self._observations.clear()
        self._reported.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_relevant(packet: ParsedPacket) -> bool:
        """Return True only for TCP and UDP packets (port-bearing protocols)."""
        if not isinstance(packet, dict):
            return False
        return packet.get("protocol") in (PROTO_TCP, PROTO_UDP)
