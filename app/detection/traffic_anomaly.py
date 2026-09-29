"""
NexIDS Traffic Anomaly Detector
================================
Detects unusual bulk traffic patterns by comparing observed metrics to
configurable baselines within a sliding time window.

Tracked metrics
---------------
* **Packets per second (PPS)** — total packet rate from any source.
* **Bytes per second (BPS)** — total byte throughput.
* **Unique destination IPs** — large fan-out may indicate scanning.
* **Unique destination ports** — wide port spread may indicate scanning.

Detection logic
---------------
At every inspection the detector computes the above metrics over the last
``window_seconds`` seconds.  Any metric that exceeds its configured
threshold generates a ``"Traffic Anomaly"`` event.

One *combined* event is raised per window (not one per metric) to keep
the output clean.  The ``evidence`` dict records which metrics exceeded
their threshold and by how much.

Design notes
------------
* No machine learning — all thresholds are explicit and configurable.
* The detector is *per-network* (global state, not per-source).
  Per-source rate limiting belongs to the port scan / ICMP detectors.
* Confidence is proportional to how many thresholds are exceeded.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any

from app.detection.models import DetectionEvent
from app.utils.constants import (
    ALERT_TRAFFIC_ANOMALY,
    TRAFFIC_BYTES_THRESHOLD,
    TRAFFIC_WINDOW_SECONDS,
)
from app.utils.logger import get_logger

log = get_logger(__name__)

ParsedPacket = dict[str, Any]

_DETECTOR_NAME = "TrafficAnomalyDetector"

# Defaults for additional thresholds not yet in constants.py
_DEFAULT_PPS_THRESHOLD = 1_000          # packets/second
_DEFAULT_UNIQUE_DST_THRESHOLD = 200     # unique destination IPs in window
_DEFAULT_UNIQUE_PORT_THRESHOLD = 500    # unique destination ports in window


class TrafficAnomalyDetector:
    """Stateful, baseline-free traffic anomaly detector.

    Parameters
    ----------
    pps_threshold:
        Packets-per-second sustained rate to flag.
    bps_threshold:
        Bytes-per-second sustained rate to flag.
    unique_dst_threshold:
        Unique destination IP count in the window to flag.
    unique_port_threshold:
        Unique destination port count in the window to flag.
    window_seconds:
        Sliding window width in seconds.
    """

    def __init__(
        self,
        pps_threshold: float = _DEFAULT_PPS_THRESHOLD,
        bps_threshold: float = TRAFFIC_BYTES_THRESHOLD / TRAFFIC_WINDOW_SECONDS,
        unique_dst_threshold: int = _DEFAULT_UNIQUE_DST_THRESHOLD,
        unique_port_threshold: int = _DEFAULT_UNIQUE_PORT_THRESHOLD,
        window_seconds: float = TRAFFIC_WINDOW_SECONDS,
    ) -> None:
        self.pps_threshold = pps_threshold
        self.bps_threshold = bps_threshold
        self.unique_dst_threshold = unique_dst_threshold
        self.unique_port_threshold = unique_port_threshold
        self.window_seconds = window_seconds

        # Each entry: (timestamp, length, dst_ip, dst_port)
        self._window: deque[tuple[float, int, str | None, int | None]] = deque()
        self._last_event_time: float = 0.0

        log.debug(
            "%s initialised — pps=%.0f  bps=%.0f  window=%.1fs",
            _DETECTOR_NAME, pps_threshold, bps_threshold, window_seconds,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect(self, packet: ParsedPacket) -> DetectionEvent | None:
        """Inspect one parsed packet; return event if any threshold exceeded."""
        if not isinstance(packet, dict):
            return None

        ts: float = packet.get("timestamp", time.time())
        length: int = packet.get("length", 0)
        dst_ip: str | None = packet.get("dst_ip")
        dst_port: int | None = packet.get("dst_port")

        # Add to window
        self._window.append((ts, length, dst_ip, dst_port))

        # Evict stale entries
        cutoff = ts - self.window_seconds
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()

        if not self._window:
            return None

        # Calculate metrics
        # Use max(span, window_seconds) so a single packet at t=0 does not
        # produce an astronomically large PPS / BPS reading.
        raw_span = ts - self._window[0][0]
        actual_span = raw_span if raw_span >= 0.1 else self.window_seconds
        total_pkts = len(self._window)
        total_bytes = sum(r[1] for r in self._window)
        unique_dsts = {r[2] for r in self._window if r[2]}
        unique_ports = {r[3] for r in self._window if r[3] is not None}

        pps = total_pkts / actual_span
        bps = total_bytes / actual_span

        # Gather threshold violations
        violations: dict[str, dict[str, float]] = {}
        if pps >= self.pps_threshold:
            violations["packets_per_second"] = {
                "observed": round(pps, 2),
                "threshold": self.pps_threshold,
            }
        if bps >= self.bps_threshold:
            violations["bytes_per_second"] = {
                "observed": round(bps, 2),
                "threshold": self.bps_threshold,
            }
        if len(unique_dsts) >= self.unique_dst_threshold:
            violations["unique_destinations"] = {
                "observed": len(unique_dsts),
                "threshold": self.unique_dst_threshold,
            }
        if len(unique_ports) >= self.unique_port_threshold:
            violations["unique_ports"] = {
                "observed": len(unique_ports),
                "threshold": self.unique_port_threshold,
            }

        if not violations:
            return None

        # Cooldown — one event per window
        if ts - self._last_event_time < self.window_seconds:
            return None
        self._last_event_time = ts

        confidence = min(1.0, len(violations) / 4)

        descriptions = []
        for metric, vals in violations.items():
            descriptions.append(
                f"{metric}={vals['observed']} (threshold {vals['threshold']})"
            )

        event = DetectionEvent(
            detection_type=ALERT_TRAFFIC_ANOMALY,
            source=None,
            destination=None,
            protocol=packet.get("protocol", "UNKNOWN"),
            evidence={
                "violations": violations,
                "window_seconds": self.window_seconds,
                "total_packets_in_window": total_pkts,
                "total_bytes_in_window": total_bytes,
                "unique_destinations": len(unique_dsts),
                "unique_ports": len(unique_ports),
            },
            description=(
                "Traffic anomaly detected: " + "; ".join(descriptions) + "."
            ),
            confidence=confidence,
            detector=_DETECTOR_NAME,
            timestamp=ts,
        )

        log.info(
            "%s triggered — violations: %s",
            ALERT_TRAFFIC_ANOMALY, list(violations.keys()),
        )
        return event

    def inspect_batch(self, packets: list[ParsedPacket]) -> list[DetectionEvent]:
        """Inspect a batch; return all triggered events."""
        if not packets:
            return []
        events: list[DetectionEvent] = []
        for pkt in packets:
            ev = self.inspect(pkt)
            if ev:
                events.append(ev)
        return events

    def reset(self) -> None:
        """Clear all accumulated state."""
        self._window.clear()
        self._last_event_time = 0.0
