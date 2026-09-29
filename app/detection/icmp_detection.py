"""
NexIDS ICMP Anomaly Detector
=============================
Detects unusually high ICMP activity from a single source within a
configurable sliding time window.

Detection logic
---------------
For every ICMP packet, the detector records ``(src_ip, dst_ip, timestamp)``.
If the count of ICMP packets from the same source within ``window_seconds``
reaches or exceeds ``threshold``, a :class:`~app.detection.models.DetectionEvent`
with type ``"Unusual ICMP Activity"`` is generated.

A secondary check tracks unique *destination* IPs from the same source.
If the same source pings many different hosts in a short window it is
additionally flagged as potential ICMP-based reconnaissance.

Important notes
---------------
* Language is deliberately cautious — "Unusual ICMP Activity" rather than
  "ICMP Flood Attack".
* ICMP type/code context is preserved in the evidence dict so analysts
  can distinguish echo-requests (type=8) from other types.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from app.detection.models import DetectionEvent
from app.utils.constants import (
    ALERT_ICMP_ANOMALY,
    ICMP_FLOOD_THRESHOLD,
    ICMP_WINDOW_SECONDS,
    PROTO_ICMP,
)
from app.utils.logger import get_logger

log = get_logger(__name__)

ParsedPacket = dict[str, Any]

_DETECTOR_NAME = "ICMPDetector"

# Reconnaissance threshold: distinct destinations from one source
_RECON_DEST_THRESHOLD = 5


class ICMPDetector:
    """Stateful ICMP anomaly detector.

    Parameters
    ----------
    threshold:
        ICMP packets from one source within ``window_seconds`` to trigger.
    window_seconds:
        Sliding window width in seconds.
    recon_threshold:
        Number of distinct destination IPs from one source that
        additionally triggers a reconnaissance-pattern note.
    """

    def __init__(
        self,
        threshold: int = ICMP_FLOOD_THRESHOLD,
        window_seconds: float = ICMP_WINDOW_SECONDS,
        recon_threshold: int = _RECON_DEST_THRESHOLD,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.recon_threshold = recon_threshold

        # src_ip → list of (timestamp, dst_ip, icmp_type, icmp_code)
        self._observations: dict[str, list[tuple[float, str | None, int | None, int | None]]] = (
            defaultdict(list)
        )
        self._reported: dict[str, float] = {}

        log.debug(
            "%s initialised — threshold=%d  window=%.1fs",
            _DETECTOR_NAME, threshold, window_seconds,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect(self, packet: ParsedPacket) -> DetectionEvent | None:
        """Inspect one parsed packet. Returns a DetectionEvent if triggered."""
        if not isinstance(packet, dict):
            return None
        if packet.get("protocol") != PROTO_ICMP:
            return None

        src_ip: str | None = packet.get("src_ip")
        dst_ip: str | None = packet.get("dst_ip")
        ts: float = packet.get("timestamp", time.time())
        icmp_type: int | None = packet.get("icmp_type")
        icmp_code: int | None = packet.get("icmp_code")

        if not src_ip:
            return None

        # Record and trim window
        self._observations[src_ip].append((ts, dst_ip, icmp_type, icmp_code))
        cutoff = ts - self.window_seconds
        self._observations[src_ip] = [
            r for r in self._observations[src_ip] if r[0] >= cutoff
        ]

        window_records = self._observations[src_ip]
        packet_count = len(window_records)

        if packet_count < self.threshold:
            return None

        # Avoid duplicate reports within the same window
        last_reported = self._reported.get(src_ip, 0.0)
        if ts - last_reported < self.window_seconds:
            return None

        self._reported[src_ip] = ts

        # Build evidence
        unique_dsts = {r[1] for r in window_records if r[1]}
        icmp_types = list({r[2] for r in window_records if r[2] is not None})
        is_recon = len(unique_dsts) >= self.recon_threshold

        description = (
            f"Source {src_ip} sent {packet_count} ICMP packets in "
            f"{self.window_seconds}s (threshold: {self.threshold})."
        )
        if is_recon:
            description += (
                f" Packets targeted {len(unique_dsts)} distinct destinations — "
                "possible ICMP-based reconnaissance."
            )

        confidence = min(1.0, packet_count / (self.threshold * 2))

        event = DetectionEvent(
            detection_type=ALERT_ICMP_ANOMALY,
            source=src_ip,
            destination=dst_ip,
            protocol=PROTO_ICMP,
            evidence={
                "packet_count": packet_count,
                "threshold": self.threshold,
                "window_seconds": self.window_seconds,
                "unique_destinations": len(unique_dsts),
                "destination_sample": sorted(unique_dsts)[:10],
                "icmp_types_seen": icmp_types,
                "possible_reconnaissance": is_recon,
            },
            description=description,
            confidence=confidence,
            detector=_DETECTOR_NAME,
            timestamp=ts,
        )

        log.info(
            "%s triggered for %s — %d ICMP packets in %.1fs",
            ALERT_ICMP_ANOMALY, src_ip, packet_count, self.window_seconds,
        )
        return event

    def inspect_batch(self, packets: list[ParsedPacket]) -> list[DetectionEvent]:
        """Inspect a batch of packets; return all triggered events."""
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
        self._observations.clear()
        self._reported.clear()
