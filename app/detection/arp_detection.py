"""
NexIDS ARP Anomaly Detector
============================
Detects suspicious ARP behaviour by tracking IP-to-MAC address mappings
and the frequency of ARP requests.

Detection checks
----------------
1. **MAC mapping change** — an IP address is seen advertising a different
   MAC address than previously recorded.  This is a common indicator of
   ARP cache poisoning, though it can also occur legitimately (e.g., a
   device is replaced or a VM migrates).  Language is cautious:
   ``"Potential ARP Anomaly"``.

2. **Gratuitous ARP flood** — an IP sends an unusual number of unsolicited
   ARP replies (op=2) in a short window.  Real gratuitous ARPs exist (e.g.,
   CARP/VRRP failover) but high rates are suspicious.

3. **ARP request flood** — a single source makes an unusually large number
   of ARP requests (op=1) in a short window.  May indicate ARP scanning.

Important notes
---------------
* The detector does **not** confirm ARP spoofing.
* ``Potential ARP Anomaly`` is used in all events.
* Mapping state is persistent across calls — this is intentional as ARP
  table inconsistencies only make sense across multiple packets.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from app.detection.models import DetectionEvent
from app.utils.constants import ALERT_ARP_ANOMALY, PROTO_ARP
from app.utils.logger import get_logger

log = get_logger(__name__)

ParsedPacket = dict[str, Any]

_DETECTOR_NAME = "ARPDetector"

# Default thresholds (can be overridden per instance)
_DEFAULT_REQUEST_THRESHOLD = 20    # ARP requests per source in window
_DEFAULT_REPLY_THRESHOLD = 10      # Unsolicited ARP replies per source in window
_DEFAULT_WINDOW = 10.0             # seconds


class ARPDetector:
    """Stateful ARP anomaly detector.

    Parameters
    ----------
    request_threshold:
        Max ARP requests (op=1) from one source in ``window_seconds``
        before flagging.
    reply_threshold:
        Max unsolicited ARP replies (op=2) from one source in ``window_seconds``
        before flagging.
    window_seconds:
        Sliding time window.
    """

    def __init__(
        self,
        request_threshold: int = _DEFAULT_REQUEST_THRESHOLD,
        reply_threshold: int = _DEFAULT_REPLY_THRESHOLD,
        window_seconds: float = _DEFAULT_WINDOW,
    ) -> None:
        self.request_threshold = request_threshold
        self.reply_threshold = reply_threshold
        self.window_seconds = window_seconds

        # ip → first observed MAC (the "trusted" baseline)
        self._ip_mac_table: dict[str, str] = {}
        # ip → list of previous MACs it has been seen with (for evidence)
        self._ip_mac_history: dict[str, list[str]] = defaultdict(list)

        # src_ip → list of (timestamp, op)
        self._request_obs: dict[str, list[float]] = defaultdict(list)
        self._reply_obs: dict[str, list[float]] = defaultdict(list)

        # Flood report cooldown
        self._flood_reported: dict[str, float] = {}

        log.debug(
            "%s initialised — req_threshold=%d  reply_threshold=%d  window=%.1fs",
            _DETECTOR_NAME, request_threshold, reply_threshold, window_seconds,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect(self, packet: ParsedPacket) -> list[DetectionEvent]:
        """Inspect one ARP packet; may return 0, 1, or 2 events.

        Returns a *list* (rather than a single event) because one packet
        can simultaneously trigger both a mapping-change and a flood event.
        """
        if not isinstance(packet, dict):
            return []
        if packet.get("protocol") != PROTO_ARP:
            return []

        src_ip: str | None = packet.get("arp_psrc") or packet.get("src_ip")
        src_mac: str | None = packet.get("arp_hwsrc") or packet.get("src_mac")
        dst_ip: str | None = packet.get("arp_pdst") or packet.get("dst_ip")
        arp_op: int | None = packet.get("arp_op")
        ts: float = packet.get("timestamp", time.time())

        events: list[DetectionEvent] = []

        # ---- Check 1: IP→MAC mapping inconsistency --------------------
        if src_ip and src_mac:
            mapping_event = self._check_mapping_change(src_ip, src_mac, dst_ip, ts, packet)
            if mapping_event:
                events.append(mapping_event)

        # ---- Check 2: ARP request/reply flood -------------------------
        if src_ip and arp_op is not None:
            flood_event = self._check_arp_flood(src_ip, dst_ip, arp_op, ts)
            if flood_event:
                events.append(flood_event)

        return events

    def inspect_batch(self, packets: list[ParsedPacket]) -> list[DetectionEvent]:
        """Inspect a batch of packets; return all triggered events."""
        if not packets:
            return []
        events: list[DetectionEvent] = []
        for pkt in packets:
            events.extend(self.inspect(pkt))
        return events

    def reset(self) -> None:
        """Clear all accumulated state."""
        self._ip_mac_table.clear()
        self._ip_mac_history.clear()
        self._request_obs.clear()
        self._reply_obs.clear()
        self._flood_reported.clear()

    @property
    def ip_mac_table(self) -> dict[str, str]:
        """Read-only view of the current IP→MAC baseline table."""
        return dict(self._ip_mac_table)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _check_mapping_change(
        self,
        src_ip: str,
        src_mac: str,
        dst_ip: str | None,
        ts: float,
        packet: ParsedPacket,
    ) -> DetectionEvent | None:
        """Detect when an IP advertises a different MAC than previously seen."""
        if src_ip not in self._ip_mac_table:
            # First time we see this IP — record it as baseline
            self._ip_mac_table[src_ip] = src_mac
            self._ip_mac_history[src_ip].append(src_mac)
            return None

        known_mac = self._ip_mac_table[src_ip]
        if src_mac == known_mac:
            return None  # Stable mapping — no anomaly

        # MAC has changed — record and flag
        log.info(
            "ARP mapping change: IP %s was %s, now %s",
            src_ip, known_mac, src_mac,
        )
        self._ip_mac_history[src_ip].append(src_mac)
        # Update baseline to latest to avoid repeated identical events
        self._ip_mac_table[src_ip] = src_mac

        return DetectionEvent(
            detection_type=ALERT_ARP_ANOMALY,
            source=src_ip,
            destination=dst_ip,
            protocol=PROTO_ARP,
            evidence={
                "previous_mac": known_mac,
                "observed_mac": src_mac,
                "old_mac": known_mac,
                "new_mac": src_mac,
                "ip_address": src_ip,
                "mac_history": list(self._ip_mac_history[src_ip]),
                "arp_op": packet.get("arp_op"),
                "anomaly_subtype": "ip_mac_mapping_change",
                "subtype": "mapping_change",
            },
            description=(
                f"IP address {src_ip} was previously associated with MAC "
                f"{known_mac} but is now advertising MAC {src_mac}. "
                "This may indicate ARP cache manipulation, device replacement, "
                "or VM migration."
            ),
            confidence=0.7,
            detector=_DETECTOR_NAME,
            timestamp=ts,
        )

    def _check_arp_flood(
        self,
        src_ip: str,
        dst_ip: str | None,
        arp_op: int,
        ts: float,
    ) -> DetectionEvent | None:
        """Detect high-frequency ARP requests or replies."""
        cutoff = ts - self.window_seconds

        if arp_op == 1:   # ARP request
            obs = self._request_obs[src_ip]
            obs.append(ts)
            self._request_obs[src_ip] = [t for t in obs if t >= cutoff]
            count = len(self._request_obs[src_ip])
            threshold = self.request_threshold
            label = "ARP request flood"
            subtype = "arp_request_flood"
        elif arp_op == 2:  # ARP reply (unsolicited / gratuitous)
            obs = self._reply_obs[src_ip]
            obs.append(ts)
            self._reply_obs[src_ip] = [t for t in obs if t >= cutoff]
            count = len(self._reply_obs[src_ip])
            threshold = self.reply_threshold
            label = "Unsolicited ARP reply flood"
            subtype = "arp_reply_flood"
        else:
            return None

        if count < threshold:
            return None

        # Cooldown check
        flood_key = f"{src_ip}:{arp_op}"
        last = self._flood_reported.get(flood_key, 0.0)
        if ts - last < self.window_seconds:
            return None
        self._flood_reported[flood_key] = ts

        confidence = min(1.0, count / (threshold * 2))

        return DetectionEvent(
            detection_type=ALERT_ARP_ANOMALY,
            source=src_ip,
            destination=dst_ip,
            protocol=PROTO_ARP,
            evidence={
                "arp_op": arp_op,
                "packet_count": count,
                "threshold": threshold,
                "window_seconds": self.window_seconds,
                "anomaly_subtype": subtype,
                "subtype": subtype,
            },
            description=(
                f"{label} from {src_ip}: {count} ARP "
                f"{'requests' if arp_op == 1 else 'replies'} in "
                f"{self.window_seconds}s (threshold: {threshold})."
            ),
            confidence=confidence,
            detector=_DETECTOR_NAME,
            timestamp=ts,
        )
