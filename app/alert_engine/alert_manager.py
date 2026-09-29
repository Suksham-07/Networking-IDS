"""
NexIDS Alert Manager
====================
Manages the lifecycle of security alerts: creation from detection events,
enrichment, aggregation/de-duplication, memory storage, filtering, and
notification dispatching.

Architecture
------------
::

    DetectionEvent(s)
          ↓
    AlertManager.process_event() / process_events()
          ├──▶ Confidence filtering
          ├──▶ Aggregation / Coalescing (sliding time window per source+type)
          ├──▶ Enrichment (risk context, recommendations, base severity)
          ├──▶ Alert Store (query, filter, update status)
          └──▶ Notification Callbacks (UI, logs, stream)
          ↓
    [Alert, ...]

Usage
-----
::

    from app.alert_engine import AlertManager
    from app.detection import DetectionEngine

    manager = AlertManager()
    alerts = manager.process_events(detection_events)
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import Any

from app.alert_engine.alert_model import (
    STATUS_NEW,
    VALID_STATUSES,
    Alert,
)
from app.detection.models import DetectionEvent
from app.utils.constants import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from app.utils.logger import get_logger

log = get_logger(__name__)

ParsedPacket = dict[str, Any]
AlertCallback = Callable[[Alert], None]


class AlertManager:
    """Manages alert creation, enrichment, deduplication, and lifecycle.

    Parameters
    ----------
    enable_aggregation:
        If True, multiple detection events from the same source and detection
        type within ``aggregation_window_seconds`` are coalesced into a single
        alert with an incremented ``event_count``.
    aggregation_window_seconds:
        Time window (in seconds) during which repeated events are merged.
    cooldown_seconds:
        Cooldown window (in seconds) to throttle repeated alerts from the same source.
    min_confidence:
        Minimum confidence threshold [0.0 – 1.0] below which detection events
        are ignored.
    max_stored_alerts:
        Maximum number of alerts kept in memory. Oldest alerts are evicted when
        the capacity is reached.
    """

    def __init__(
        self,
        enable_aggregation: bool = True,
        aggregation_window_seconds: float = 10.0,
        cooldown_seconds: float = 30.0,
        min_confidence: float = 0.0,
        max_stored_alerts: int = 10_000,
    ) -> None:
        self.enable_aggregation = enable_aggregation
        self.aggregation_window_seconds = aggregation_window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.min_confidence = max(0.0, min(1.0, float(min_confidence)))
        self.max_stored_alerts = max(1, int(max_stored_alerts))

        self._alerts: list[Alert] = []
        self._alert_index: dict[str, Alert] = {}
        # Key: (source, detection_type) -> Alert
        self._active_windows: dict[tuple[str | None, str], Alert] = {}
        self._callbacks: list[AlertCallback] = []

        log.info(
            "AlertManager initialised (aggregation=%s, window=%.1fs, min_confidence=%.2f).",
            self.enable_aggregation,
            self.aggregation_window_seconds,
            self.min_confidence,
        )

    # ------------------------------------------------------------------
    # Core Ingestion API
    # ------------------------------------------------------------------

    def create_alert(
        self,
        event: DetectionEvent,
        severity: str | None = None,
        risk_context: str | None = None,
        recommendations: list[str] | None = None,
        alert_id: str | None = None,
        status: str = STATUS_NEW,
    ) -> Alert:
        """Create a new enriched Alert directly from a DetectionEvent without storing."""
        return Alert.from_detection_event(
            event=event,
            severity=severity,
            risk_context=risk_context,
            recommendations=recommendations,
            alert_id=alert_id,
            status=status,
        )

    def process_event(self, event: DetectionEvent | None) -> Alert | None:
        """Process a single detection event into an Alert.

        Parameters
        ----------
        event:
            The DetectionEvent to process.

        Returns
        -------
        Alert | None
            The created or updated Alert, or None if filtered out.
        """
        if event is None or not isinstance(event, DetectionEvent):
            log.debug("AlertManager: received invalid or None event.")
            return None

        if event.confidence < self.min_confidence:
            log.debug(
                "AlertManager: event confidence (%.2f) below threshold (%.2f) — ignored.",
                event.confidence,
                self.min_confidence,
            )
            return None

        # Check aggregation window
        if self.enable_aggregation:
            key = (event.source, event.detection_type)
            active_alert = self._active_windows.get(key)

            if active_alert is not None:
                elapsed = event.timestamp - active_alert.last_seen
                # Coalesce if within aggregation window or cooldown
                if 0 <= elapsed <= max(self.aggregation_window_seconds, self.cooldown_seconds):
                    active_alert.event_count += 1
                    active_alert.last_seen = event.timestamp
                    active_alert.confidence = max(active_alert.confidence, event.confidence)

                    # Merge / update evidence
                    if event.evidence:
                        for k, v in event.evidence.items():
                            if k not in active_alert.evidence or active_alert.evidence[k] != v:
                                active_alert.evidence[k] = v

                    log.debug(
                        "AlertManager: coalesced event for %s (%s) into alert %s (count=%d).",
                        event.source,
                        event.detection_type,
                        active_alert.alert_id,
                        active_alert.event_count,
                    )
                    return active_alert

        # Create new Alert
        alert = self.create_alert(event)
        self._store_alert(alert)

        if self.enable_aggregation:
            key = (event.source, event.detection_type)
            self._active_windows[key] = alert

        # Dispatch callbacks
        self._dispatch_callbacks(alert)

        log.info(
            "Alert generated: [%s] %s (Source: %s, ID: %s)",
            alert.severity,
            alert.detection_type,
            alert.source or "N/A",
            alert.alert_id,
        )
        return alert

    def process_events(self, events: list[DetectionEvent]) -> list[Alert]:
        """Process a collection of detection events.

        Parameters
        ----------
        events:
            List of DetectionEvents to process.

        Returns
        -------
        list[Alert]
            Distinct list of created or updated Alert instances.
        """
        if not events:
            return []

        result_alerts: list[Alert] = []
        seen_ids: set[str] = set()

        for evt in events:
            alert = self.process_event(evt)
            if alert is not None and alert.alert_id not in seen_ids:
                seen_ids.add(alert.alert_id)
                result_alerts.append(alert)

        log.info(
            "AlertManager processed %d events → %d unique alerts.",
            len(events),
            len(result_alerts),
        )
        return result_alerts

    def process_packet(
        self,
        packet: ParsedPacket,
        detection_engine: Any,
    ) -> list[Alert]:
        """Convenience method: inspect a packet and process any triggered events."""
        events = detection_engine.inspect(packet)
        return self.process_events(events)

    def process_packets(
        self,
        packets: list[ParsedPacket],
        detection_engine: Any,
    ) -> list[Alert]:
        """Convenience method: inspect a batch of packets and process triggered events."""
        events = detection_engine.inspect_batch(packets)
        return self.process_events(events)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def register_callback(self, callback: AlertCallback) -> None:
        """Register a callback to be called whenever a new alert is generated."""
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def unregister_callback(self, callback: AlertCallback) -> None:
        """Unregister a previously registered callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def _dispatch_callbacks(self, alert: Alert) -> None:
        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception as exc:  # noqa: BLE001
                log.warning("Error in alert callback %r: %s", cb, exc)

    # ------------------------------------------------------------------
    # Alert Store & Query API
    # ------------------------------------------------------------------

    def _store_alert(self, alert: Alert) -> None:
        """Store an alert in memory, evicting oldest if capacity reached."""
        if len(self._alerts) >= self.max_stored_alerts:
            evicted = self._alerts.pop(0)
            self._alert_index.pop(evicted.alert_id, None)

        self._alerts.append(alert)
        self._alert_index[alert.alert_id] = alert

    def get_alerts(
        self,
        severity: str | None = None,
        detection_type: str | None = None,
        source: str | None = None,
        destination: str | None = None,
        status: str | None = None,
        min_confidence: float = 0.0,
        limit: int | None = None,
    ) -> list[Alert]:
        """Query and filter stored alerts.

        Parameters
        ----------
        severity:
            Filter by severity level (e.g. ``"HIGH"``).
        detection_type:
            Filter by detection category name.
        source:
            Filter by source address.
        destination:
            Filter by destination address.
        status:
            Filter by lifecycle status (e.g. ``"NEW"``).
        min_confidence:
            Minimum confidence filter.
        limit:
            Maximum number of alerts to return (most recent first if limited).

        Returns
        -------
        list[Alert]
            Filtered list of Alert objects.
        """
        filtered = self._alerts

        if severity is not None:
            filtered = [a for a in filtered if a.severity.upper() == severity.upper()]

        if detection_type is not None:
            filtered = [a for a in filtered if a.detection_type == detection_type]

        if source is not None:
            filtered = [a for a in filtered if a.source == source]

        if destination is not None:
            filtered = [a for a in filtered if a.destination == destination]

        if status is not None:
            filtered = [a for a in filtered if a.status.upper() == status.upper()]

        if min_confidence > 0.0:
            filtered = [a for a in filtered if a.confidence >= min_confidence]

        if limit is not None and limit > 0:
            return filtered[-limit:]

        return list(filtered)

    def get_alert_by_id(self, alert_id: str) -> Alert | None:
        """Lookup an alert by its unique alert_id."""
        return self._alert_index.get(alert_id)

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        """Update the lifecycle status of a stored alert.

        Parameters
        ----------
        alert_id:
            ID of the alert to update.
        status:
            New status (``"NEW"``, ``"ACKNOWLEDGED"``, ``"RESOLVED"``, ``"SUPPRESSED"``).

        Returns
        -------
        bool
            True if alert was found and updated, False otherwise.
        """
        if status not in VALID_STATUSES:
            log.warning("Invalid alert status '%s' requested.", status)
            return False

        alert = self.get_alert_by_id(alert_id)
        if alert is None:
            log.warning("Alert ID '%s' not found for status update.", alert_id)
            return False

        alert.status = status
        log.info("Alert %s status updated to '%s'.", alert_id, status)
        return True

    def get_statistics(self) -> dict[str, Any]:
        """Compute aggregate statistics over stored alerts.

        Returns
        -------
        dict[str, Any]
            Breakdown by severity, detection type, status, protocol, and totals.
        """
        total = len(self._alerts)
        severity_counts = Counter(a.severity for a in self._alerts)
        type_counts = Counter(a.detection_type for a in self._alerts)
        status_counts = Counter(a.status for a in self._alerts)
        proto_counts = Counter(a.protocol for a in self._alerts)
        sources = {a.source for a in self._alerts if a.source is not None}
        total_coalesced_events = sum(a.event_count for a in self._alerts)

        return {
            "total_alerts": total,
            "total_events_coalesced": total_coalesced_events,
            "unique_sources_count": len(sources),
            "by_severity": {
                SEVERITY_LOW: severity_counts.get(SEVERITY_LOW, 0),
                SEVERITY_MEDIUM: severity_counts.get(SEVERITY_MEDIUM, 0),
                SEVERITY_HIGH: severity_counts.get(SEVERITY_HIGH, 0),
                SEVERITY_CRITICAL: severity_counts.get(SEVERITY_CRITICAL, 0),
            },
            "by_detection_type": dict(type_counts),
            "by_status": dict(status_counts),
            "by_protocol": dict(proto_counts),
        }

    def clear(self) -> None:
        """Clear all stored alerts and active aggregation tracking."""
        self._alerts.clear()
        self._alert_index.clear()
        self._active_windows.clear()
        log.debug("AlertManager: all alerts and active aggregation state cleared.")

    def reset(self) -> None:
        """Alias for :meth:`clear`."""
        self.clear()


# Alias for compatibility
AlertEngine = AlertManager
