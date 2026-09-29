"""
NexIDS Alert Model
==================
Defines the structured ``Alert`` dataclass representing actionable,
explainable security alerts generated from detection events.

Design principles
-----------------
* Plain dataclass — JSON-serialisable via ``to_dict()`` and ``to_json()``.
* Cautious, objective language (avoids unproven claims of adversary intent).
* Structured fields: alert ID, timestamps, severity, confidence, evidence,
  risk context, and defensive recommendations.
* Interoperable with Phase 3 (DetectionEngine) and Phase 5 (Prioritizer).
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

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
    SEVERITY_ORDER,
)

# Valid alert statuses
STATUS_NEW = "NEW"
STATUS_ACKNOWLEDGED = "ACKNOWLEDGED"
STATUS_RESOLVED = "RESOLVED"
STATUS_SUPPRESSED = "SUPPRESSED"
VALID_STATUSES = {STATUS_NEW, STATUS_ACKNOWLEDGED, STATUS_RESOLVED, STATUS_SUPPRESSED}


def determine_base_severity(event: DetectionEvent) -> str:
    """Determine initial severity based on detection type and evidence.

    Parameters
    ----------
    event:
        The underlying DetectionEvent.

    Returns
    -------
    str
        One of ``SEVERITY_LOW``, ``SEVERITY_MEDIUM``, ``SEVERITY_HIGH``, ``SEVERITY_CRITICAL``.
    """
    dtype = event.detection_type
    evidence = event.evidence or {}

    if dtype == ALERT_ARP_ANOMALY:
        subtype = str(evidence.get("anomaly_subtype") or evidence.get("subtype") or "")
        if "mapping_change" in subtype:
            return SEVERITY_HIGH
        return SEVERITY_MEDIUM

    if dtype == ALERT_PORT_SCAN:
        ports = evidence.get("distinct_ports", 0)
        if isinstance(ports, int) and ports >= 50:
            return SEVERITY_HIGH
        return SEVERITY_MEDIUM

    if dtype == ALERT_TRAFFIC_ANOMALY:
        pps = evidence.get("pps", 0)
        bps = evidence.get("bps", 0)
        violations = evidence.get("violations", {})
        if "packets_per_second" in violations:
            pps = violations["packets_per_second"].get("observed", pps)
        if "bytes_per_second" in violations:
            bps = violations["bytes_per_second"].get("observed", bps)

        if (isinstance(pps, (int, float)) and pps >= 5000) or (
            isinstance(bps, (int, float)) and bps >= 50_000_000
        ):
            return SEVERITY_HIGH
        return SEVERITY_MEDIUM

    if dtype == ALERT_ICMP_ANOMALY:
        is_recon = evidence.get("possible_reconnaissance") or evidence.get("pattern") == "reconnaissance"
        if is_recon:
            return SEVERITY_MEDIUM
        return SEVERITY_LOW

    return SEVERITY_MEDIUM


def generate_risk_context(event: DetectionEvent) -> str:
    """Generate an explainable, cautious risk assessment for the event.

    Parameters
    ----------
    event:
        The underlying DetectionEvent.

    Returns
    -------
    str
        Plain-English contextual explanation of potential impact and reasons.
    """
    dtype = event.detection_type
    evidence = event.evidence or {}
    src = event.source or "unknown source"

    if dtype == ALERT_PORT_SCAN:
        ports_count = evidence.get("distinct_ports", "multiple")
        return (
            f"Host {src} probed {ports_count} distinct destination ports. "
            "This pattern is consistent with automated port scanning or service enumeration, "
            "which often precedes targeted service interactions, though legitimate network "
            "management tools or multi-port services can produce similar observations."
        )

    if dtype == ALERT_ICMP_ANOMALY:
        is_recon = evidence.get("possible_reconnaissance") or evidence.get("pattern") == "reconnaissance"
        count = evidence.get("packet_count", "an elevated volume of")
        if is_recon:
            return (
                f"Host {src} transmitted {count} ICMP echo requests across multiple targets. "
                "This behaviour is characteristic of host discovery (ping sweep) activity, "
                "which may map live systems on the network segment."
            )
        return (
            f"Host {src} generated {count} ICMP packets within a short observation window. "
            "Elevated ICMP rates may indicate network diagnostics, automated reachability polling, "
            "or potential ICMP flood activity impacting network bandwidth."
        )

    if dtype == ALERT_ARP_ANOMALY:
        subtype = str(evidence.get("anomaly_subtype") or evidence.get("subtype") or "anomaly")
        if "mapping_change" in subtype:
            ip = evidence.get("ip_address") or evidence.get("ip", src)
            old_mac = evidence.get("previous_mac") or evidence.get("old_mac", "unknown")
            new_mac = evidence.get("observed_mac") or evidence.get("new_mac", "unknown")
            return (
                f"IP address {ip} changed its associated hardware address from {old_mac} to {new_mac}. "
                "This may indicate ARP spoofing / cache poisoning attempting traffic interception, "
                "or benign events such as DHCP reassignment, NIC replacement, or device roaming."
            )
        return (
            f"High volume of ARP {subtype.replace('_', ' ')}s observed from {src}. "
            "Excessive ARP traffic can degrade local broadcast domain performance and may stem from "
            "network discovery tools, misconfigured network stacks, or ARP scanning."
        )

    if dtype == ALERT_TRAFFIC_ANOMALY:
        pps = evidence.get("pps")
        bps = evidence.get("bps")
        violations = evidence.get("violations", {})
        if pps is None and "packets_per_second" in violations:
            pps = violations["packets_per_second"].get("observed")
        if bps is None and "bytes_per_second" in violations:
            bps = violations["bytes_per_second"].get("observed")

        rate_parts = []
        if pps is not None and isinstance(pps, (int, float)):
            rate_parts.append(f"{pps:.0f} packets/sec")
        if bps is not None and isinstance(bps, (int, float)):
            rate_parts.append(f"{bps / 1_000_000:.2f} MB/s")
        rate_desc = f" ({', '.join(rate_parts)})" if rate_parts else ""
        return (
            f"Traffic volume{rate_desc} significantly exceeded normal baseline thresholds. "
            "High traffic spikes can be caused by large legitimate data transfers, media streaming, "
            "scheduled system backups, or denial-of-service traffic."
        )

    return (
        f"Unusual network observation recorded for {src} using protocol {event.protocol}."
    )


def generate_recommendations(event: DetectionEvent) -> list[str]:
    """Generate structured, actionable defensive recommendations for the event.

    Parameters
    ----------
    event:
        The underlying DetectionEvent.

    Returns
    -------
    list[str]
        List of actionable verification and mitigation suggestions.
    """
    dtype = event.detection_type
    evidence = event.evidence or {}

    if dtype == ALERT_PORT_SCAN:
        return [
            "Verify whether the source IP belongs to an authorized security audit or network monitoring tool.",
            "Review host-based firewall and router ACLs to ensure only necessary ports are accessible.",
            "Inspect authentication logs on contacted destination systems for suspicious connection attempts.",
            "Consider applying connection rate limiting or temporary blocking if unauthorized.",
        ]

    if dtype == ALERT_ICMP_ANOMALY:
        return [
            "Confirm if network administrators initiated ping sweeps or path diagnostic tests.",
            "Configure network perimeter and internal routers to rate-limit ICMP echo request packets.",
            "Inspect the source endpoint for unauthorized network scanning tools or scripts.",
        ]

    if dtype == ALERT_ARP_ANOMALY:
        subtype = str(evidence.get("anomaly_subtype") or evidence.get("subtype") or "")
        if "mapping_change" in subtype:
            return [
                "Verify the MAC address against the authoritative network asset inventory or DHCP leases.",
                "Check the physical switch port or wireless AP associated with the suspect MAC address.",
                "Enable Dynamic ARP Inspection (DAI) and DHCP Snooping on managed network switches.",
                "Inspect local endpoints for IP address conflicts or unauthorized network devices.",
            ]
        return [
            "Inspect the source host to determine the cause of elevated ARP broadcast traffic.",
            "Verify switch broadcast suppression and storm control thresholds on the local segment.",
            "Check for potential physical or virtual network switching loops.",
        ]

    if dtype == ALERT_TRAFFIC_ANOMALY:
        return [
            "Identify the active process or service generating high throughput on the source host.",
            "Verify if scheduled backups, system updates, or heavy file transfers are in progress.",
            "Apply Quality of Service (QoS) or bandwidth rate limits to preserve network availability.",
            "Temporarily isolate the host for forensic inspection if traffic origin cannot be verified.",
        ]

    return [
        "Inspect the source and destination hosts involved in the observation.",
        "Review relevant system and application logs for unusual connection behavior.",
        "Ensure network firewall and access control policies are up to date.",
    ]


@dataclass
class Alert:
    """A structured, explainable security alert.

    Attributes
    ----------
    alert_id:
        Unique string identifier for the alert.
    timestamp:
        Unix epoch (seconds) when the alert was created.
    detection_type:
        Category name (e.g. ``"Potential Port Scan"``).
    severity:
        Severity level (``"LOW"``, ``"MEDIUM"``, ``"HIGH"``, ``"CRITICAL"``).
    source:
        Source IP address or MAC address if applicable.
    destination:
        Destination IP address or MAC address if applicable.
    protocol:
        Network protocol involved (``"TCP"``, ``"UDP"``, ``"ICMP"``, ``"ARP"``...).
    confidence:
        Confidence score in [0.0, 1.0].
    description:
        Human-readable summary of the detected observation.
    evidence:
        Dictionary of facts and metrics collected by the detector.
    risk_context:
        Plain-English explanation of the potential risk and context.
    recommendations:
        Actionable mitigation and verification steps for administrators.
    detector:
        Name of the detector module that originated the underlying event.
    event_count:
        Number of underlying detection events coalesced into this alert.
    status:
        Current lifecycle state (``"NEW"``, ``"ACKNOWLEDGED"``, ``"RESOLVED"``, ``"SUPPRESSED"``).
    first_seen:
        Unix epoch timestamp of the first observed event for this alert.
    last_seen:
        Unix epoch timestamp of the most recent event for this alert.
    """

    detection_type: str
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    severity: str = SEVERITY_MEDIUM
    source: str | None = None
    destination: str | None = None
    protocol: str = "UNKNOWN"
    confidence: float = 0.5
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    risk_context: str = ""
    recommendations: list[str] = field(default_factory=list)
    detector: str = "unknown"
    event_count: int = 1
    status: str = STATUS_NEW
    first_seen: float = 0.0
    last_seen: float = 0.0

    def __post_init__(self) -> None:
        # Clamp confidence to [0.0, 1.0]
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

        # Validate severity
        if self.severity not in SEVERITY_ORDER:
            self.severity = SEVERITY_MEDIUM

        # Validate status
        if self.status not in VALID_STATUSES:
            self.status = STATUS_NEW

        # Initialize first_seen and last_seen if unset
        if self.first_seen <= 0.0:
            self.first_seen = self.timestamp
        if self.last_seen <= 0.0:
            self.last_seen = self.timestamp

        # Ensure recommendations is a list
        if not isinstance(self.recommendations, list):
            self.recommendations = list(self.recommendations)

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def from_detection_event(
        cls,
        event: DetectionEvent,
        severity: str | None = None,
        risk_context: str | None = None,
        recommendations: list[str] | None = None,
        alert_id: str | None = None,
        status: str = STATUS_NEW,
    ) -> Alert:
        """Create a fully enriched Alert from a :class:`~app.detection.models.DetectionEvent`.

        Parameters
        ----------
        event:
            The detection event to convert.
        severity:
            Optional explicit severity. If None, derived automatically.
        risk_context:
            Optional explicit risk context. If None, generated automatically.
        recommendations:
            Optional explicit recommendations. If None, generated automatically.
        alert_id:
            Optional explicit alert ID. If None, a UUID is generated.
        status:
            Initial alert status (default: ``"NEW"``).

        Returns
        -------
        Alert
            A new enriched Alert instance.
        """
        resolved_severity = (
            severity if severity is not None else determine_base_severity(event)
        )
        resolved_risk = (
            risk_context if risk_context is not None else generate_risk_context(event)
        )
        resolved_recs = (
            recommendations
            if recommendations is not None
            else generate_recommendations(event)
        )

        kwargs: dict[str, Any] = {
            "detection_type": event.detection_type,
            "timestamp": event.timestamp,
            "severity": resolved_severity,
            "source": event.source,
            "destination": event.destination,
            "protocol": event.protocol,
            "confidence": event.confidence,
            "description": event.description,
            "evidence": dict(event.evidence) if event.evidence else {},
            "risk_context": resolved_risk,
            "recommendations": resolved_recs,
            "detector": event.detector,
            "event_count": 1,
            "status": status,
            "first_seen": event.timestamp,
            "last_seen": event.timestamp,
        }
        if alert_id is not None:
            kwargs["alert_id"] = alert_id

        return cls(**kwargs)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        """Construct an Alert instance from a dictionary."""
        valid_fields = cls.__dataclass_fields__.keys()
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)

    # ------------------------------------------------------------------
    # Serialisation & Utility
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict representation of the alert."""
        return asdict(self)

    def to_json(self, indent: int | None = None) -> str:
        """Return a JSON-formatted string representation."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
