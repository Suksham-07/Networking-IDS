"""
NexIDS Prioritization Rules & Configuration (Phase 5)
=====================================================
Defines rule-based evaluation functions, scoring algorithms, and configuration
for computing composite risk scores and triage priority bands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.alert_engine.alert_model import Alert
from app.utils.constants import (
    PRIORITY_P1,
    PRIORITY_P2,
    PRIORITY_P3,
    PRIORITY_P4,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)


@dataclass
class PrioritizationConfig:
    """Configurable weights, thresholds, and asset definitions for alert prioritization.

    Attributes
    ----------
    severity_weights:
        Point allocations for each base severity level (max 40 pts).
    max_confidence_score:
        Maximum points allocated from detection confidence (max 20 pts).
    max_recurrence_score:
        Maximum points allocated for recurring detections / high event count (max 15 pts).
    max_asset_criticality_score:
        Maximum points allocated for critical or high-value infrastructure assets (max 15 pts).
    max_correlation_score:
        Maximum points allocated for correlated multi-vector attacks (max 10 pts).
    critical_assets:
        Set of known critical IP addresses or hostnames (e.g. gateway, DNS, servers).
    critical_asset_suffixes:
        Common IP suffixes designating default gateways/routers (e.g. ".1", ".254").
    asset_weights:
        Specific custom point weights for designated IP addresses.
    p1_threshold:
        Composite score threshold to qualify for P1_CRITICAL (default: 75.0).
    p2_threshold:
        Composite score threshold to qualify for P2_HIGH (default: 50.0).
    p3_threshold:
        Composite score threshold to qualify for P3_MEDIUM (default: 25.0).
    correlation_window_seconds:
        Time window for correlating distinct detection types from the same source.
    """

    severity_weights: dict[str, float] = field(
        default_factory=lambda: {
            SEVERITY_CRITICAL: 40.0,
            SEVERITY_HIGH: 30.0,
            SEVERITY_MEDIUM: 20.0,
            SEVERITY_LOW: 10.0,
        }
    )
    max_confidence_score: float = 20.0
    max_recurrence_score: float = 15.0
    max_asset_criticality_score: float = 15.0
    max_correlation_score: float = 10.0

    critical_assets: set[str] = field(
        default_factory=lambda: {
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "1.1.1.1",
            "127.0.0.1",
        }
    )
    critical_asset_suffixes: tuple[str, ...] = (".1", ".254")
    asset_weights: dict[str, float] = field(default_factory=dict)

    p1_threshold: float = 75.0
    p2_threshold: float = 50.0
    p3_threshold: float = 25.0
    correlation_window_seconds: float = 300.0


def evaluate_severity(
    alert: Alert,
    config: PrioritizationConfig,
) -> tuple[float, str]:
    """Calculate severity points and reason based on base severity."""
    score = config.severity_weights.get(alert.severity, 15.0)
    reason = f"Base severity '{alert.severity}' contributes {score:.1f} points."
    return score, reason


def evaluate_confidence(
    alert: Alert,
    config: PrioritizationConfig,
) -> tuple[float, str]:
    """Calculate confidence points and reason based on detector confidence."""
    clamped_conf = max(0.0, min(1.0, float(alert.confidence)))
    score = round(clamped_conf * config.max_confidence_score, 2)
    reason = f"Detection confidence ({clamped_conf:.2f}) contributes {score:.1f} points."
    return score, reason


def evaluate_recurrence(
    alert: Alert,
    config: PrioritizationConfig,
) -> tuple[float, str | None]:
    """Calculate boost points based on event recurrence frequency."""
    count = alert.event_count
    if count >= 10:
        score = config.max_recurrence_score
        reason = f"High recurrence: {count} coalesced events observed (+{score:.1f} pts)."
    elif count >= 5:
        score = min(10.0, config.max_recurrence_score)
        reason = f"Elevated recurrence: {count} coalesced events observed (+{score:.1f} pts)."
    elif count >= 2:
        score = min(5.0, config.max_recurrence_score)
        reason = f"Repeated occurrence: {count} events observed (+{score:.1f} pts)."
    else:
        score = 0.0
        reason = None
    return score, reason


def is_critical_asset(
    ip: str | None,
    config: PrioritizationConfig,
) -> bool:
    """Determine whether an IP matches configured critical asset criteria."""
    if not ip or not isinstance(ip, str):
        return False
    clean_ip = ip.strip()
    if clean_ip in config.critical_assets:
        return True
    if clean_ip in config.asset_weights:
        return True
    if any(clean_ip.endswith(sfx) for sfx in config.critical_asset_suffixes):
        return True
    return False


def evaluate_asset_criticality(
    alert: Alert,
    config: PrioritizationConfig,
) -> tuple[float, str | None]:
    """Calculate points if target or source is a critical network asset."""
    dst = alert.destination
    src = alert.source

    # Check custom weights first
    if dst and dst in config.asset_weights:
        custom_score = min(config.max_asset_criticality_score, config.asset_weights[dst])
        return custom_score, f"Destination {dst} has custom asset criticality (+{custom_score:.1f} pts)."
    if src and src in config.asset_weights:
        custom_score = min(config.max_asset_criticality_score, config.asset_weights[src])
        return custom_score, f"Source {src} has custom asset criticality (+{custom_score:.1f} pts)."

    # Destination critical asset (e.g. gateway or core server being targeted)
    if is_critical_asset(dst, config):
        score = config.max_asset_criticality_score
        return score, f"Destination {dst} is a designated critical infrastructure asset (+{score:.1f} pts)."

    # Source critical asset (e.g. gateway or core server potentially compromised or spoofed)
    if is_critical_asset(src, config):
        score = round(config.max_asset_criticality_score * 0.7, 1)
        return score, f"Source {src} is a designated critical infrastructure asset (+{score:.1f} pts)."

    return 0.0, None


def evaluate_correlation(
    alert: Alert,
    context_alerts: list[Alert] | None,
    config: PrioritizationConfig,
) -> tuple[float, str | None]:
    """Calculate boost points if correlated multi-vector activities are detected."""
    if not context_alerts or not alert.source:
        return 0.0, None

    other_types: set[str] = set()
    for other in context_alerts:
        if other.alert_id == alert.alert_id:
            continue
        if other.source == alert.source:
            # Check within time window
            time_diff = abs(alert.timestamp - other.timestamp)
            if time_diff <= config.correlation_window_seconds:
                if other.detection_type != alert.detection_type:
                    other_types.add(other.detection_type)

    if not other_types:
        return 0.0, None

    if len(other_types) >= 2:
        score = config.max_correlation_score
        types_str = ", ".join(sorted(other_types))
        reason = (
            f"Multi-vector attack chain: source {alert.source} also triggered {len(other_types)} "
            f"other alert types ({types_str}) (+{score:.1f} pts)."
        )
    else:
        score = min(7.0, config.max_correlation_score)
        other_type = next(iter(other_types))
        reason = (
            f"Correlated activity: source {alert.source} also triggered '{other_type}' (+{score:.1f} pts)."
        )

    return score, reason


def determine_priority_level(
    score: float,
    config: PrioritizationConfig,
) -> str:
    """Map a composite risk score [0.0 - 100.0] to a priority level tier."""
    if score >= config.p1_threshold:
        return PRIORITY_P1
    if score >= config.p2_threshold:
        return PRIORITY_P2
    if score >= config.p3_threshold:
        return PRIORITY_P3
    return PRIORITY_P4
