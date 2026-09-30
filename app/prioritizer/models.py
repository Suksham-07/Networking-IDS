"""
NexIDS Prioritization Models (Phase 5)
======================================
Defines data structures representing prioritized alerts and detailed,
explainable score breakdowns.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from app.alert_engine.alert_model import Alert
from app.utils.constants import (
    PRIORITY_ORDER,
    PRIORITY_P1,
    PRIORITY_P2,
    PRIORITY_P3,
    PRIORITY_P4,
)

PRIORITY_LABELS: dict[str, str] = {
    PRIORITY_P1: "P1 (Critical)",
    PRIORITY_P2: "P2 (High)",
    PRIORITY_P3: "P3 (Medium)",
    PRIORITY_P4: "P4 (Low)",
}


@dataclass
class ScoreBreakdown:
    """Detailed, explainable breakdown of an alert's composite priority score.

    Attributes
    ----------
    base_severity_score:
        Points derived from the alert's base severity (LOW/MED/HIGH/CRITICAL).
    confidence_score:
        Points scaled by the detector's confidence [0.0 - 1.0].
    recurrence_boost:
        Points added due to repeated occurrences (event_count or frequency).
    asset_criticality_boost:
        Points added if the source or target is a high-value network asset.
    correlation_boost:
        Points added if multi-vector or chained attack patterns were detected.
    total_score:
        Final clamped composite risk score in [0.0, 100.0].
    priority_level:
        Assigned triage priority band (P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW).
    reasons:
        List of human-readable justifications explaining the score.
    """

    base_severity_score: float = 0.0
    confidence_score: float = 0.0
    recurrence_boost: float = 0.0
    asset_criticality_boost: float = 0.0
    correlation_boost: float = 0.0
    total_score: float = 0.0
    priority_level: str = PRIORITY_P4
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dictionary representation."""
        return asdict(self)


@dataclass
class PrioritizedAlert:
    """An alert enriched with risk prioritization scoring, priority tier, and explainable rationale.

    Attributes
    ----------
    alert:
        The underlying :class:`~app.alert_engine.alert_model.Alert`.
    priority_score:
        Composite risk score on a 0.0 – 100.0 scale.
    priority_level:
        Priority level tier (P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW).
    reasons:
        Plain-English explanations for why this priority was assigned.
    score_breakdown:
        Detailed component-by-component scoring breakdown.
    """

    alert: Alert
    priority_score: float = 0.0
    priority_level: str = PRIORITY_P4
    reasons: list[str] = field(default_factory=list)
    score_breakdown: ScoreBreakdown = field(default_factory=ScoreBreakdown)

    def __post_init__(self) -> None:
        self.priority_score = max(0.0, min(100.0, float(self.priority_score)))
        if self.priority_level not in PRIORITY_ORDER:
            self.priority_level = PRIORITY_P4
        if not isinstance(self.reasons, list):
            self.reasons = list(self.reasons)

    # ------------------------------------------------------------------
    # Forwarded properties from underlying Alert
    # ------------------------------------------------------------------

    @property
    def alert_id(self) -> str:
        return self.alert.alert_id

    @property
    def timestamp(self) -> float:
        return self.alert.timestamp

    @property
    def detection_type(self) -> str:
        return self.alert.detection_type

    @property
    def severity(self) -> str:
        return self.alert.severity

    @property
    def source(self) -> str | None:
        return self.alert.source

    @property
    def destination(self) -> str | None:
        return self.alert.destination

    @property
    def protocol(self) -> str:
        return self.alert.protocol

    @property
    def confidence(self) -> float:
        return self.alert.confidence

    @property
    def description(self) -> str:
        return self.alert.description

    @property
    def evidence(self) -> dict[str, Any]:
        return self.alert.evidence

    @property
    def risk_context(self) -> str:
        return self.alert.risk_context

    @property
    def recommendations(self) -> list[str]:
        return self.alert.recommendations

    @property
    def detector(self) -> str:
        return self.alert.detector

    @property
    def event_count(self) -> int:
        return self.alert.event_count

    @property
    def status(self) -> str:
        return self.alert.status

    @property
    def first_seen(self) -> float:
        return self.alert.first_seen

    @property
    def last_seen(self) -> float:
        return self.alert.last_seen

    @property
    def priority_label(self) -> str:
        """Human-readable label for the priority tier."""
        return PRIORITY_LABELS.get(self.priority_level, self.priority_level)

    # ------------------------------------------------------------------
    # Comparison and sorting
    # ------------------------------------------------------------------

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, PrioritizedAlert):
            return NotImplemented
        return self.priority_score < other.priority_score

    def __le__(self, other: Any) -> bool:
        if not isinstance(other, PrioritizedAlert):
            return NotImplemented
        return self.priority_score <= other.priority_score

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, PrioritizedAlert):
            return NotImplemented
        return self.priority_score > other.priority_score

    def __ge__(self, other: Any) -> bool:
        if not isinstance(other, PrioritizedAlert):
            return NotImplemented
        return self.priority_score >= other.priority_score

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, PrioritizedAlert):
            return False
        return (
            self.alert.alert_id == other.alert.alert_id
            and self.priority_score == other.priority_score
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a unified dictionary combining base alert fields and prioritization metrics."""
        data = self.alert.to_dict()
        data["priority_score"] = round(self.priority_score, 2)
        data["priority_level"] = self.priority_level
        data["priority_label"] = self.priority_label
        data["priority_reasons"] = list(self.reasons)
        data["score_breakdown"] = self.score_breakdown.to_dict()
        return data

    def to_json(self, indent: int | None = None) -> str:
        """Return a JSON string representation."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
