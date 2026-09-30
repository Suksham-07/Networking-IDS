"""
NexIDS — Alert Prioritization Engine (Phase 5)
==============================================
Provides rule-based alert prioritization, composite risk scoring, triage bands,
and multi-vector attack correlation.
"""

from __future__ import annotations

from app.prioritizer.engine import AlertPrioritizer, PrioritizationEngine
from app.prioritizer.models import (
    PRIORITY_LABELS,
    PrioritizedAlert,
    ScoreBreakdown,
)
from app.prioritizer.rules import (
    PrioritizationConfig,
    determine_priority_level,
    evaluate_asset_criticality,
    evaluate_confidence,
    evaluate_correlation,
    evaluate_recurrence,
    evaluate_severity,
    is_critical_asset,
)
from app.utils.constants import (
    PRIORITY_ORDER,
    PRIORITY_P1,
    PRIORITY_P2,
    PRIORITY_P3,
    PRIORITY_P4,
)

__all__ = [
    "AlertPrioritizer",
    "PrioritizationEngine",
    "PrioritizedAlert",
    "ScoreBreakdown",
    "PrioritizationConfig",
    "PRIORITY_P1",
    "PRIORITY_P2",
    "PRIORITY_P3",
    "PRIORITY_P4",
    "PRIORITY_ORDER",
    "PRIORITY_LABELS",
    "determine_priority_level",
    "evaluate_severity",
    "evaluate_confidence",
    "evaluate_recurrence",
    "evaluate_asset_criticality",
    "evaluate_correlation",
    "is_critical_asset",
]
