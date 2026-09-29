"""
NexIDS — Alert Engine (Phase 4)
================================
Responsible for generating structured, explainable security alerts from
detection events, applying enrichment (risk context & actionable recommendations),
deduplication/aggregation, and maintaining alert state.
"""

from __future__ import annotations

from app.alert_engine.alert_manager import AlertEngine, AlertManager
from app.alert_engine.alert_model import (
    STATUS_ACKNOWLEDGED,
    STATUS_NEW,
    STATUS_RESOLVED,
    STATUS_SUPPRESSED,
    VALID_STATUSES,
    Alert,
    determine_base_severity,
    generate_recommendations,
    generate_risk_context,
)

__all__ = [
    "Alert",
    "AlertManager",
    "AlertEngine",
    "determine_base_severity",
    "generate_risk_context",
    "generate_recommendations",
    "STATUS_NEW",
    "STATUS_ACKNOWLEDGED",
    "STATUS_RESOLVED",
    "STATUS_SUPPRESSED",
    "VALID_STATUSES",
]
