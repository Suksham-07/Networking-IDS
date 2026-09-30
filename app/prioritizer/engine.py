"""
NexIDS Alert Prioritization Engine (Phase 5)
============================================
Orchestrates alert scoring, multi-vector correlation, risk classification,
and triage filtering.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from app.alert_engine.alert_model import Alert
from app.prioritizer.models import (
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
)
from app.utils.constants import (
    PRIORITY_ORDER,
    PRIORITY_P1,
    PRIORITY_P2,
    PRIORITY_P3,
    PRIORITY_P4,
)
from app.utils.logger import get_logger

log = get_logger(__name__)


class AlertPrioritizer:
    """Prioritizes and triages security alerts based on explainable risk rules.

    Parameters
    ----------
    config:
        Optional :class:`PrioritizationConfig` specifying custom weights and thresholds.
    """

    def __init__(self, config: PrioritizationConfig | None = None) -> None:
        self.config = config or PrioritizationConfig()

    def prioritize_alert(
        self,
        alert: Alert,
        context_alerts: list[Alert] | None = None,
    ) -> PrioritizedAlert:
        """Compute the composite risk score and assign priority for a single alert.

        Parameters
        ----------
        alert:
            The :class:`~app.alert_engine.alert_model.Alert` to prioritize.
        context_alerts:
            Optional collection of other recent alerts used to detect multi-vector correlation.

        Returns
        -------
        PrioritizedAlert
            Enriched alert with composite score, priority level, and detailed explanation.
        """
        sev_score, sev_reason = evaluate_severity(alert, self.config)
        conf_score, conf_reason = evaluate_confidence(alert, self.config)
        rec_boost, rec_reason = evaluate_recurrence(alert, self.config)
        asset_boost, asset_reason = evaluate_asset_criticality(alert, self.config)
        corr_boost, corr_reason = evaluate_correlation(alert, context_alerts, self.config)

        total_score = min(
            100.0,
            max(
                0.0,
                round(
                    sev_score + conf_score + rec_boost + asset_boost + corr_boost,
                    2,
                ),
            ),
        )

        priority_level = determine_priority_level(total_score, self.config)

        reasons: list[str] = [sev_reason, conf_reason]
        if rec_reason:
            reasons.append(rec_reason)
        if asset_reason:
            reasons.append(asset_reason)
        if corr_reason:
            reasons.append(corr_reason)

        breakdown = ScoreBreakdown(
            base_severity_score=round(sev_score, 2),
            confidence_score=round(conf_score, 2),
            recurrence_boost=round(rec_boost, 2),
            asset_criticality_boost=round(asset_boost, 2),
            correlation_boost=round(corr_boost, 2),
            total_score=total_score,
            priority_level=priority_level,
            reasons=reasons,
        )

        return PrioritizedAlert(
            alert=alert,
            priority_score=total_score,
            priority_level=priority_level,
            reasons=reasons,
            score_breakdown=breakdown,
        )

    # Convenience alias
    prioritize = prioritize_alert

    def prioritize_alerts(
        self,
        alerts: list[Alert],
        sort_by_priority: bool = True,
    ) -> list[PrioritizedAlert]:
        """Prioritize a batch of alerts with full cross-alert correlation analysis.

        Parameters
        ----------
        alerts:
            List of alerts to prioritize.
        sort_by_priority:
            If True, sorts returned alerts in descending order of priority score.

        Returns
        -------
        list[PrioritizedAlert]
            Prioritized alert objects.
        """
        if not alerts:
            return []

        prioritized: list[PrioritizedAlert] = []
        for alert in alerts:
            p_alert = self.prioritize_alert(alert, context_alerts=alerts)
            prioritized.append(p_alert)

        if sort_by_priority:
            prioritized.sort(key=lambda a: (a.priority_score, a.timestamp), reverse=True)

        return prioritized

    # Convenience alias
    prioritize_many = prioritize_alerts

    # ------------------------------------------------------------------
    # Filtering & Triage utilities
    # ------------------------------------------------------------------

    def filter_by_priority(
        self,
        alerts: list[PrioritizedAlert],
        min_level: str | None = None,
        levels: list[str] | set[str] | None = None,
    ) -> list[PrioritizedAlert]:
        """Filter alerts by minimum priority tier or exact priority levels."""
        if not alerts:
            return []

        result = alerts
        if min_level and min_level in PRIORITY_ORDER:
            min_rank = PRIORITY_ORDER[min_level]
            result = [a for a in result if PRIORITY_ORDER.get(a.priority_level, 0) >= min_rank]

        if levels is not None:
            level_set = set(levels)
            result = [a for a in result if a.priority_level in level_set]

        return result

    def filter_by_asset(
        self,
        alerts: list[PrioritizedAlert],
        asset_ip: str,
    ) -> list[PrioritizedAlert]:
        """Filter alerts involving the specified asset as source or destination."""
        if not alerts or not asset_ip:
            return []
        target = asset_ip.strip()
        return [
            a for a in alerts
            if (a.source and a.source.strip() == target)
            or (a.destination and a.destination.strip() == target)
        ]

    def filter_by_score(
        self,
        alerts: list[PrioritizedAlert],
        min_score: float = 0.0,
        max_score: float = 100.0,
    ) -> list[PrioritizedAlert]:
        """Filter alerts within a priority score range [min_score, max_score]."""
        if not alerts:
            return []
        return [
            a for a in alerts
            if min_score <= a.priority_score <= max_score
        ]

    def get_top_threats(
        self,
        alerts: list[PrioritizedAlert],
        limit: int = 5,
    ) -> list[PrioritizedAlert]:
        """Retrieve the top N highest-risk alerts sorted by priority score."""
        if not alerts:
            return []
        sorted_alerts = sorted(alerts, key=lambda a: (a.priority_score, a.timestamp), reverse=True)
        return sorted_alerts[: max(1, limit)]

    def get_triage_summary(
        self,
        alerts: list[PrioritizedAlert],
    ) -> dict[str, Any]:
        """Generate high-level triage statistics and incident metrics.

        Parameters
        ----------
        alerts:
            List of prioritized alerts.

        Returns
        -------
        dict[str, Any]
            Statistical summary containing counts, averages, and top offenders/targets.
        """
        if not alerts:
            return {
                "total_alerts": 0,
                "priority_counts": {
                    PRIORITY_P1: 0,
                    PRIORITY_P2: 0,
                    PRIORITY_P3: 0,
                    PRIORITY_P4: 0,
                },
                "average_score": 0.0,
                "max_score": 0.0,
                "top_offenders": [],
                "top_targets": [],
                "critical_alert_count": 0,
                "recommended_action": "No alerts to triage.",
            }

        counts: dict[str, int] = {
            PRIORITY_P1: 0,
            PRIORITY_P2: 0,
            PRIORITY_P3: 0,
            PRIORITY_P4: 0,
        }
        for a in alerts:
            if a.priority_level in counts:
                counts[a.priority_level] += 1
            else:
                counts[PRIORITY_P4] += 1

        scores = [a.priority_score for a in alerts]
        avg_score = round(sum(scores) / len(scores), 2)
        max_score = round(max(scores), 2)

        # Source aggregation
        src_map: dict[str, list[PrioritizedAlert]] = {}
        for a in alerts:
            if a.source:
                src_map.setdefault(a.source, []).append(a)

        top_offenders = []
        for src, src_alerts in sorted(src_map.items(), key=lambda item: len(item[1]), reverse=True)[:5]:
            top_offenders.append({
                "source": src,
                "alert_count": len(src_alerts),
                "max_score": max(sa.priority_score for sa in src_alerts),
                "highest_priority": max(
                    (sa.priority_level for sa in src_alerts),
                    key=lambda lvl: PRIORITY_ORDER.get(lvl, 0),
                ),
            })

        # Destination aggregation
        dst_map: dict[str, list[PrioritizedAlert]] = {}
        for a in alerts:
            if a.destination:
                dst_map.setdefault(a.destination, []).append(a)

        top_targets = []
        for dst, dst_alerts in sorted(dst_map.items(), key=lambda item: len(item[1]), reverse=True)[:5]:
            top_targets.append({
                "destination": dst,
                "alert_count": len(dst_alerts),
                "max_score": max(da.priority_score for da in dst_alerts),
                "highest_priority": max(
                    (da.priority_level for da in dst_alerts),
                    key=lambda lvl: PRIORITY_ORDER.get(lvl, 0),
                ),
            })

        # Recommended triage recommendation
        p1_count = counts[PRIORITY_P1]
        p2_count = counts[PRIORITY_P2]
        if p1_count > 0:
            action = f"URGENT: {p1_count} P1 Critical alert(s) detected. Immediate investigation required."
        elif p2_count > 0:
            action = f"ELEVATED: {p2_count} P2 High-priority alert(s) requiring prompt review."
        elif counts[PRIORITY_P3] > 0:
            action = "MODERATE: Standard priority alerts present; review during routine triage."
        else:
            action = "LOW: Informational alerts only; no immediate intervention required."

        return {
            "total_alerts": len(alerts),
            "priority_counts": counts,
            "average_score": avg_score,
            "max_score": max_score,
            "top_offenders": top_offenders,
            "top_targets": top_targets,
            "critical_alert_count": p1_count,
            "recommended_action": action,
        }


# Backwards compatibility / alternative alias
PrioritizationEngine = AlertPrioritizer
