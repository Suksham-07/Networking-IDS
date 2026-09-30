"""
NexIDS Dashboard Module (Phase 7)
=================================
Flask-based SOC dashboard and REST API for real-time network intrusion detection
monitoring, alert triage, and security report generation.
"""

from __future__ import annotations

from app.dashboard.app import create_app
from app.dashboard.service import DashboardService

__all__ = ["create_app", "DashboardService"]
