"""
NexIDS Flask Dashboard Application Factory (Phase 7)
====================================================
Configures and launches the Flask web application for the NexIDS dashboard.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from flask import Flask, jsonify
from flask_cors import CORS

from app.dashboard.routes import bp
from app.dashboard.service import DashboardService
from app.utils.constants import PROJECT_NAME, REPORTS_DIR, VERSION


def create_app(
    service: DashboardService | None = None,
    test_config: dict[str, Any] | None = None,
) -> Flask:
    """Create and configure a Flask application instance for the NexIDS dashboard.

    Parameters
    ----------
    service:
        Optional :class:`DashboardService` instance. If None, a new service is created.
    test_config:
        Optional dictionary of test overrides for ``app.config``.

    Returns
    -------
    Flask
        Configured Flask web application.
    """
    root_dir = Path(__file__).resolve().parent.parent.parent
    template_folder = root_dir / "frontend" / "templates"
    static_folder = root_dir / "frontend" / "static"

    app = Flask(
        __name__,
        template_folder=str(template_folder),
        static_folder=str(static_folder),
    )

    CORS(app)

    # Core configuration
    app.config["PROJECT_NAME"] = PROJECT_NAME
    app.config["VERSION"] = VERSION
    app.config["REPORTS_DIR"] = str(root_dir / REPORTS_DIR)

    # Attach DashboardService instance
    if service is None:
        service = DashboardService(reports_dir=app.config["REPORTS_DIR"])
    app.config["DASHBOARD_SERVICE"] = service

    if test_config:
        app.config.update(test_config)

    # Register routes
    app.register_blueprint(bp)

    # Safe error handlers
    @app.errorhandler(404)
    def handle_not_found(err):
        return jsonify({"error": "Resource not found", "status": 404}), 404

    @app.errorhandler(500)
    def handle_server_error(err):
        return jsonify({"error": "An internal server error occurred", "status": 500}), 500

    return app
