"""
NexIDS — Network Intrusion Detection System
==========================================
Authorised network monitoring, pattern detection, alert prioritisation,
and security audit reporting.

Entry Point
-----------
Run with::

    python main.py                        # Default: start web-based SOC dashboard
    python main.py --demo                 # Run complete synthetic demonstration (safe CLI demo)
    python main.py --cli                  # Run CLI packet capture (auto interface)
    python main.py --cli -i eth0          # Run CLI capture on specific interface
    python main.py --web --port 8080      # Start web dashboard on custom port
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from app.alert_engine.alert_manager import AlertManager
from app.capture.packet_capture import PacketCapture
from app.detection.engine import DetectionEngine
from app.detection.models import DetectionEvent
from app.prioritizer.engine import AlertPrioritizer
from app.reporter.report_generator import ReportGenerator
from app.utils.config import get_config
from app.utils.constants import (
    ALERT_ARP_ANOMALY,
    ALERT_ICMP_ANOMALY,
    ALERT_PORT_SCAN,
    ALERT_TRAFFIC_ANOMALY,
    PROJECT_NAME,
    VERSION,
)
from app.utils.logger import get_logger

log = get_logger(__name__, level=logging.INFO)


def _ensure_directories() -> None:
    """Ensure essential directories exist before application operations."""
    cfg = get_config()
    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    cfg.logs_dir.mkdir(parents=True, exist_ok=True)


def _build_arg_parser() -> argparse.ArgumentParser:
    cfg = get_config()
    parser = argparse.ArgumentParser(
        prog="nexids",
        description=f"{PROJECT_NAME} v{VERSION} — Defensive Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--web", "--dashboard",
        action="store_true",
        dest="run_dashboard",
        default=False,
        help="Launch the web-based SOC dashboard (default if no capture flags specified).",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        dest="run_cli",
        default=False,
        help="Run in command-line packet capture mode.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        dest="run_demo",
        default=False,
        help="Execute safe synthetic demonstration scenario and export sample reports.",
    )
    parser.add_argument(
        "--interface", "-i",
        default=cfg.default_interface,
        help="Network interface to monitor (default: auto-detect).",
    )
    parser.add_argument(
        "--filter", "-f",
        default=cfg.bpf_filter,
        dest="bpf_filter",
        help="BPF capture filter (e.g. 'tcp', 'port 80').  Default: all traffic.",
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=cfg.capture_limit,
        help="Stop after capturing this many packets.  0 = unlimited.",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=cfg.capture_timeout,
        help="Stop after this many seconds.  0 = run until Ctrl-C.",
    )
    parser.add_argument(
        "--log-level",
        default=cfg.log_level,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help=f"Minimum log level (default: {cfg.log_level}).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=cfg.port,
        help=f"Port for the web dashboard (default: {cfg.port}).",
    )
    parser.add_argument(
        "--host",
        default=cfg.host,
        help=f"Host interface to bind the web dashboard (default: {cfg.host}).",
    )
    return parser


def _run_demo_cli() -> int:
    """Run an end-to-end synthetic demonstration scenario in the terminal."""
    log.info("=" * 65)
    log.info("%s v%s -- [DEMO MODE] Synthetic Scenario Execution", PROJECT_NAME, VERSION)
    log.info("=" * 65)
    log.info("Generating safe synthetic network detection events...")

    engine = DetectionEngine()
    manager = AlertManager()
    prioritizer = AlertPrioritizer()
    reporter = ReportGenerator()

    now = time.time()
    synthetic_events = [
        DetectionEvent(
            detection_type=ALERT_ARP_ANOMALY,
            source="192.168.1.150",
            destination="192.168.1.1",
            protocol="ARP",
            confidence=0.95,
            description="Potential ARP spoofing: MAC address mutated for default gateway.",
            evidence={
                "ip_address": "192.168.1.1",
                "previous_mac": "00:11:22:33:44:55",
                "observed_mac": "aa:bb:cc:dd:ee:ff",
            },
            detector="ARPAnomalyDetector",
            timestamp=now - 30,
        ),
        DetectionEvent(
            detection_type=ALERT_PORT_SCAN,
            source="192.168.1.150",
            destination="192.168.1.1",
            protocol="TCP",
            confidence=0.92,
            description="Potential port scan: 42 distinct destination ports probed in 6s.",
            evidence={
                "distinct_ports": 42,
                "scanned_ports": [21, 22, 23, 25, 53, 80, 443, 8080],
            },
            detector="PortScanDetector",
            timestamp=now - 20,
        ),
        DetectionEvent(
            detection_type=ALERT_TRAFFIC_ANOMALY,
            source="192.168.1.200",
            destination="10.0.0.10",
            protocol="UDP",
            confidence=0.87,
            description="Traffic anomaly: high volume packet burst exceeding threshold.",
            evidence={"pps": 6500.0, "bps": 12800000.0},
            detector="TrafficAnomalyDetector",
            timestamp=now - 10,
        ),
        DetectionEvent(
            detection_type=ALERT_ICMP_ANOMALY,
            source="10.0.0.88",
            destination="192.168.1.254",
            protocol="ICMP",
            confidence=0.75,
            description="Unusual ICMP activity: 55 echo requests observed.",
            evidence={"packet_count": 55, "possible_reconnaissance": True},
            detector="ICMPAnomalyDetector",
            timestamp=now - 5,
        ),
    ]

    log.info("Processing %d synthetic events through Alert Engine...", len(synthetic_events))
    created_alerts = manager.process_events(synthetic_events)
    log.info("Created %d structured security alerts.", len(created_alerts))

    log.info("Prioritizing alerts with explainable rule engine...")
    prioritized = prioritizer.prioritize_alerts(manager.get_alerts())

    print("\n" + "=" * 80)
    print(f"{'PRIORITY':<14} | {'SEVERITY':<10} | {'SCORE':<7} | {'ALERT TYPE':<24} | {'SOURCE'}")
    print("-" * 80)
    for p in prioritized:
        print(f"{p.priority_level:<14} | {p.severity:<10} | {p.priority_score:<7.1f} | {p.detection_type:<24} | {p.source or 'N/A'}")
    print("=" * 80 + "\n")

    log.info("Generating demo audit reports...")
    json_path = reporter.generate_json_report(
        alerts=manager.get_alerts(),
        prioritized_alerts=prioritized,
        session_start=now - 60,
        session_end=now,
        packets_observed=18450,
        report_title=f"{PROJECT_NAME} Demo Security Audit Report",
    )
    html_path = reporter.generate_html_report(
        alerts=manager.get_alerts(),
        prioritized_alerts=prioritized,
        session_start=now - 60,
        session_end=now,
        packets_observed=18450,
        report_title=f"{PROJECT_NAME} Demo Security Audit Report",
    )

    log.info("Demo JSON Report written: %s", json_path.resolve())
    log.info("Demo HTML Report written: %s", html_path.resolve())
    log.info("Demo completed successfully. System status: READY.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Application entry point.

    Parameters
    ----------
    argv:
        Argument list (defaults to ``sys.argv[1:]``).

    Returns
    -------
    int
        Exit code (0 = success, non-zero = error).
    """
    _ensure_directories()
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Re-configure logger with requested level
    numeric_level = getattr(logging, args.log_level.upper(), logging.INFO)
    log.setLevel(numeric_level)
    for handler in log.handlers:
        handler.setLevel(numeric_level)

    # 1. Demo Mode
    if args.run_demo:
        return _run_demo_cli()

    # Determine whether to run web or CLI
    # If explicitly asked for web, or if neither cli nor capture parameters were specified: run web
    is_cli_requested = args.run_cli or (
        argv is not None and any(arg in argv for arg in ("-i", "--interface", "-f", "--filter", "-c", "--count", "-t", "--timeout", "--cli"))
    )

    # 2. Web Dashboard Mode (Default unless CLI is requested)
    if args.run_dashboard or not is_cli_requested:
        from app.dashboard import create_app
        app = create_app()
        log.info("=" * 60)
        log.info("%s v%s — Defensive SOC Dashboard", PROJECT_NAME, VERSION)
        log.info("Web interface accessible at: http://%s:%d", args.host, args.port)
        log.info("Pass --cli for command-line packet capture or --demo for synthetic demo.")
        log.info("=" * 60)
        try:
            app.run(host=args.host, port=args.port, debug=False)
            return 0
        except Exception as exc:
            log.error("Failed to start Web Dashboard on %s:%d: %s", args.host, args.port, exc)
            return 1

    # 3. CLI Packet Capture Mode
    log.info("=" * 60)
    log.info("%s v%s — Authorised Network Monitoring (CLI)", PROJECT_NAME, VERSION)
    log.info("=" * 60)
    log.info(
        "Config: interface=%s  filter='%s'  count=%d  timeout=%ds",
        args.interface or "auto",
        args.bpf_filter or "all",
        args.count,
        args.timeout,
    )

    detection_engine = DetectionEngine()
    alert_manager = AlertManager()
    prioritizer = AlertPrioritizer()
    reporter = ReportGenerator()
    start_time = time.time()

    def _on_packet(parsed_pkt):
        try:
            events = detection_engine.inspect(parsed_pkt)
            if events:
                new_alerts = alert_manager.process_events(events)
                for a in new_alerts:
                    log.warning("[%s] %s from %s -> %s", a.severity, a.detection_type, a.source, a.destination)
        except Exception as err:
            log.debug("Packet inspection error: %s", err)

    capture = PacketCapture(
        interface=args.interface,
        bpf_filter=args.bpf_filter,
        packet_limit=args.count,
        timeout=args.timeout,
        on_packet=_on_packet,
    )

    try:
        capture.start()
        log.info("Monitoring active — press Ctrl-C to stop.")

        while capture.is_running():
            time.sleep(1)
            stats = capture.get_stats()
            log.debug(
                "Status: packets=%d  elapsed=%.1fs",
                stats["packet_count"],
                stats["elapsed_seconds"],
            )

    except KeyboardInterrupt:
        log.info("Interrupted by user — stopping capture...")
    except Exception as exc:  # noqa: BLE001
        log.error("Unexpected error during capture: %s", exc)
        return 1
    finally:
        if capture.is_running():
            capture.stop()

    stop_time = time.time()
    stats = capture.get_stats()
    log.info(
        "Session complete: %d packets captured in %.1f seconds.",
        stats["packet_count"],
        stats["elapsed_seconds"],
    )

    alerts = alert_manager.get_alerts()
    log.info("Alerts detected during session: %d", len(alerts))
    if alerts:
        prioritized = prioritizer.prioritize_alerts(alerts)
        log.info("Top alert: %s (%s, score=%.1f)", prioritized[0].detection_type, prioritized[0].priority_level, prioritized[0].priority_score)
        # Generate summary report
        json_path = reporter.generate_json_report(
            alerts=alerts,
            prioritized_alerts=prioritized,
            session_start=start_time,
            session_end=stop_time,
            packets_observed=stats["packet_count"],
        )
        log.info("Session report saved to: %s", json_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
