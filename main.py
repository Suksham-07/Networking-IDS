"""
NexIDS — Network Intrusion Detection System
==========================================
Authorised network monitoring and intrusion detection.

Entry Point
-----------
Run with::

    python main.py [--interface <iface>] [--filter <bpf>]
                   [--count <n>]        [--timeout <s>]
                   [--log-level <level>]

Examples::

    python main.py                        # default interface, unlimited
    python main.py --interface eth0       # specific interface
    python main.py --count 500            # stop after 500 packets
    python main.py --timeout 60           # stop after 60 s
    python main.py --filter "tcp port 80" # only HTTP traffic

Current Status (Phase 1 & 2)
-----------------------------
* Project structure fully initialised.
* Packet capture (``PacketCapture``) implemented.
* Packet parsing (``parse_packet`` / ``parse_packets``) implemented.
* Detection, alerting, prioritisation, dashboard — planned for later phases.
"""

from __future__ import annotations

import argparse
import logging
import sys

from app.capture.packet_capture import PacketCapture
from app.utils.constants import PROJECT_NAME, VERSION
from app.utils.logger import get_logger

log = get_logger(__name__, level=logging.INFO)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nexids",
        description=f"{PROJECT_NAME} v{VERSION} — Authorised Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--interface", "-i",
        default=None,
        help="Network interface to monitor (default: auto-detect).",
    )
    parser.add_argument(
        "--filter", "-f",
        default="",
        dest="bpf_filter",
        help="BPF capture filter (e.g. 'tcp', 'port 80').  Default: all traffic.",
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=0,
        help="Stop after capturing this many packets.  0 = unlimited.",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=0,
        help="Stop after this many seconds.  0 = run until Ctrl-C.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Minimum log level (default: INFO).",
    )
    return parser


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
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Re-configure logger with the requested level
    numeric_level = getattr(logging, args.log_level.upper(), logging.INFO)
    log.setLevel(numeric_level)
    for handler in log.handlers:
        handler.setLevel(numeric_level)

    log.info("=" * 60)
    log.info("%s v%s — Authorised Network Monitoring", PROJECT_NAME, VERSION)
    log.info("=" * 60)
    log.info(
        "Config: interface=%s  filter='%s'  count=%d  timeout=%ds",
        args.interface or "auto",
        args.bpf_filter or "all",
        args.count,
        args.timeout,
    )

    capture = PacketCapture(
        interface=args.interface,
        bpf_filter=args.bpf_filter,
        packet_limit=args.count,
        timeout=args.timeout,
    )

    try:
        capture.start()
        log.info("Monitoring active — press Ctrl-C to stop.")

        # Block main thread; the capture runs in a daemon thread
        while capture.is_running():
            import time
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
        log.error("Unexpected error: %s", exc)
        return 1
    finally:
        if capture.is_running():
            capture.stop()

    stats = capture.get_stats()
    log.info(
        "Session complete: %d packets captured in %.1f seconds.",
        stats["packet_count"],
        stats["elapsed_seconds"],
    )

    # ------------------------------------------------------------------
    # Placeholder summary (detection output added in later phases)
    # ------------------------------------------------------------------
    parsed = capture.get_parsed_packets()
    if parsed:
        from collections import Counter
        proto_counts = Counter(p["protocol"] for p in parsed)
        log.info("Protocol breakdown: %s", dict(proto_counts))

    return 0


if __name__ == "__main__":
    sys.exit(main())
