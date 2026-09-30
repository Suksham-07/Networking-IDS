"""
NexIDS Constants
================
Project-wide constants shared by all modules.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Project metadata
# ---------------------------------------------------------------------------
PROJECT_NAME = "NexIDS"
VERSION = "0.1.0"
DESCRIPTION = "Network Intrusion Detection System — authorized monitoring only."

# ---------------------------------------------------------------------------
# Severity levels (ordered lowest → highest)
# ---------------------------------------------------------------------------
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_ORDER: dict[str, int] = {
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}

# ---------------------------------------------------------------------------
# Priority levels (Phase 5 Prioritizer: ordered lowest → highest)
# ---------------------------------------------------------------------------
PRIORITY_P4 = "P4_LOW"
PRIORITY_P3 = "P3_MEDIUM"
PRIORITY_P2 = "P2_HIGH"
PRIORITY_P1 = "P1_CRITICAL"

PRIORITY_ORDER: dict[str, int] = {
    PRIORITY_P4: 1,
    PRIORITY_P3: 2,
    PRIORITY_P2: 3,
    PRIORITY_P1: 4,
}

# ---------------------------------------------------------------------------
# Alert types
# ---------------------------------------------------------------------------
ALERT_PORT_SCAN = "Potential Port Scan"
ALERT_ICMP_ANOMALY = "Unusual ICMP Activity"
ALERT_ARP_ANOMALY = "Potential ARP Anomaly"
ALERT_TRAFFIC_ANOMALY = "Traffic Anomaly"

# ---------------------------------------------------------------------------
# Protocol names
# ---------------------------------------------------------------------------
PROTO_TCP = "TCP"
PROTO_UDP = "UDP"
PROTO_ICMP = "ICMP"
PROTO_ARP = "ARP"
PROTO_IP = "IP"
PROTO_UNKNOWN = "UNKNOWN"

# ---------------------------------------------------------------------------
# Detection thresholds (configurable defaults via app.utils.config)
# ---------------------------------------------------------------------------
from app.utils.config import get_config

_cfg = get_config()

PORT_SCAN_THRESHOLD = _cfg.port_scan_threshold
PORT_SCAN_WINDOW_SECONDS = int(_cfg.port_scan_window_seconds)

ICMP_FLOOD_THRESHOLD = _cfg.icmp_flood_threshold
ICMP_WINDOW_SECONDS = int(_cfg.icmp_window_seconds)

ARP_SPOOF_MAC_CHANGE = _cfg.arp_spoof_mac_change

TRAFFIC_BYTES_THRESHOLD = _cfg.traffic_bytes_threshold
TRAFFIC_WINDOW_SECONDS = int(_cfg.traffic_window_seconds)

# ---------------------------------------------------------------------------
# Capture defaults
# ---------------------------------------------------------------------------
DEFAULT_CAPTURE_TIMEOUT = _cfg.capture_timeout
DEFAULT_CAPTURE_COUNT = _cfg.capture_limit
DEFAULT_INTERFACE = _cfg.default_interface
BPF_FILTER_ALL = _cfg.bpf_filter

# ---------------------------------------------------------------------------
# Report output paths
# ---------------------------------------------------------------------------
REPORTS_DIR = str(_cfg.reports_dir.name if _cfg.reports_dir.is_absolute() else _cfg.reports_dir)

