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
# Detection thresholds (configurable defaults)
# ---------------------------------------------------------------------------
PORT_SCAN_THRESHOLD = 15          # unique ports per source in the window
PORT_SCAN_WINDOW_SECONDS = 10     # sliding window for port scan detection

ICMP_FLOOD_THRESHOLD = 50         # ICMP packets per source in the window
ICMP_WINDOW_SECONDS = 5

ARP_SPOOF_MAC_CHANGE = True       # flag if an IP→MAC mapping changes

TRAFFIC_BYTES_THRESHOLD = 10_000_000   # 10 MB in window flags anomaly
TRAFFIC_WINDOW_SECONDS = 10

# ---------------------------------------------------------------------------
# Capture defaults
# ---------------------------------------------------------------------------
DEFAULT_CAPTURE_TIMEOUT = 0       # 0 = run until stopped
DEFAULT_CAPTURE_COUNT = 0         # 0 = unlimited
DEFAULT_INTERFACE = None          # None = Scapy default / first available
BPF_FILTER_ALL = ""               # empty = capture everything

# ---------------------------------------------------------------------------
# Report output paths
# ---------------------------------------------------------------------------
REPORTS_DIR = "reports"
