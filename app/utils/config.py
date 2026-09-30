"""
NexIDS Configuration Management (Phase 8)
=========================================
Centralised configuration for thresholds, timeouts, network interfaces,
and execution modes.

Values are read from environment variables (e.g. via .env or system environment)
with robust type coercion and safe defaults. Secrets are never loaded or stored here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Default root directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent.parent


def _get_env_str(key: str, default: str) -> str:
    """Retrieve string from environment or return default."""
    return os.environ.get(key, default).strip()


def _get_env_int(key: str, default: int) -> int:
    """Retrieve integer from environment or return default."""
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return int(val.strip())
    except ValueError:
        return default


def _get_env_float(key: str, default: float) -> float:
    """Retrieve float from environment or return default."""
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return float(val.strip())
    except ValueError:
        return default


def _get_env_bool(key: str, default: bool) -> bool:
    """Retrieve boolean from environment or return default."""
    val = os.environ.get(key)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "on", "enabled")


@dataclass
class NexIDSConfig:
    """Configuration settings for the NexIDS system."""

    # Application Mode & Server
    mode: str = "demo"                       # "demo", "live", "web", "cli"
    host: str = "127.0.0.1"                  # Web dashboard binding host
    port: int = 5000                         # Web dashboard binding port
    log_level: str = "INFO"                  # DEBUG, INFO, WARNING, ERROR
    refresh_interval: int = 3                # Dashboard polling interval in seconds

    # Directory Paths
    reports_dir: Path = BASE_DIR / "reports"
    logs_dir: Path = BASE_DIR / "logs"

    # Capture Settings
    default_interface: str | None = None     # None = auto-detect
    capture_timeout: int = 0                 # 0 = run until stopped
    capture_limit: int = 0                   # 0 = unlimited packets
    bpf_filter: str = ""                     # BPF capture filter

    # Detection Thresholds
    port_scan_threshold: int = 15            # Unique ports per source in window
    port_scan_window_seconds: float = 10.0   # Sliding window (seconds)

    icmp_flood_threshold: int = 50           # ICMP packets per source in window
    icmp_window_seconds: float = 5.0         # Sliding window (seconds)

    arp_spoof_mac_change: bool = True        # Flag if IP-MAC mapping mutates

    traffic_bytes_threshold: int = 10_000_000  # 10 MB burst in window
    traffic_window_seconds: float = 10.0     # Sliding window (seconds)

    # Confidence Thresholds
    min_alert_confidence: float = 0.5        # Minimum confidence to promote event to alert

    @classmethod
    def from_env(cls) -> NexIDSConfig:
        """Construct configuration instance populated from environment variables."""
        reports_dir_str = _get_env_str("NEXIDS_REPORT_DIR", str(BASE_DIR / "reports"))
        logs_dir_str = _get_env_str("NEXIDS_LOG_DIR", str(BASE_DIR / "logs"))
        iface = os.environ.get("NEXIDS_INTERFACE")
        iface_val = iface.strip() if iface and iface.strip() else None

        return cls(
            mode=_get_env_str("NEXIDS_MODE", "demo"),
            host=_get_env_str("NEXIDS_HOST", "127.0.0.1"),
            port=_get_env_int("NEXIDS_PORT", 5000),
            log_level=_get_env_str("NEXIDS_LOG_LEVEL", "INFO").upper(),
            refresh_interval=_get_env_int("NEXIDS_REFRESH_INTERVAL", 3),
            reports_dir=Path(reports_dir_str),
            logs_dir=Path(logs_dir_str),
            default_interface=iface_val,
            capture_timeout=_get_env_int("NEXIDS_CAPTURE_TIMEOUT", 0),
            capture_limit=_get_env_int("NEXIDS_CAPTURE_LIMIT", 0),
            bpf_filter=_get_env_str("NEXIDS_BPF_FILTER", ""),
            port_scan_threshold=_get_env_int("NEXIDS_PORT_SCAN_THRESHOLD", 15),
            port_scan_window_seconds=_get_env_float("NEXIDS_PORT_SCAN_WINDOW", 10.0),
            icmp_flood_threshold=_get_env_int("NEXIDS_ICMP_FLOOD_THRESHOLD", 50),
            icmp_window_seconds=_get_env_float("NEXIDS_ICMP_WINDOW", 5.0),
            arp_spoof_mac_change=_get_env_bool("NEXIDS_ARP_SPOOF_MAC_CHANGE", True),
            traffic_bytes_threshold=_get_env_int("NEXIDS_TRAFFIC_BYTES_THRESHOLD", 10_000_000),
            traffic_window_seconds=_get_env_float("NEXIDS_TRAFFIC_WINDOW", 10.0),
            min_alert_confidence=_get_env_float("NEXIDS_MIN_ALERT_CONFIDENCE", 0.5),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to a sanitized dictionary for reporting and debugging."""
        return {
            "mode": self.mode,
            "host": self.host,
            "port": self.port,
            "log_level": self.log_level,
            "refresh_interval": self.refresh_interval,
            "reports_dir": str(self.reports_dir),
            "logs_dir": str(self.logs_dir),
            "default_interface": self.default_interface or "auto",
            "capture_timeout": self.capture_timeout,
            "capture_limit": self.capture_limit,
            "bpf_filter": self.bpf_filter or "all",
            "port_scan_threshold": self.port_scan_threshold,
            "port_scan_window_seconds": self.port_scan_window_seconds,
            "icmp_flood_threshold": self.icmp_flood_threshold,
            "icmp_window_seconds": self.icmp_window_seconds,
            "arp_spoof_mac_change": self.arp_spoof_mac_change,
            "traffic_bytes_threshold": self.traffic_bytes_threshold,
            "traffic_window_seconds": self.traffic_window_seconds,
            "min_alert_confidence": self.min_alert_confidence,
        }


# Global default configuration instance
config = NexIDSConfig.from_env()


def get_config() -> NexIDSConfig:
    """Return the global configuration instance."""
    global config
    return config
