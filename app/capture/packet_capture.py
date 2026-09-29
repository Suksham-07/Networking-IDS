"""
NexIDS Packet Capture
=====================
Manages live network packet capture using Scapy's ``sniff()`` function.

The ``PacketCapture`` class runs capture in a background thread so that
the rest of the application remains responsive.  Captured packets are
immediately parsed and stored in an in-memory buffer.

Usage
-----
::

    from app.capture.packet_capture import PacketCapture

    cap = PacketCapture(interface="eth0", packet_limit=1000)
    cap.start()
    # ... do other work ...
    cap.stop()
    parsed = cap.get_parsed_packets()
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

from app.capture.packet_parser import ParsedPacket, parse_packet
from app.utils.constants import (
    BPF_FILTER_ALL,
    DEFAULT_CAPTURE_COUNT,
    DEFAULT_CAPTURE_TIMEOUT,
    DEFAULT_INTERFACE,
)
from app.utils.logger import get_logger

log = get_logger(__name__)


class PacketCapture:
    """Live packet capture controller.

    Parameters
    ----------
    interface:
        Network interface name (e.g. ``"eth0"``, ``"Wi-Fi"``).
        ``None`` lets Scapy pick the default interface.
    bpf_filter:
        Berkeley Packet Filter string (e.g. ``"tcp"``, ``"port 80"``).
        Empty string captures everything.
    packet_limit:
        Maximum number of packets to capture before auto-stopping.
        ``0`` means unlimited.
    timeout:
        Seconds to run before auto-stopping.  ``0`` means run until
        :meth:`stop` is called.
    on_packet:
        Optional callback invoked with each *parsed* packet immediately
        after it is captured.  Useful for real-time alerting.
    """

    def __init__(
        self,
        interface: str | None = DEFAULT_INTERFACE,
        bpf_filter: str = BPF_FILTER_ALL,
        packet_limit: int = DEFAULT_CAPTURE_COUNT,
        timeout: int = DEFAULT_CAPTURE_TIMEOUT,
        on_packet: Callable[[ParsedPacket], None] | None = None,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_limit = packet_limit
        self.timeout = timeout
        self.on_packet = on_packet

        self._raw_packets: list[Any] = []
        self._parsed_packets: list[ParsedPacket] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False
        self._start_time: float | None = None
        self._stop_time: float | None = None

        log.info(
            "PacketCapture initialised — interface=%s  filter='%s'  limit=%d  timeout=%ds",
            self.interface or "auto",
            self.bpf_filter or "(none)",
            self.packet_limit,
            self.timeout,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start packet capture in a background thread.

        Raises
        ------
        RuntimeError
            If capture is already running.
        """
        if self._running:
            raise RuntimeError("PacketCapture is already running.")

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._capture_loop,
            name="nexids-capture",
            daemon=True,
        )
        self._running = True
        self._start_time = time.time()
        self._thread.start()
        log.info("Packet capture started.")

    def stop(self) -> None:
        """Signal the capture thread to stop and wait for it to finish."""
        if not self._running:
            log.warning("stop() called but capture is not running.")
            return

        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._running = False
        self._stop_time = time.time()
        log.info(
            "Packet capture stopped. Captured %d packets.",
            self.packet_count,
        )

    def is_running(self) -> bool:
        """Return ``True`` if the capture thread is active."""
        return self._running

    @property
    def packet_count(self) -> int:
        """Total number of successfully parsed packets captured so far."""
        with self._lock:
            return len(self._parsed_packets)

    def get_parsed_packets(self) -> list[ParsedPacket]:
        """Return a snapshot of all parsed packets collected so far.

        Returns
        -------
        list[ParsedPacket]
            A copy of the internal buffer — safe to iterate while capture
            continues in the background.
        """
        with self._lock:
            return list(self._parsed_packets)

    def get_stats(self) -> dict[str, Any]:
        """Return a dict of capture statistics.

        Returns
        -------
        dict
            Keys: ``running``, ``packet_count``, ``start_time``,
            ``elapsed_seconds``, ``interface``, ``filter``.
        """
        now = time.time()
        elapsed = (
            now - self._start_time
            if self._start_time and self._running
            else (
                self._stop_time - self._start_time
                if self._start_time and self._stop_time
                else 0.0
            )
        )
        return {
            "running": self._running,
            "packet_count": self.packet_count,
            "start_time": self._start_time,
            "elapsed_seconds": round(elapsed, 2),
            "interface": self.interface or "auto",
            "filter": self.bpf_filter or "(none)",
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _capture_loop(self) -> None:
        """Background thread body: runs Scapy sniff() and feeds packets."""
        try:
            from scapy.all import sniff  # type: ignore[import]
        except ImportError:
            log.error(
                "Scapy is not installed.  Install it with:  pip install scapy"
            )
            self._running = False
            return

        sniff_kwargs: dict[str, Any] = {
            "prn": self._handle_packet,
            "store": False,          # we manage storage ourselves
            "stop_filter": lambda _: self._stop_event.is_set(),
        }

        if self.interface:
            sniff_kwargs["iface"] = self.interface
        if self.bpf_filter:
            sniff_kwargs["filter"] = self.bpf_filter
        if self.packet_limit > 0:
            sniff_kwargs["count"] = self.packet_limit
        if self.timeout > 0:
            sniff_kwargs["timeout"] = self.timeout

        try:
            sniff(**sniff_kwargs)
        except Exception as exc:  # noqa: BLE001
            log.error("Capture thread error: %s", exc)
        finally:
            self._running = False

    def _handle_packet(self, pkt: Any) -> None:
        """Callback invoked by Scapy for each captured packet."""
        parsed = parse_packet(pkt)
        if parsed is None:
            return

        with self._lock:
            self._parsed_packets.append(parsed)

        if self.on_packet:
            try:
                self.on_packet(parsed)
            except Exception as exc:  # noqa: BLE001
                log.warning("on_packet callback raised: %s", exc)


# ---------------------------------------------------------------------------
# Convenience function for simple blocking captures
# ---------------------------------------------------------------------------

def capture_packets(
    interface: str | None = None,
    bpf_filter: str = "",
    count: int = 100,
    timeout: int = 30,
) -> list[ParsedPacket]:
    """Capture packets synchronously and return parsed results.

    This is a convenience wrapper for short, one-shot captures.
    For continuous monitoring use :class:`PacketCapture` directly.

    Parameters
    ----------
    interface:
        Network interface.  ``None`` = Scapy default.
    bpf_filter:
        BPF filter string.
    count:
        Number of packets to capture (``0`` = unlimited until timeout).
    timeout:
        Seconds to run.

    Returns
    -------
    list[ParsedPacket]
        Parsed packets.
    """
    try:
        from scapy.all import sniff  # type: ignore[import]
    except ImportError:
        log.error("Scapy is not installed.")
        return []

    raw: list[Any] = []

    def _collect(pkt: Any) -> None:
        raw.append(pkt)

    sniff_kwargs: dict[str, Any] = {
        "prn": _collect,
        "store": False,
        "count": count,
        "timeout": timeout,
    }
    if interface:
        sniff_kwargs["iface"] = interface
    if bpf_filter:
        sniff_kwargs["filter"] = bpf_filter

    try:
        sniff(**sniff_kwargs)
    except Exception as exc:  # noqa: BLE001
        log.error("capture_packets error: %s", exc)
        return []

    from app.capture.packet_parser import parse_packets
    return parse_packets(raw)
