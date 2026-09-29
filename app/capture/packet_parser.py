"""
NexIDS Packet Parser
====================
Converts raw Scapy packets into normalised, JSON-serialisable
``ParsedPacket`` dictionaries.

Each ``ParsedPacket`` is a plain ``dict`` with a guaranteed schema so that
detection modules can work with simple key access rather than Scapy layer
inspection.

Schema
------
::

    {
        "timestamp":  float,        # Unix epoch (seconds)
        "protocol":   str,          # "TCP" | "UDP" | "ICMP" | "ARP" | "IP" | "UNKNOWN"
        "src_ip":     str | None,
        "dst_ip":     str | None,
        "src_mac":    str | None,
        "dst_mac":    str | None,
        "src_port":   int | None,
        "dst_port":   int | None,
        "length":     int,          # packet length in bytes
        "flags":      str | None,   # TCP flags string e.g. "S", "SA"
        "ttl":        int | None,
        "icmp_type":  int | None,
        "icmp_code":  int | None,
        "arp_op":     int | None,   # 1=request, 2=reply
        "arp_psrc":   str | None,   # ARP sender IP
        "arp_pdst":   str | None,   # ARP target IP
        "arp_hwsrc":  str | None,   # ARP sender MAC
        "arp_hwdst":  str | None,   # ARP target MAC
        "raw":        bool,         # True when a Raw payload layer exists
    }
"""

from __future__ import annotations

import time
from typing import Any

from app.utils.constants import (
    PROTO_ARP,
    PROTO_ICMP,
    PROTO_IP,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_UNKNOWN,
)
from app.utils.logger import get_logger

log = get_logger(__name__)

# Type alias for the normalised packet dict
ParsedPacket = dict[str, Any]


def _empty_packet(ts: float | None = None) -> ParsedPacket:
    """Return a zeroed-out ParsedPacket template."""
    return {
        "timestamp": ts if ts is not None else time.time(),
        "protocol": PROTO_UNKNOWN,
        "src_ip": None,
        "dst_ip": None,
        "src_mac": None,
        "dst_mac": None,
        "src_port": None,
        "dst_port": None,
        "length": 0,
        "flags": None,
        "ttl": None,
        "icmp_type": None,
        "icmp_code": None,
        "arp_op": None,
        "arp_psrc": None,
        "arp_pdst": None,
        "arp_hwsrc": None,
        "arp_hwdst": None,
        "raw": False,
    }


def parse_packet(pkt: Any) -> ParsedPacket | None:
    """Normalise a Scapy packet into a ``ParsedPacket`` dict.

    Parameters
    ----------
    pkt:
        A Scapy ``Packet`` object as returned by ``sniff()`` or
        constructed synthetically in tests.

    Returns
    -------
    ParsedPacket | None
        The normalised dict, or ``None`` if ``pkt`` is ``None`` or
        cannot be processed.

    Notes
    -----
    * All fields default to ``None`` / ``0`` when absent so callers
      can safely access them without ``KeyError``.
    * MAC addresses are lower-cased for consistent comparison.
    * The function is deliberately non-raising — unexpected layer
      structures are logged as warnings and a best-effort dict is
      returned.
    """
    if pkt is None:
        log.debug("parse_packet received None — skipping.")
        return None

    try:
        # Scapy makes the packet timestamp available via pkt.time
        ts: float = float(getattr(pkt, "time", time.time()))
        result = _empty_packet(ts)
        result["length"] = len(pkt)

        # ------------------------------------------------------------------ #
        # Ethernet / MAC layer
        # ------------------------------------------------------------------ #
        if pkt.haslayer("Ether"):
            eth = pkt["Ether"]
            result["src_mac"] = str(eth.src).lower()
            result["dst_mac"] = str(eth.dst).lower()

        # ------------------------------------------------------------------ #
        # ARP
        # ------------------------------------------------------------------ #
        if pkt.haslayer("ARP"):
            arp = pkt["ARP"]
            result["protocol"] = PROTO_ARP
            result["arp_op"] = int(arp.op)
            result["arp_psrc"] = str(arp.psrc)
            result["arp_pdst"] = str(arp.pdst)
            result["arp_hwsrc"] = str(arp.hwsrc).lower()
            result["arp_hwdst"] = str(arp.hwdst).lower()
            # ARP carries IP-like addresses — expose them as src/dst_ip too
            result["src_ip"] = result["arp_psrc"]
            result["dst_ip"] = result["arp_pdst"]
            return result

        # ------------------------------------------------------------------ #
        # IP layer
        # ------------------------------------------------------------------ #
        if pkt.haslayer("IP"):
            ip = pkt["IP"]
            result["src_ip"] = str(ip.src)
            result["dst_ip"] = str(ip.dst)
            result["ttl"] = int(ip.ttl)
            result["protocol"] = PROTO_IP   # overridden below if transport known

            # ---- TCP ----
            if pkt.haslayer("TCP"):
                tcp = pkt["TCP"]
                result["protocol"] = PROTO_TCP
                result["src_port"] = int(tcp.sport)
                result["dst_port"] = int(tcp.dport)
                # Convert Scapy flags object to a compact string e.g. "S", "SA"
                result["flags"] = _tcp_flags_string(tcp.flags)

            # ---- UDP ----
            elif pkt.haslayer("UDP"):
                udp = pkt["UDP"]
                result["protocol"] = PROTO_UDP
                result["src_port"] = int(udp.sport)
                result["dst_port"] = int(udp.dport)

            # ---- ICMP ----
            elif pkt.haslayer("ICMP"):
                icmp = pkt["ICMP"]
                result["protocol"] = PROTO_ICMP
                result["icmp_type"] = int(icmp.type)
                result["icmp_code"] = int(icmp.code)

        # ------------------------------------------------------------------ #
        # Raw payload presence
        # ------------------------------------------------------------------ #
        result["raw"] = pkt.haslayer("Raw")

        return result

    except Exception as exc:  # noqa: BLE001
        log.warning("Failed to parse packet: %s", exc)
        return None


def _tcp_flags_string(flags: Any) -> str:
    """Convert a Scapy TCP flags field to a human-readable string.

    Parameters
    ----------
    flags:
        The ``tcp.flags`` value from Scapy (can be an int, string, or
        Scapy ``FlagValue`` object).

    Returns
    -------
    str
        A compact string such as ``"S"``, ``"SA"``, ``"PA"``, etc.
    """
    flag_map = [
        (0x001, "F"),   # FIN
        (0x002, "S"),   # SYN
        (0x004, "R"),   # RST
        (0x008, "P"),   # PSH
        (0x010, "A"),   # ACK
        (0x020, "U"),   # URG
        (0x040, "E"),   # ECE
        (0x080, "C"),   # CWR
        (0x100, "N"),   # NS
    ]
    try:
        int_flags = int(flags)
        return "".join(letter for bit, letter in flag_map if int_flags & bit)
    except (TypeError, ValueError):
        return str(flags)


def parse_packets(pkts: list[Any]) -> list[ParsedPacket]:
    """Batch-parse a list of Scapy packets.

    Parameters
    ----------
    pkts:
        Iterable of Scapy packet objects.

    Returns
    -------
    list[ParsedPacket]
        Successfully parsed packets; ``None`` results are silently dropped.
    """
    if not pkts:
        return []

    results: list[ParsedPacket] = []
    for pkt in pkts:
        parsed = parse_packet(pkt)
        if parsed is not None:
            results.append(parsed)

    log.debug("Parsed %d / %d packets successfully.", len(results), len(pkts))
    return results
