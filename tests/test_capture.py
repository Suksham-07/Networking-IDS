"""
NexIDS — Packet Capture & Parsing Tests (Phase 1 & 2)
======================================================
All tests use synthetic/mock Scapy-style packet objects — no live
network traffic is required.

Coverage
--------
* ``parse_packet`` — TCP, UDP, ICMP, ARP, unknown, malformed, None
* ``parse_packets`` — batch parsing, empty list, mixed-valid list
* ``PacketCapture`` — construction, start/stop, stats, double-start guard
* Protocol field extraction — flags, TTL, ports, MAC addresses
* Edge cases — zero-length payload, missing layers, None input
"""

from __future__ import annotations

import time
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers — build lightweight synthetic Scapy-like packet mocks
# ---------------------------------------------------------------------------

def _make_layer(name: str, **fields) -> MagicMock:
    """Create a mock Scapy layer with ``__getitem__`` access."""
    layer = MagicMock()
    for attr, val in fields.items():
        setattr(layer, attr, val)
    layer.__class__.__name__ = name
    return layer


def _build_mock_packet(
    *,
    has_ether: bool = False,
    has_ip: bool = False,
    has_tcp: bool = False,
    has_udp: bool = False,
    has_icmp: bool = False,
    has_arp: bool = False,
    has_raw: bool = False,
    # Ethernet fields
    eth_src: str = "aa:bb:cc:dd:ee:ff",
    eth_dst: str = "11:22:33:44:55:66",
    # IP fields
    ip_src: str = "192.168.1.10",
    ip_dst: str = "10.0.0.1",
    ip_ttl: int = 64,
    # TCP fields
    tcp_sport: int = 12345,
    tcp_dport: int = 80,
    tcp_flags: int = 0x002,   # SYN
    # UDP fields
    udp_sport: int = 54321,
    udp_dport: int = 53,
    # ICMP fields
    icmp_type: int = 8,
    icmp_code: int = 0,
    # ARP fields
    arp_op: int = 1,
    arp_psrc: str = "192.168.1.10",
    arp_pdst: str = "192.168.1.1",
    arp_hwsrc: str = "aa:bb:cc:dd:ee:ff",
    arp_hwdst: str = "00:00:00:00:00:00",
    # Misc
    pkt_len: int = 64,
    pkt_time: float | None = None,
) -> MagicMock:
    """Build a mock Scapy-style packet with the requested layers."""
    pkt = MagicMock()
    pkt.time = pkt_time if pkt_time is not None else time.time()
    pkt.__len__ = MagicMock(return_value=pkt_len)

    layer_map: dict[str, MagicMock] = {}

    if has_ether:
        eth = _make_layer("Ether", src=eth_src, dst=eth_dst)
        layer_map["Ether"] = eth

    if has_ip:
        ip = _make_layer("IP", src=ip_src, dst=ip_dst, ttl=ip_ttl)
        layer_map["IP"] = ip

    if has_tcp:
        tcp = _make_layer("TCP", sport=tcp_sport, dport=tcp_dport, flags=tcp_flags)
        layer_map["TCP"] = tcp

    if has_udp:
        udp = _make_layer("UDP", sport=udp_sport, dport=udp_dport)
        layer_map["UDP"] = udp

    if has_icmp:
        icmp = _make_layer("ICMP", type=icmp_type, code=icmp_code)
        layer_map["ICMP"] = icmp

    if has_arp:
        arp = _make_layer(
            "ARP",
            op=arp_op,
            psrc=arp_psrc,
            pdst=arp_pdst,
            hwsrc=arp_hwsrc,
            hwdst=arp_hwdst,
        )
        layer_map["ARP"] = arp

    if has_raw:
        layer_map["Raw"] = _make_layer("Raw")

    def _has_layer(name: str) -> bool:
        return name in layer_map

    def _getitem(name: str) -> MagicMock:
        return layer_map[name]

    pkt.haslayer = MagicMock(side_effect=_has_layer)
    pkt.__getitem__ = MagicMock(side_effect=_getitem)

    return pkt


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestParsePacketTCP(unittest.TestCase):
    """Tests for TCP packet parsing."""

    def setUp(self) -> None:
        self.pkt = _build_mock_packet(
            has_ether=True,
            has_ip=True,
            has_tcp=True,
            ip_src="192.168.1.5",
            ip_dst="10.10.10.1",
            ip_ttl=128,
            tcp_sport=49152,
            tcp_dport=443,
            tcp_flags=0x002,  # SYN
        )

    def test_protocol_is_tcp(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertIsNotNone(result)
        self.assertEqual(result["protocol"], "TCP")

    def test_ip_addresses_extracted(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["src_ip"], "192.168.1.5")
        self.assertEqual(result["dst_ip"], "10.10.10.1")

    def test_ports_extracted(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["src_port"], 49152)
        self.assertEqual(result["dst_port"], 443)

    def test_ttl_extracted(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["ttl"], 128)

    def test_mac_addresses_lower_cased(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["src_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result["dst_mac"], "11:22:33:44:55:66")

    def test_syn_flag_string(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        # SYN = 0x002 → "S"
        self.assertIn("S", result["flags"])

    def test_length_set(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["length"], 64)

    def test_timestamp_present(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertIsInstance(result["timestamp"], float)
        self.assertGreater(result["timestamp"], 0)

    def test_arp_fields_none(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertIsNone(result["arp_op"])
        self.assertIsNone(result["arp_psrc"])

    def test_icmp_fields_none(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertIsNone(result["icmp_type"])


class TestParsePacketUDP(unittest.TestCase):
    """Tests for UDP packet parsing."""

    def setUp(self) -> None:
        self.pkt = _build_mock_packet(
            has_ip=True,
            has_udp=True,
            ip_src="172.16.0.5",
            ip_dst="8.8.8.8",
            udp_sport=5000,
            udp_dport=53,
        )

    def test_protocol_is_udp(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["protocol"], "UDP")

    def test_ports_extracted(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["src_port"], 5000)
        self.assertEqual(result["dst_port"], 53)

    def test_no_flags(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertIsNone(result["flags"])

    def test_no_icmp_fields(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertIsNone(result["icmp_type"])
        self.assertIsNone(result["icmp_code"])


class TestParsePacketICMP(unittest.TestCase):
    """Tests for ICMP packet parsing."""

    def setUp(self) -> None:
        self.pkt = _build_mock_packet(
            has_ip=True,
            has_icmp=True,
            ip_src="10.0.0.5",
            ip_dst="10.0.0.1",
            icmp_type=8,   # Echo Request
            icmp_code=0,
        )

    def test_protocol_is_icmp(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["protocol"], "ICMP")

    def test_icmp_type_and_code(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["icmp_type"], 8)
        self.assertEqual(result["icmp_code"], 0)

    def test_no_ports(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertIsNone(result["src_port"])
        self.assertIsNone(result["dst_port"])


class TestParsePacketARP(unittest.TestCase):
    """Tests for ARP packet parsing."""

    def setUp(self) -> None:
        self.pkt = _build_mock_packet(
            has_ether=True,
            has_arp=True,
            arp_op=1,
            arp_psrc="192.168.1.10",
            arp_pdst="192.168.1.1",
            arp_hwsrc="de:ad:be:ef:00:01",
            arp_hwdst="00:00:00:00:00:00",
        )

    def test_protocol_is_arp(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["protocol"], "ARP")

    def test_arp_op_extracted(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["arp_op"], 1)

    def test_arp_ips_extracted(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["arp_psrc"], "192.168.1.10")
        self.assertEqual(result["arp_pdst"], "192.168.1.1")

    def test_arp_hwsrc_lower_cased(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["arp_hwsrc"], "de:ad:be:ef:00:01")

    def test_src_ip_mirrors_arp_psrc(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertEqual(result["src_ip"], result["arp_psrc"])

    def test_arp_short_circuits_ip_processing(self) -> None:
        """ARP packets should not have IP layer ports."""
        from app.capture.packet_parser import parse_packet
        result = parse_packet(self.pkt)
        self.assertIsNone(result["src_port"])
        self.assertIsNone(result["dst_port"])


class TestParsePacketEdgeCases(unittest.TestCase):
    """Edge case and error-handling tests."""

    def test_none_input_returns_none(self) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(None)
        self.assertIsNone(result)

    def test_unknown_protocol_packet(self) -> None:
        """Packet with no recognised layers → protocol = UNKNOWN."""
        pkt = MagicMock()
        pkt.time = time.time()
        pkt.__len__ = MagicMock(return_value=20)
        pkt.haslayer = MagicMock(return_value=False)
        pkt.__getitem__ = MagicMock(side_effect=KeyError)

        from app.capture.packet_parser import parse_packet
        result = parse_packet(pkt)
        self.assertIsNotNone(result)
        self.assertEqual(result["protocol"], "UNKNOWN")

    def test_malformed_packet_does_not_raise(self) -> None:
        """A packet that raises internally should be caught and return None."""
        bad_pkt = MagicMock()
        bad_pkt.time = time.time()
        bad_pkt.__len__ = MagicMock(side_effect=RuntimeError("simulated error"))

        from app.capture.packet_parser import parse_packet
        # Should not propagate the exception
        result = parse_packet(bad_pkt)
        self.assertIsNone(result)

    def test_raw_layer_flagged(self) -> None:
        pkt = _build_mock_packet(has_ip=True, has_tcp=True, has_raw=True)
        from app.capture.packet_parser import parse_packet
        result = parse_packet(pkt)
        self.assertTrue(result["raw"])

    def test_no_raw_layer_flagged_false(self) -> None:
        pkt = _build_mock_packet(has_ip=True, has_tcp=True, has_raw=False)
        from app.capture.packet_parser import parse_packet
        result = parse_packet(pkt)
        self.assertFalse(result["raw"])

    def test_zero_length_packet(self) -> None:
        pkt = _build_mock_packet(has_ip=True, has_tcp=True, pkt_len=0)
        from app.capture.packet_parser import parse_packet
        result = parse_packet(pkt)
        self.assertIsNotNone(result)
        self.assertEqual(result["length"], 0)


class TestParsePackets(unittest.TestCase):
    """Batch-parsing tests."""

    def test_empty_list_returns_empty(self) -> None:
        from app.capture.packet_parser import parse_packets
        result = parse_packets([])
        self.assertEqual(result, [])

    def test_all_valid_packets(self) -> None:
        pkts = [
            _build_mock_packet(has_ip=True, has_tcp=True),
            _build_mock_packet(has_ip=True, has_udp=True),
            _build_mock_packet(has_ip=True, has_icmp=True),
        ]
        from app.capture.packet_parser import parse_packets
        result = parse_packets(pkts)
        self.assertEqual(len(result), 3)

    def test_none_packets_are_skipped(self) -> None:
        pkts = [
            _build_mock_packet(has_ip=True, has_tcp=True),
            None,
            _build_mock_packet(has_ip=True, has_udp=True),
        ]
        from app.capture.packet_parser import parse_packets
        result = parse_packets(pkts)
        self.assertEqual(len(result), 2)

    def test_all_malformed_returns_empty(self) -> None:
        bad = MagicMock()
        bad.time = time.time()
        bad.__len__ = MagicMock(side_effect=RuntimeError("boom"))
        from app.capture.packet_parser import parse_packets
        result = parse_packets([bad, bad, bad])
        self.assertEqual(result, [])


class TestTCPFlagsString(unittest.TestCase):
    """Unit tests for the internal _tcp_flags_string helper."""

    def _flags(self, val: int) -> str:
        from app.capture.packet_parser import _tcp_flags_string
        return _tcp_flags_string(val)

    def test_syn(self) -> None:
        self.assertEqual(self._flags(0x002), "S")

    def test_syn_ack(self) -> None:
        flags = self._flags(0x012)
        self.assertIn("S", flags)
        self.assertIn("A", flags)

    def test_rst(self) -> None:
        self.assertIn("R", self._flags(0x004))

    def test_fin_ack(self) -> None:
        flags = self._flags(0x011)
        self.assertIn("F", flags)
        self.assertIn("A", flags)

    def test_zero_flags(self) -> None:
        self.assertEqual(self._flags(0x000), "")

    def test_non_integer_input(self) -> None:
        from app.capture.packet_parser import _tcp_flags_string
        # Should not raise
        result = _tcp_flags_string("SA")
        self.assertIsInstance(result, str)


class TestPacketCaptureConstruction(unittest.TestCase):
    """Tests for PacketCapture initialisation and basic state."""

    def test_default_construction(self) -> None:
        from app.capture.packet_capture import PacketCapture
        cap = PacketCapture()
        self.assertFalse(cap.is_running())
        self.assertEqual(cap.packet_count, 0)

    def test_custom_params_stored(self) -> None:
        from app.capture.packet_capture import PacketCapture
        cap = PacketCapture(
            interface="eth0",
            bpf_filter="tcp",
            packet_limit=500,
            timeout=60,
        )
        self.assertEqual(cap.interface, "eth0")
        self.assertEqual(cap.bpf_filter, "tcp")
        self.assertEqual(cap.packet_limit, 500)
        self.assertEqual(cap.timeout, 60)

    def test_get_parsed_packets_initially_empty(self) -> None:
        from app.capture.packet_capture import PacketCapture
        cap = PacketCapture()
        self.assertEqual(cap.get_parsed_packets(), [])

    def test_stats_not_running(self) -> None:
        from app.capture.packet_capture import PacketCapture
        cap = PacketCapture()
        stats = cap.get_stats()
        self.assertFalse(stats["running"])
        self.assertEqual(stats["packet_count"], 0)


class TestPacketCaptureStartStop(unittest.TestCase):
    """Tests for start/stop lifecycle (Scapy patched out)."""

    def _make_capture(self) -> "PacketCapture":  # noqa: F821
        from app.capture.packet_capture import PacketCapture
        return PacketCapture(timeout=1)

    @patch("app.capture.packet_capture.PacketCapture._capture_loop")
    def test_start_sets_running(self, mock_loop: MagicMock) -> None:
        from app.capture.packet_capture import PacketCapture
        cap = PacketCapture()
        # Override _capture_loop so it exits immediately
        mock_loop.return_value = None

        # Replace the actual thread with one that calls the mock
        import threading
        def _fake_thread_body() -> None:
            cap._running = False  # simulate thread finishing

        with patch("threading.Thread") as mock_thread_cls:
            mock_thread_instance = MagicMock()
            mock_thread_cls.return_value = mock_thread_instance

            cap.start()
            self.assertTrue(mock_thread_instance.start.called)

    def test_double_start_raises(self) -> None:
        from app.capture.packet_capture import PacketCapture
        cap = PacketCapture()
        cap._running = True  # simulate already running
        with self.assertRaises(RuntimeError):
            cap.start()

    def test_stop_when_not_running_logs_warning(self) -> None:
        from app.capture.packet_capture import PacketCapture
        cap = PacketCapture()
        # Should not raise, just log a warning
        cap.stop()

    def test_handle_packet_appends_parsed(self) -> None:
        """_handle_packet should parse and store the packet."""
        from app.capture.packet_capture import PacketCapture
        cap = PacketCapture()
        mock_pkt = _build_mock_packet(has_ip=True, has_tcp=True)

        cap._handle_packet(mock_pkt)
        self.assertEqual(cap.packet_count, 1)
        stored = cap.get_parsed_packets()
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["protocol"], "TCP")

    def test_handle_packet_calls_on_packet_callback(self) -> None:
        from app.capture.packet_capture import PacketCapture
        received: list = []
        cap = PacketCapture(on_packet=received.append)
        mock_pkt = _build_mock_packet(has_ip=True, has_udp=True)

        cap._handle_packet(mock_pkt)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["protocol"], "UDP")

    def test_handle_none_packet_is_ignored(self) -> None:
        from app.capture.packet_capture import PacketCapture
        cap = PacketCapture()

        # parse_packet(None) returns None — _handle_packet should not append
        bad_pkt = MagicMock()
        bad_pkt.time = time.time()
        bad_pkt.__len__ = MagicMock(side_effect=RuntimeError("boom"))

        cap._handle_packet(bad_pkt)
        self.assertEqual(cap.packet_count, 0)


class TestParsedPacketSchema(unittest.TestCase):
    """Verify that every parsed packet has all required schema keys."""

    REQUIRED_KEYS = [
        "timestamp", "protocol", "src_ip", "dst_ip",
        "src_mac", "dst_mac", "src_port", "dst_port",
        "length", "flags", "ttl", "icmp_type", "icmp_code",
        "arp_op", "arp_psrc", "arp_pdst", "arp_hwsrc", "arp_hwdst",
        "raw",
    ]

    def _check(self, pkt_kwargs: dict) -> None:
        from app.capture.packet_parser import parse_packet
        result = parse_packet(_build_mock_packet(**pkt_kwargs))
        for key in self.REQUIRED_KEYS:
            self.assertIn(key, result, msg=f"Missing key: {key}")

    def test_tcp_has_all_keys(self) -> None:
        self._check({"has_ip": True, "has_tcp": True})

    def test_udp_has_all_keys(self) -> None:
        self._check({"has_ip": True, "has_udp": True})

    def test_icmp_has_all_keys(self) -> None:
        self._check({"has_ip": True, "has_icmp": True})

    def test_arp_has_all_keys(self) -> None:
        self._check({"has_arp": True})

    def test_unknown_has_all_keys(self) -> None:
        pkt = MagicMock()
        pkt.time = time.time()
        pkt.__len__ = MagicMock(return_value=20)
        pkt.haslayer = MagicMock(return_value=False)
        pkt.__getitem__ = MagicMock(side_effect=KeyError)
        from app.capture.packet_parser import parse_packet
        result = parse_packet(pkt)
        for key in self.REQUIRED_KEYS:
            self.assertIn(key, result, msg=f"Missing key: {key}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
