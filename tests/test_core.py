"""
Tests for the core scanner components.

Run with:  python -m pytest tests/ -v
Or:        python tests/test_core.py
"""

import socket
import sys
import threading
import time
import unittest
from pathlib import Path

# Make the package importable when running tests directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from portscanner.core.targets import (
    parse_targets, parse_ports, is_private_ip, TargetParseError,
)
from portscanner.core.scanner import (
    Scanner, ScanConfig, ScanType, PortStatus, scan_blocking,
)
from portscanner.core.services import lookup_service
from portscanner.core import exporters
from portscanner.core.history import HistoryStore


# --------------------------------------------------------------------------- #
# Test helper: a tiny TCP server that opens a port and optionally sends a
# banner. We use this to verify scanner behavior end-to-end without depending
# on the user's network.
# --------------------------------------------------------------------------- #

class _TestTcpServer:
    """Bind to localhost on an ephemeral port; accept-then-banner-then-close."""

    def __init__(self, banner: bytes = b""):
        self.banner = banner
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "_TestTcpServer":
        self._thread.start()
        return self

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                client, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                if self.banner:
                    client.sendall(self.banner)
                # Drain a bit so HTTP probes don't hang the scanner.
                client.settimeout(0.2)
                try:
                    client.recv(1024)
                except (socket.timeout, OSError):
                    pass
            finally:
                client.close()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Target parsing                                                               #
# --------------------------------------------------------------------------- #

class TestTargetParsing(unittest.TestCase):

    def test_single_ip(self):
        self.assertEqual(parse_targets("192.168.1.1"), ["192.168.1.1"])

    def test_multiple_ips(self):
        self.assertEqual(
            parse_targets("192.168.1.1, 192.168.1.2"),
            ["192.168.1.1", "192.168.1.2"],
        )

    def test_dedup(self):
        self.assertEqual(
            parse_targets("10.0.0.1, 10.0.0.1"),
            ["10.0.0.1"],
        )

    def test_cidr_small(self):
        result = parse_targets("192.168.1.0/30")
        # /30 has 4 addresses but .hosts() yields 2 (network + broadcast excluded)
        self.assertEqual(result, ["192.168.1.1", "192.168.1.2"])

    def test_cidr_too_large(self):
        with self.assertRaises(TargetParseError):
            parse_targets("10.0.0.0/8")

    def test_range_full(self):
        self.assertEqual(
            parse_targets("192.168.1.1-192.168.1.3"),
            ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
        )

    def test_range_short(self):
        self.assertEqual(
            parse_targets("192.168.1.1-3"),
            ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
        )

    def test_empty_raises(self):
        with self.assertRaises(TargetParseError):
            parse_targets("")
        with self.assertRaises(TargetParseError):
            parse_targets("   ")

    def test_invalid_ip(self):
        with self.assertRaises(TargetParseError):
            parse_targets("999.999.999.999")

    def test_localhost_resolves(self):
        # Should resolve to 127.0.0.1
        result = parse_targets("localhost")
        self.assertIn("127.0.0.1", result)

    def test_is_private_ip(self):
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("192.168.0.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("not-an-ip"))


class TestPortParsing(unittest.TestCase):

    def test_single(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_range(self):
        self.assertEqual(parse_ports("80-82"), [80, 81, 82])

    def test_mixed(self):
        self.assertEqual(parse_ports("22, 80, 443"), [22, 80, 443])

    def test_complex(self):
        self.assertEqual(parse_ports("1-3, 80, 443"), [1, 2, 3, 80, 443])

    def test_dedup_and_sort(self):
        self.assertEqual(parse_ports("80, 22, 80, 22"), [22, 80])

    def test_invalid_zero(self):
        with self.assertRaises(TargetParseError):
            parse_ports("0")

    def test_invalid_high(self):
        with self.assertRaises(TargetParseError):
            parse_ports("65536")

    def test_invalid_reverse(self):
        with self.assertRaises(TargetParseError):
            parse_ports("100-50")

    def test_invalid_garbage(self):
        with self.assertRaises(TargetParseError):
            parse_ports("abc")


# --------------------------------------------------------------------------- #
# Service DB                                                                   #
# --------------------------------------------------------------------------- #

class TestServiceLookup(unittest.TestCase):

    def test_known(self):
        self.assertEqual(lookup_service(80), "http")
        self.assertEqual(lookup_service(443), "https")
        self.assertEqual(lookup_service(22), "ssh")

    def test_unknown(self):
        self.assertEqual(lookup_service(54321), "unknown")


# --------------------------------------------------------------------------- #
# End-to-end scan                                                              #
# --------------------------------------------------------------------------- #

class TestTcpConnectScan(unittest.TestCase):

    def test_scan_open_port(self):
        srv = _TestTcpServer(banner=b"SSH-2.0-OpenSSH_8.0\r\n").start()
        try:
            cfg = ScanConfig(
                targets=["127.0.0.1"],
                ports=[srv.port],
                scan_type=ScanType.TCP_CONNECT,
                timeout=1.0, threads=4, retries=0, grab_banners=True,
            )
            results = scan_blocking(cfg)
        finally:
            srv.stop()

        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r.status, PortStatus.OPEN)
        self.assertEqual(r.port, srv.port)
        self.assertIn("SSH", r.banner)

    def test_scan_closed_port(self):
        # Pick an ephemeral port that's almost certainly closed.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # release it

        cfg = ScanConfig(
            targets=["127.0.0.1"],
            ports=[port],
            scan_type=ScanType.TCP_CONNECT,
            timeout=1.0, threads=4, retries=0, grab_banners=False,
        )
        results = scan_blocking(cfg)
        self.assertEqual(len(results), 1)
        # Port may show as closed (typical) or filtered (some kernels). Both ok.
        self.assertIn(results[0].status, (PortStatus.CLOSED, PortStatus.FILTERED))

    def test_scan_multiple_ports(self):
        srv1 = _TestTcpServer().start()
        srv2 = _TestTcpServer().start()
        try:
            cfg = ScanConfig(
                targets=["127.0.0.1"],
                ports=[srv1.port, srv2.port, 1],  # 1 should be closed/filtered
                scan_type=ScanType.TCP_CONNECT,
                timeout=1.0, threads=4, retries=0, grab_banners=False,
            )
            results = scan_blocking(cfg)
        finally:
            srv1.stop()
            srv2.stop()

        opens = [r for r in results if r.status == PortStatus.OPEN]
        self.assertEqual(len(opens), 2)
        open_ports = {r.port for r in opens}
        self.assertEqual(open_ports, {srv1.port, srv2.port})

    def test_streaming_callbacks_fire(self):
        srv = _TestTcpServer().start()
        try:
            results_streamed = []
            progress_calls = []
            done_event = threading.Event()

            cfg = ScanConfig(
                targets=["127.0.0.1"],
                ports=[srv.port],
                threads=2, timeout=1.0, retries=0, grab_banners=False,
            )
            scanner = Scanner(
                cfg,
                on_result=lambda r: results_streamed.append(r),
                on_progress=lambda d, t: progress_calls.append((d, t)),
                on_complete=lambda rs: done_event.set(),
            )
            scanner.start()
            done_event.wait(timeout=10)
        finally:
            srv.stop()

        self.assertEqual(len(results_streamed), 1)
        self.assertGreater(len(progress_calls), 0)
        self.assertEqual(progress_calls[-1], (1, 1))

    def test_stop_cancels(self):
        # Scan a few ports on an unresponsive IP — should normally take ages,
        # but we stop it and expect it to wrap up quickly.
        cfg = ScanConfig(
            targets=["10.255.255.1"],  # RFC5737 / TEST-NET-ish unreachable
            ports=list(range(1, 50)),
            scan_type=ScanType.TCP_CONNECT,
            timeout=5.0, threads=4, retries=0,
        )
        done = threading.Event()
        scanner = Scanner(cfg, on_complete=lambda rs: done.set())
        scanner.start()
        time.sleep(0.3)
        scanner.stop()
        # Should finish within a few seconds — not the full 5s × 50 ports / 4 threads.
        self.assertTrue(done.wait(timeout=15), "Scanner did not stop in time")


# --------------------------------------------------------------------------- #
# Exporters                                                                    #
# --------------------------------------------------------------------------- #

class TestExporters(unittest.TestCase):

    def setUp(self):
        srv = _TestTcpServer(banner=b"HTTP/1.1 200 OK\r\n").start()
        self.srv = srv
        cfg = ScanConfig(
            targets=["127.0.0.1"], ports=[srv.port],
            timeout=1.0, threads=2, retries=0, grab_banners=True,
        )
        self.results = scan_blocking(cfg)
        self.tmp = Path("/tmp/portscanner_test")
        self.tmp.mkdir(exist_ok=True)

    def tearDown(self):
        self.srv.stop()

    def test_json_export(self):
        out = self.tmp / "out.json"
        exporters.export_json(self.results, out)
        self.assertTrue(out.exists())
        content = out.read_text()
        self.assertIn("results", content)
        self.assertIn(str(self.srv.port), content)

    def test_csv_export(self):
        out = self.tmp / "out.csv"
        exporters.export_csv(self.results, out)
        self.assertTrue(out.exists())
        content = out.read_text()
        self.assertIn("host,port,protocol", content)
        self.assertIn("127.0.0.1", content)

    def test_txt_export(self):
        out = self.tmp / "out.txt"
        exporters.export_txt(self.results, out)
        self.assertTrue(out.exists())
        content = out.read_text()
        self.assertIn("Port Scan Report", content)
        self.assertIn("127.0.0.1", content)


# --------------------------------------------------------------------------- #
# History                                                                      #
# --------------------------------------------------------------------------- #

class TestHistory(unittest.TestCase):

    def setUp(self):
        self.db_path = Path("/tmp/portscanner_test_history.db")
        if self.db_path.exists():
            self.db_path.unlink()
        self.store = HistoryStore(self.db_path)

    def tearDown(self):
        self.store.close()
        if self.db_path.exists():
            self.db_path.unlink()

    def test_save_and_list(self):
        from portscanner.core.scanner import PortResult, PortStatus
        results = [PortResult(host="127.0.0.1", port=22, protocol="tcp",
                              status=PortStatus.OPEN, service="ssh")]
        scan_id = self.store.save_scan(
            started_at=time.time(), finished_at=time.time(),
            targets="127.0.0.1", ports="22",
            scan_type="tcp_connect", results=results,
        )
        self.assertGreater(scan_id, 0)
        records = self.store.list_scans()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].open_count, 1)

    def test_delete(self):
        from portscanner.core.scanner import PortResult, PortStatus
        results = [PortResult(host="127.0.0.1", port=22, protocol="tcp",
                              status=PortStatus.OPEN)]
        scan_id = self.store.save_scan(
            started_at=time.time(), finished_at=time.time(),
            targets="x", ports="22", scan_type="tcp_connect", results=results,
        )
        self.store.delete_scan(scan_id)
        self.assertEqual(len(self.store.list_scans()), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
