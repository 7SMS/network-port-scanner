"""
Tests for v3 features:
- Service version detection
- Scan profiles (save/load/builtin protection)
- HTML report generation
- ResultsTableModel + filter proxy

Run with: python -m unittest portscanner.tests.test_features -v
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from portscanner.core.version_detect import detect_version, pattern_count
from portscanner.core.profiles import ProfileStore, ScanProfile, BUILTIN_PROFILES
from portscanner.core.html_report import export_html
from portscanner.core.scanner import PortResult, PortStatus


# --------------------------------------------------------------------------- #
# Version detection
# --------------------------------------------------------------------------- #

class TestVersionDetection(unittest.TestCase):

    def test_pattern_count_is_reasonable(self):
        """Smoke check: we have a meaningful number of patterns."""
        self.assertGreater(pattern_count(), 20)

    def test_openssh(self):
        v = detect_version("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
        self.assertEqual(v.product, "OpenSSH")
        self.assertEqual(v.version, "8.2p1")
        self.assertIn("Ubuntu", v.extra)

    def test_openssh_minimal(self):
        v = detect_version("SSH-2.0-OpenSSH_7.4")
        self.assertEqual(v.product, "OpenSSH")
        self.assertEqual(v.version, "7.4")

    def test_nginx_with_extra(self):
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n"
        v = detect_version(banner)
        self.assertEqual(v.product, "nginx")
        self.assertEqual(v.version, "1.18.0")
        self.assertEqual(v.extra, "Ubuntu")

    def test_apache(self):
        v = detect_version("Server: Apache/2.4.41 (Ubuntu)")
        self.assertEqual(v.product, "Apache httpd")
        self.assertEqual(v.version, "2.4.41")

    def test_iis(self):
        v = detect_version("Server: Microsoft-IIS/10.0")
        self.assertEqual(v.product, "Microsoft IIS")
        self.assertEqual(v.version, "10.0")

    def test_proftpd(self):
        v = detect_version("220 ProFTPD 1.3.5e Server (Debian)")
        self.assertEqual(v.product, "ProFTPD")
        self.assertEqual(v.version, "1.3.5e")

    def test_vsftpd(self):
        v = detect_version("220 (vsFTPd 3.0.3)")
        self.assertEqual(v.product, "vsftpd")
        self.assertEqual(v.version, "3.0.3")

    def test_redis(self):
        v = detect_version("redis_version:6.0.16")
        self.assertEqual(v.product, "Redis")
        self.assertEqual(v.version, "6.0.16")

    def test_memcached(self):
        v = detect_version("VERSION 1.6.9\r\n")
        self.assertEqual(v.product, "Memcached")
        self.assertEqual(v.version, "1.6.9")

    def test_vnc(self):
        v = detect_version("RFB 003.008")
        self.assertEqual(v.product, "VNC (RFB)")
        self.assertEqual(v.version, "003.008")

    def test_unknown_banner(self):
        v = detect_version("garbage banner with no match")
        self.assertEqual(v.product, "")
        self.assertFalse(v.is_known)

    def test_empty_banner(self):
        v = detect_version("")
        self.assertEqual(v.product, "")
        self.assertEqual(v.to_string(), "")

    def test_to_string_format(self):
        v = detect_version("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
        s = v.to_string()
        self.assertIn("OpenSSH", s)
        self.assertIn("8.2p1", s)
        self.assertIn("Ubuntu", s)


# --------------------------------------------------------------------------- #
# Profiles
# --------------------------------------------------------------------------- #

class TestProfiles(unittest.TestCase):

    def setUp(self):
        # Use a temp file so we don't pollute the user's real profiles.
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(self.path)  # ProfileStore should handle missing file
        self.store = ProfileStore(Path(self.path))

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_builtins_present(self):
        names = [p.name for p in self.store.list_all() if p.builtin]
        self.assertIn("Quick Scan (top 100)", names)
        self.assertIn("Web Servers", names)
        self.assertIn("Databases", names)
        self.assertGreaterEqual(len(names), 5)

    def test_save_and_retrieve(self):
        prof = ScanProfile(
            name="My Test Profile",
            targets="10.0.0.1",
            ports="80,443",
            threads=50,
        )
        ok = self.store.save(prof)
        self.assertTrue(ok)
        retrieved = self.store.get("My Test Profile")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.targets, "10.0.0.1")
        self.assertEqual(retrieved.ports, "80,443")
        self.assertEqual(retrieved.threads, 50)
        self.assertFalse(retrieved.builtin)

    def test_cannot_overwrite_builtin(self):
        prof = ScanProfile(name="Quick Scan (top 100)", targets="x")
        ok = self.store.save(prof)
        self.assertFalse(ok)

    def test_cannot_delete_builtin(self):
        ok = self.store.delete("Quick Scan (top 100)")
        self.assertFalse(ok)

    def test_persistence(self):
        """Save in one store, reload from disk, verify."""
        self.store.save(ScanProfile(name="Persisted", targets="1.1.1.1"))
        store2 = ProfileStore(Path(self.path))
        retrieved = store2.get("Persisted")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.targets, "1.1.1.1")

    def test_delete(self):
        self.store.save(ScanProfile(name="Doomed"))
        self.assertTrue(self.store.exists("Doomed"))
        self.assertTrue(self.store.delete("Doomed"))
        self.assertIsNone(self.store.get("Doomed"))

    def test_corrupt_file_does_not_crash(self):
        """If profiles.json is garbage, we should silently start fresh."""
        Path(self.path).write_text("not valid json {{{")
        store = ProfileStore(Path(self.path))
        # Built-ins still available
        self.assertGreater(len(store.list_all()), 0)


# --------------------------------------------------------------------------- #
# HTML report
# --------------------------------------------------------------------------- #

class TestHtmlReport(unittest.TestCase):

    def _sample_results(self):
        return [
            PortResult(host="10.0.0.1", port=22, protocol="tcp",
                       status=PortStatus.OPEN, service="ssh",
                       banner="SSH-2.0-OpenSSH_8.2p1",
                       product="OpenSSH", version="8.2p1"),
            PortResult(host="10.0.0.1", port=80, protocol="tcp",
                       status=PortStatus.OPEN, service="http",
                       banner="Server: nginx/1.18.0",
                       product="nginx", version="1.18.0"),
            PortResult(host="10.0.0.1", port=443, protocol="tcp",
                       status=PortStatus.CLOSED, service="https"),
            PortResult(host="10.0.0.2", port=3306, protocol="tcp",
                       status=PortStatus.OPEN, service="mysql"),
        ]

    def test_export_html_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            export_html(
                self._sample_results(), out,
                title="Test Report",
                targets="10.0.0.0/30",
                ports="22,80,443,3306",
                scan_type="tcp_connect",
                elapsed_seconds=1.23,
            )
            self.assertTrue(out.exists())
            content = out.read_text()
            self.assertIn("Test Report", content)
            self.assertIn("10.0.0.1", content)
            self.assertIn("10.0.0.2", content)
            self.assertIn("OpenSSH", content)
            self.assertIn("nginx", content)
            self.assertIn("7SM", content)  # signature

    def test_html_escapes_user_input(self):
        """Banners with HTML must be escaped, not rendered."""
        results = [
            PortResult(host="evil.com", port=80, protocol="tcp",
                       status=PortStatus.OPEN, service="http",
                       banner="<script>alert(1)</script>"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            export_html(results, out)
            content = out.read_text()
            self.assertNotIn("<script>alert(1)</script>", content)
            self.assertIn("&lt;script&gt;", content)

    def test_html_handles_empty_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "empty.html"
            export_html([], out)
            self.assertTrue(out.exists())
            content = out.read_text()
            self.assertIn("No hosts scanned", content)


# --------------------------------------------------------------------------- #
# Results model + proxy
# --------------------------------------------------------------------------- #

class TestResultsModel(unittest.TestCase):
    """Test the Qt model. Requires PyQt6 + a QApplication for some operations."""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt6.QtWidgets import QApplication
        cls._app = QApplication.instance() or QApplication([])

    def setUp(self):
        from portscanner.gui.results_model import (
            ResultsTableModel, ResultsFilterProxy,
        )
        self.model = ResultsTableModel()
        self.proxy = ResultsFilterProxy()
        self.proxy.setSourceModel(self.model)

    def _make(self, port, status=PortStatus.OPEN, service="http", banner=""):
        return PortResult(host="127.0.0.1", port=port, protocol="tcp",
                          status=status, service=service, banner=banner)

    def test_append_increments_row_count(self):
        self.assertEqual(self.model.rowCount(), 0)
        self.model.append_result(self._make(80))
        self.assertEqual(self.model.rowCount(), 1)
        self.model.append_result(self._make(443))
        self.assertEqual(self.model.rowCount(), 2)

    def test_clear(self):
        self.model.append_result(self._make(80))
        self.model.append_result(self._make(443))
        self.model.clear()
        self.assertEqual(self.model.rowCount(), 0)

    def test_filter_by_text(self):
        self.model.append_result(self._make(80, service="http"))
        self.model.append_result(self._make(22, service="ssh"))
        self.model.append_result(self._make(443, service="https"))
        self.proxy.set_search_text("ssh")
        self.assertEqual(self.proxy.rowCount(), 1)
        self.proxy.set_search_text("")
        self.assertEqual(self.proxy.rowCount(), 3)

    def test_filter_open_only(self):
        self.model.append_result(self._make(80, status=PortStatus.OPEN))
        self.model.append_result(self._make(81, status=PortStatus.CLOSED))
        self.model.append_result(self._make(82, status=PortStatus.FILTERED))
        self.proxy.set_open_only(True)
        self.assertEqual(self.proxy.rowCount(), 1)
        self.proxy.set_open_only(False)
        self.assertEqual(self.proxy.rowCount(), 3)

    def test_combined_filter(self):
        self.model.append_result(self._make(80, status=PortStatus.OPEN, service="http"))
        self.model.append_result(self._make(22, status=PortStatus.OPEN, service="ssh"))
        self.model.append_result(self._make(443, status=PortStatus.CLOSED, service="https"))
        self.proxy.set_search_text("http")
        self.proxy.set_open_only(True)
        # http is open; https is closed (excluded by open_only); ssh has no "http" text
        self.assertEqual(self.proxy.rowCount(), 1)

    def test_handles_many_rows(self):
        """Smoke test: model should accept thousands of rows quickly."""
        for p in range(1, 5001):
            self.model.append_result(self._make(p))
        self.assertEqual(self.model.rowCount(), 5000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
