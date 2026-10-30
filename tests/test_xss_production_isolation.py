"""Exercise the shipped checker, not a separate benchmark observer."""

import html
import importlib.util
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.xss.playwright_confirm import PlaywrightExecutionChecker


class Sentinel(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.hits.append(self.path)
        self.send_response(400)
        self.send_header("Content-Length", "0")
        self.end_headers()


class Page(BaseHTTPRequestHandler):
    sentinel_port = 0

    def log_message(self, *_):
        pass

    def do_GET(self):
        query = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        if self.path.startswith("/socket"):
            body = f"<script>new WebSocket('ws://127.0.0.1:{self.sentinel_port}/outside');</script>"
        elif self.path.startswith("/execute"):
            body = "<script>alert(" + json.dumps(query) + ")</script>"
        else:
            body = "<p>" + html.escape(query) + "</p><script>alert('Welcome');</script>"
        encoded = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@unittest.skipUnless(importlib.util.find_spec("playwright"), "Playwright extra not installed")
class ProductionIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            if not os.path.isfile(playwright.chromium.executable_path):
                raise unittest.SkipTest("Playwright-managed Chromium not installed")
        cls.sentinel = ThreadingHTTPServer(("127.0.0.1", 0), Sentinel)
        Page.sentinel_port = cls.sentinel.server_port
        cls.target = ThreadingHTTPServer(("127.0.0.1", 0), Page)
        cls.threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (cls.sentinel, cls.target)]
        for thread in cls.threads:
            thread.start()
        cls.origin = f"http://127.0.0.1:{cls.target.server_port}"

    @classmethod
    def tearDownClass(cls):
        for server in (cls.target, cls.sentinel):
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        scope_file = Path(self.tmp.name) / "scope.txt"
        scope_file.write_text(self.origin + "\n")
        self.scope = ScopeValidator(scope_file)
        self.checker = PlaywrightExecutionChecker(self.scope, timeout_ms=2000)
        self.addCleanup(self.checker.close)
        Sentinel.hits.clear()

    def test_unrelated_alert_with_escaped_reflection_never_confirms(self):
        for local in (False, True):
            with self.subTest(local_only=local):
                result = self.checker.confirm(self.origin + "/safe?q=audit-marker", "audit-marker", local_only=local)
                self.assertEqual(result["classification"], "reflected_not_executed")
                self.assertFalse(result["alert_observed"])
                self.assertFalse(result["marker_observed"])
                self.assertEqual(result["dialogs"], [{"type": "alert", "text": "Welcome"}])

    def test_matching_alert_is_execution_evidence(self):
        result = self.checker.confirm(self.origin + "/execute?q=audit-marker", "audit-marker", local_only=True)
        self.assertEqual(result["classification"], "confirmed")
        self.assertTrue(result["alert_observed"])
        self.assertFalse(result["marker_observed"])

    def test_websockets_cannot_bypass_scope_in_either_mode(self):
        with self.assertRaises(ValueError):
            self.scope.require(f"http://127.0.0.1:{self.sentinel.server_port}/outside")
        for local in (False, True):
            with self.subTest(local_only=local):
                result = self.checker.confirm(self.origin + "/socket?q=audit-marker", "audit-marker", local_only=local)
                self.assertGreaterEqual(result["blocked_websockets"], 1)
                self.assertEqual(Sentinel.hits, [])
                self.assertNotEqual(result["classification"], "confirmed")
