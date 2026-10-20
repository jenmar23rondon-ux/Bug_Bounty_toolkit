import html
import importlib.util
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.xss.playwright_confirm import PlaywrightExecutionChecker


class ReflectionLab(BaseHTTPRequestHandler):
    def do_GET(self):
        value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        body = html.escape(value) if urlsplit(self.path).path == "/escaped" else value
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(("<!doctype html><html><body>" + body +
                          "<script>console.error('local-lab-console-error')</script></body></html>").encode())

    def log_message(self, *_args):
        pass


@unittest.skipUnless(importlib.util.find_spec("playwright"), "optional Playwright dependency is not installed")
class PlaywrightLocalLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright
        try:
            with sync_playwright() as playwright:
                if not os.path.isfile(playwright.chromium.executable_path):
                    raise unittest.SkipTest("Playwright Chromium binary is not installed")
                browser = playwright.chromium.launch(headless=True)
                browser.close()
        except unittest.SkipTest:
            raise
        except Exception as exc:
            raise unittest.SkipTest(f"headless Chromium unavailable: {type(exc).__name__}") from exc
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ReflectionLab)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "server"):
            cls.server.shutdown()
            cls.worker.join()
            cls.server.server_close()

    def test_executes_marker_and_alert_only_for_unescaped_local_reflection(self):
        with tempfile.TemporaryDirectory() as directory:
            scope_path = Path(directory) / "scope.txt"
            scope_path.write_text("127.0.0.1\n")
            checker = PlaywrightExecutionChecker(ScopeValidator(scope_path))
            marker = "local-marker-123"
            payload = f"<svg onload=\"window.__bbtk_xss_marker='{marker}';alert('{marker}')\"></svg>"
            from urllib.parse import urlencode
            try:
                executed = checker.confirm(self.base + "/reflect?" + urlencode({"q": payload}), marker)
                escaped = checker.confirm(self.base + "/escaped?" + urlencode({"q": payload}), marker)
            finally:
                checker.close()
        self.assertEqual(executed["classification"], "confirmed")
        self.assertTrue(executed["marker_observed"])
        self.assertTrue(executed["alert_observed"])
        self.assertTrue(any("local-lab-console-error" in item for item in executed["console_errors"]))
        self.assertEqual(escaped["classification"], "reflected_not_executed")
        self.assertFalse(escaped["marker_observed"])
        self.assertFalse(escaped["alert_observed"])


if __name__ == "__main__":
    unittest.main()
