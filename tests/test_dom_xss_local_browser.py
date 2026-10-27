"""Optional real-Chromium DOM-only evaluation against a disposable loopback fixture."""

import importlib.util
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest

from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.xss.dom_local import run_dom_local
from bugbounty_toolkit.xss.playwright_confirm import PlaywrightExecutionChecker


class _DomOnlyLab(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        safe = self.path.startswith("/dom-safe")
        sink = (
            "document.querySelector('#result').textContent = value;"
            if safe
            else "document.querySelector('#result').innerHTML = value;"
        )
        body = (
            "<!doctype html><html><body><div id='result'></div><script>"
            "const value = new URLSearchParams(location.search).get('q') ?? "
            "decodeURIComponent(location.hash.slice(1));" + sink + "</script></body></html>"
        )
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@unittest.skipUnless(importlib.util.find_spec("playwright"), "Playwright extra not installed")
class DomOnlyBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright

        try:
            with sync_playwright() as playwright:
                if not os.path.isfile(playwright.chromium.executable_path):
                    raise unittest.SkipTest("Playwright-managed Chromium not installed")
                browser = playwright.chromium.launch(headless=True)
                browser.close()
        except unittest.SkipTest:
            raise
        except Exception as exc:
            raise unittest.SkipTest(f"Chromium unavailable: {type(exc).__name__}") from exc
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _DomOnlyLab)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "server"):
            cls.server.shutdown()
            cls.thread.join()
            cls.server.server_close()

    def test_dom_only_both_sources_execute_but_safe_text_content_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope_file = root / "scope.txt"
            scope_file.write_text("127.0.0.1\n", encoding="utf-8")
            checker = PlaywrightExecutionChecker(ScopeValidator(scope_file))
            try:
                _, vulnerable = run_dom_local(
                    [self.base_url + "/dom-vulnerable"],
                    ["q"],
                    checker,
                    root / "vuln",
                    4,
                )
                _, safe = run_dom_local(
                    [self.base_url + "/dom-safe"],
                    ["q"],
                    checker,
                    root / "safe",
                    4,
                )
            finally:
                checker.close()
        self.assertEqual(sum(r["classification"] == "execution_observed" for r in vulnerable), 2)
        self.assertEqual(sum(r["classification"] == "execution_observed" for r in safe), 0)
        self.assertTrue(all(r["confirmed"] is (r["classification"] == "execution_observed") for r in vulnerable + safe))
        self.assertEqual(sum(r["classification"] == "sink_reached" for r in safe), 0)


if __name__ == "__main__":
    unittest.main()
