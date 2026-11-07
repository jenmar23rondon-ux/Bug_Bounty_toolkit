"""End-to-end DOM XSS lab: vulnerable page confirms, safe page does not."""

from __future__ import annotations

import importlib.util
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from bugbounty_toolkit.core.execution_budget import ExecutionBudget
from bugbounty_toolkit.core.http_client import HttpClient, RequestSpec
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.xss.dom_inscope import run_dom
from bugbounty_toolkit.xss.playwright_confirm import PlaywrightExecutionChecker
from labs.dom_xss_lab.server import DomXssHandler, serve


class _Sentinel(BaseHTTPRequestHandler):
    hits: list[str] = []
    lock = threading.Lock()

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        with self.lock:
            self.hits.append(urlsplit(self.path).path)
        body = b""
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.wfile.write(body)

    @classmethod
    def snapshot(cls) -> list[str]:
        with cls.lock:
            return list(cls.hits)


@unittest.skipUnless(importlib.util.find_spec("playwright"), "Playwright extra not installed")
class DomXssLabTests(unittest.TestCase):
    sentinel: ThreadingHTTPServer
    lab: ThreadingHTTPServer
    threads: list[threading.Thread]
    base: str

    @classmethod
    def setUpClass(cls) -> None:
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
        DomXssHandler.reset()
        _Sentinel.hits.clear()
        cls.sentinel = ThreadingHTTPServer(("127.0.0.1", 0), _Sentinel)
        cls.lab = serve()
        sentinel_port = int(cls.sentinel.server_address[1])
        DomXssHandler.external_origin = f"http://127.0.0.1:{sentinel_port}"
        cls.threads = [
            threading.Thread(target=cls.sentinel.serve_forever, daemon=True),
            threading.Thread(target=cls.lab.serve_forever, daemon=True),
        ]
        for thread in cls.threads:
            thread.start()
        cls.base = f"http://127.0.0.1:{int(cls.lab.server_address[1])}"

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "lab"):
            cls.sentinel.shutdown()
            cls.lab.shutdown()
            for thread in cls.threads:
                thread.join(timeout=5)
            cls.sentinel.server_close()
            cls.lab.server_close()
        DomXssHandler.reset()

    def test_vulnerable_page_confirms_and_safe_page_does_not(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope_file = root / "scope.txt"
            scope_file.write_text("127.0.0.1\n", encoding="utf-8")
            scope = ScopeValidator(scope_file)
            budget = ExecutionBudget(max_requests=80)
            limiter = RateLimiter(requests_per_second=100)
            headers = {"X-Lab-Token": "offline-lab", "Cookie": "session=domlab"}
            checker = PlaywrightExecutionChecker(
                scope,
                timeout_ms=5000,
                rate_limiter=limiter,
                execution_budget=budget,
            )
            try:
                _vuln_path, vulnerable = run_dom(
                    [self.base + "/vulnerable"],
                    ["q"],
                    checker,
                    root / "vulnerable",
                    max_tests=4,
                    headers=headers,
                )
                safe_path, safe = run_dom(
                    [self.base + "/safe"],
                    ["q"],
                    checker,
                    root / "safe",
                    max_tests=4,
                    headers=headers,
                )
                alias_path, alias = run_dom(
                    [self.base + "/vulnerable"],
                    ["q"],
                    checker,
                    root / "alias",
                    max_tests=4,
                    headers=headers,
                    loopback_only=True,
                )
                started = budget.summary().requests_started
                self.assertGreaterEqual(started, 1)
                client = HttpClient(scope, timeout=5, rate_limiter=limiter, execution_budget=budget)
                client.send(RequestSpec(method="GET", url=self.base + "/safe"))
                self.assertEqual(budget.summary().requests_started, started + 1)
                self.assertTrue(alias_path.is_file())
                alias_text = alias_path.read_text(encoding="utf-8")
                safe_text = safe_path.read_text(encoding="utf-8")
            finally:
                checker.close()
        self.assertIn('"loopback_only": true', alias_text)
        self.assertIn('"loopback_only": false', safe_text)
        self.assertNotIn("session=domlab", safe_text)
        self.assertNotIn("offline-lab", safe_text)
        confirmed = [item for item in vulnerable if item["classification"] == "confirmed"]
        self.assertTrue(confirmed)
        self.assertTrue(
            all(
                item["confirmed"] is True
                and item["sink_executed"] is True
                and (item["marker_observed"] is True or item["alert_observed"] is True)
                and item["finding_confirmed"] is False
                for item in confirmed
            )
        )
        self.assertTrue(any(item["classification"] == "reflected_not_executed" for item in vulnerable))
        self.assertTrue(all(item["confirmed"] is False and item["classification"] != "confirmed" for item in safe))
        self.assertTrue(all(item["finding_confirmed"] is False for item in vulnerable + safe + alias))
        self.assertTrue(any(item["classification"] == "confirmed" for item in alias))
        observed = DomXssHandler.snapshot()
        self.assertTrue(any(item["path"] == "/vulnerable" and "session=domlab" in item["cookie"] for item in observed))
        self.assertTrue(any(item["path"] == "/vulnerable" and item["token"] == "offline-lab" for item in observed))
        self.assertEqual(_Sentinel.snapshot(), [])

    def test_native_http_exhausting_the_budget_blocks_dom_navigation(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope_file = root / "scope.txt"
            scope_file.write_text("127.0.0.1\n", encoding="utf-8")
            scope = ScopeValidator(scope_file)
            budget = ExecutionBudget(max_requests=1)
            limiter = RateLimiter(requests_per_second=100)
            checker = PlaywrightExecutionChecker(
                scope,
                timeout_ms=5000,
                rate_limiter=limiter,
                execution_budget=budget,
            )
            client = HttpClient(scope, timeout=5, rate_limiter=limiter, execution_budget=budget)
            try:
                client.send(RequestSpec(method="GET", url=self.base + "/safe"))
                _path, results = run_dom(
                    [self.base + "/vulnerable"],
                    ["q"],
                    checker,
                    root / "blocked",
                    max_tests=1,
                )
            finally:
                checker.close()
        self.assertEqual(results[0]["classification"], "error")
        self.assertFalse(results[0]["confirmed"])
        self.assertIn("budget", str(results[0].get("reason", "")).lower())
        self.assertEqual(_Sentinel.snapshot(), [])


if __name__ == "__main__":
    unittest.main()
