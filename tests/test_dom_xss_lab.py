"""End-to-end DOM XSS lab: vulnerable page confirms, safe page does not."""

from __future__ import annotations

import importlib.util
import json
import os
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from bugbounty_toolkit import cli

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

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        Path(self._tmp.name, "scope.txt").write_text("127.0.0.1\n", encoding="utf-8")

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
                and item["sink_reached"] is True
                and item["execution_attributed"] is True
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
        self.assertTrue(
            any(
                item["path"] == "/session-asset"
                and "session=domlab" in item["cookie"]
                and item["token"] == "offline-lab"
                for item in observed
            )
        )
        self.assertEqual(_Sentinel.snapshot(), [])

    def _probe(self, route: str, max_tests: int) -> list[dict[str, object]]:
        root = Path(self._tmp.name)
        scope = ScopeValidator(root / "scope.txt")
        budget = ExecutionBudget(max_requests=40)
        checker = PlaywrightExecutionChecker(
            scope,
            timeout_ms=5000,
            rate_limiter=RateLimiter(requests_per_second=100),
            execution_budget=budget,
        )
        try:
            _path, results = run_dom(
                [self.base + route],
                ["q"],
                checker,
                root / route.strip("/").replace("/", "-"),
                max_tests=max_tests,
                headers={"X-Lab-Token": "offline-lab", "Cookie": "session=domlab"},
            )
        finally:
            checker.close()
        return results

    def test_unrelated_alerts_and_markers_do_not_confirm(self) -> None:
        plain_unrelated = self._probe("/unrelated-alert", 1)
        self.assertEqual(plain_unrelated[0]["classification"], "reflected_not_executed")
        self.assertTrue(plain_unrelated[0]["sink_reached"])
        self.assertFalse(plain_unrelated[0]["execution_attributed"])
        self.assertFalse(plain_unrelated[0]["confirmed"])
        both = self._probe("/unrelated-alert", 2)
        self.assertEqual(both[0]["classification"], "reflected_not_executed")
        self.assertEqual(both[1]["classification"], "confirmed")
        self.assertTrue(both[1]["marker_observed"] or both[1]["alert_observed"])

        prefixed = self._probe("/prefixed-alert", 1)
        self.assertFalse(prefixed[0]["confirmed"])
        self.assertFalse(prefixed[0]["alert_observed"])
        self.assertEqual(prefixed[0]["classification"], "reflected_not_executed")

        wrong = self._probe("/wrong-marker", 1)
        self.assertFalse(wrong[0]["marker_observed"])
        self.assertFalse(wrong[0]["alert_observed"])
        self.assertFalse(wrong[0]["confirmed"])
        self.assertEqual(wrong[0]["classification"], "reflected_not_executed")

        alert_only = self._probe("/alert-only", 1)
        self.assertTrue(alert_only[0]["alert_observed"])
        self.assertFalse(alert_only[0]["sink_reached"])
        self.assertEqual(alert_only[0]["classification"], "inconclusive")
        self.assertFalse(alert_only[0]["confirmed"])
        active_safe = self._probe("/alert-only", 2)
        self.assertTrue(all(item["confirmed"] is False for item in active_safe))

    def test_same_origin_redirect_spends_the_shared_budget_and_cross_origin_does_not_connect(self) -> None:
        with _Sentinel.lock:
            _Sentinel.hits.clear()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope_file = root / "scope.txt"
            scope_file.write_text("127.0.0.1\n", encoding="utf-8")
            scope = ScopeValidator(scope_file)
            budget = ExecutionBudget(max_requests=20)
            checker = PlaywrightExecutionChecker(
                scope,
                timeout_ms=5000,
                rate_limiter=RateLimiter(requests_per_second=100),
                execution_budget=budget,
            )
            try:
                _path, bounced = run_dom(
                    [self.base + "/bounce"],
                    ["q"],
                    checker,
                    root / "bounce",
                    max_tests=1,
                )
                self.assertGreaterEqual(budget.summary().requests_started, 2)
                self.assertFalse(bounced[0]["confirmed"])
                observed = DomXssHandler.snapshot()
                self.assertTrue(any(item["path"] == "/bounce" for item in observed))
                self.assertTrue(any(item["path"] == "/land" for item in observed))
                _path, crossed = run_dom(
                    [self.base + "/redirect-cross"],
                    ["q"],
                    checker,
                    root / "cross",
                    max_tests=1,
                    headers={"Cookie": "session=domlab", "X-Lab-Token": "offline-lab"},
                )
            finally:
                checker.close()
        self.assertFalse(crossed[0]["confirmed"])
        self.assertEqual(_Sentinel.snapshot(), [])

    def test_redirect_navigation_stops_when_the_shared_budget_is_exhausted(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope_file = root / "scope.txt"
            scope_file.write_text("127.0.0.1\n", encoding="utf-8")
            budget = ExecutionBudget(max_requests=1)
            checker = PlaywrightExecutionChecker(
                ScopeValidator(scope_file),
                timeout_ms=5000,
                rate_limiter=RateLimiter(requests_per_second=100),
                execution_budget=budget,
            )
            try:
                _path, results = run_dom(
                    [self.base + "/bounce"],
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

    def test_dom_local_cli_alias_confirms_vulnerable_and_not_safe(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = root / "records"
            (root / "settings.yaml").write_text(
                "requests_per_second: 50\ntimeout: 5\nmax_concurrency: 2\nmax_tests: 8\nmax_response_bytes: 1000000\n",
                encoding="utf-8",
            )
            vulnerable = root / "vulnerable.txt"
            safe = root / "safe.txt"
            public = root / "public.txt"
            params = root / "params.txt"
            vulnerable.write_text(self.base + "/vulnerable\n", encoding="utf-8")
            safe.write_text(self.base + "/safe\n", encoding="utf-8")
            public.write_text("https://app.example/search\n", encoding="utf-8")
            params.write_text("q\n", encoding="utf-8")

            def run(argv: list[str]) -> str:
                args = cli.build_parser().parse_args(argv)
                previous = cli.RECORDS_ROOT
                cli.RECORDS_ROOT = args.records_root
                try:
                    buffer = StringIO()
                    with redirect_stdout(buffer):
                        args.func(args)
                    return buffer.getvalue()
                finally:
                    cli.RECORDS_ROOT = previous

            run(
                [
                    "--records-root",
                    str(records),
                    "init",
                    "domlab",
                    "--authorization",
                    "offline DOM lab",
                    "--automation-allowed",
                    "--config",
                    str(root / "settings.yaml"),
                ]
            )
            run(["--records-root", str(records), "scope", "add", "domlab", "127.0.0.1"])
            run(["--records-root", str(records), "scope", "add", "domlab", "app.example"])
            with self.assertRaisesRegex(ValueError, "literal loopback"):
                run(
                    [
                        "--records-root",
                        str(records),
                        "xss",
                        "domlab",
                        "--routes",
                        str(public),
                        "--parameters",
                        str(params),
                        "--dom-local",
                        "--max-tests",
                        "1",
                        "--run-max-requests",
                        "4",
                    ]
                )
            vuln_out = run(
                [
                    "--records-root",
                    str(records),
                    "xss",
                    "domlab",
                    "--routes",
                    str(vulnerable),
                    "--parameters",
                    str(params),
                    "--dom-local",
                    "--header",
                    "X-Lab-Token: offline-lab",
                    "--cookie",
                    "session=domlab",
                    "--max-tests",
                    "4",
                    "--run-max-requests",
                    "40",
                ]
            )
            safe_out = run(
                [
                    "--records-root",
                    str(records),
                    "xss",
                    "domlab",
                    "--routes",
                    str(safe),
                    "--parameters",
                    str(params),
                    "--dom-local",
                    "--max-tests",
                    "4",
                    "--run-max-requests",
                    "40",
                ]
            )
            self.assertIn("DOM confirmed", vuln_out)
            self.assertNotIn("0 DOM confirmed", vuln_out)
            self.assertIn("0 DOM confirmed", safe_out)
            evidence = sorted((records / "domlab" / "evidence" / "xss").glob("*.json"))
            self.assertGreaterEqual(len(evidence), 2)
            payloads = [json.loads(path.read_text(encoding="utf-8")) for path in evidence]
            confirmed = [
                item for report in payloads for item in report["results"] if item.get("classification") == "confirmed"
            ]
            self.assertTrue(confirmed)
            self.assertTrue(all(report["loopback_only"] is True for report in payloads))
            self.assertTrue(all(item["finding_confirmed"] is False for item in confirmed))
            self.assertTrue(
                all(item["sink_reached"] is True and item["execution_attributed"] is True for item in confirmed)
            )
            safe_results = [
                item for report in payloads for item in report["results"] if "/safe" in str(item.get("route", ""))
            ]
            self.assertTrue(safe_results)
            self.assertTrue(all(item["confirmed"] is False for item in safe_results))

    def test_native_http_exhausting_the_budget_blocks_dom_navigation(self) -> None:
        with _Sentinel.lock:
            _Sentinel.hits.clear()
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
