"""Network-free coverage for in-scope DOM XSS classification and gates."""

from __future__ import annotations

import json
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator, cast
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import urlopen

from bugbounty_toolkit import cli
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.utils.exceptions import ToolkitError
from bugbounty_toolkit.xss.dom_inscope import (
    classify_dom_confirmation,
    dom_scope_probe_url,
    run_dom,
    validate_dom_route,
)
from bugbounty_toolkit.xss.parameter_tester import XssOptions, XssParameterTester
from bugbounty_toolkit.requests_engine.headers import parse_cookie_items
from bugbounty_toolkit.xss.playwright_confirm import PlaywrightExecutionChecker, _session_cookies
from labs.dom_xss_lab.server import DomXssHandler, serve


def _cli(argv: list[str]) -> str:
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


@contextmanager
def _lab() -> Iterator[str]:
    DomXssHandler.reset()
    server = serve()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        DomXssHandler.reset()


class DomConfirmationTests(unittest.TestCase):
    def test_confirmed_requires_sink_and_marker_or_alert(self) -> None:
        self.assertEqual(
            classify_dom_confirmation(
                sink_reached=True, marker_observed=True, alert_observed=False, reflected_in_dom=True
            ),
            "confirmed",
        )
        self.assertEqual(
            classify_dom_confirmation(
                sink_reached=True, marker_observed=False, alert_observed=True, reflected_in_dom=False
            ),
            "confirmed",
        )
        self.assertEqual(
            classify_dom_confirmation(
                sink_reached=True, marker_observed=False, alert_observed=False, reflected_in_dom=True
            ),
            "reflected_not_executed",
        )
        self.assertEqual(
            classify_dom_confirmation(
                sink_reached=False, marker_observed=False, alert_observed=False, reflected_in_dom=True
            ),
            "reflected_not_executed",
        )
        self.assertEqual(
            classify_dom_confirmation(
                sink_reached=False, marker_observed=True, alert_observed=True, reflected_in_dom=True
            ),
            "inconclusive",
        )
        self.assertEqual(
            classify_dom_confirmation(
                sink_reached=False, marker_observed=False, alert_observed=False, reflected_in_dom=False
            ),
            "not_reflected",
        )

    def test_probe_url_stays_on_the_target_origin(self) -> None:
        route = "https://app.example/search?other=1"
        query = dom_scope_probe_url(route, "q", "https://evil.example/x", "query")
        fragment = dom_scope_probe_url(route, "q", "<img src=x>", "hash")
        self.assertEqual(urlsplit(query).hostname, "app.example")
        self.assertEqual(urlsplit(fragment).hostname, "app.example")
        self.assertEqual(parse_qs(urlsplit(query).query)["q"], ["https://evil.example/x"])
        self.assertEqual(urlsplit(query).fragment, "")
        self.assertEqual(unquote(urlsplit(fragment).fragment), "<img src=x>")
        self.assertNotEqual(urlsplit(query).netloc, "evil.example")
        with self.assertRaises(ValueError):
            dom_scope_probe_url(route, "q", "m", "postMessage")

    def test_route_preflight_rejects_unsafe_urls_and_non_loopback_alias(self) -> None:
        validate_dom_route("https://app.example/search", loopback_only=False)
        validate_dom_route("http://127.0.0.1/dom", loopback_only=True)
        validate_dom_route("http://[::1]/dom", loopback_only=True)
        for rejected in (
            "file:///etc/passwd",
            "http://user:secret@app.example/",
            "https://app.example/search#frag",
            "javascript:alert(1)",
        ):
            with self.subTest(url=rejected), self.assertRaises(ValueError):
                validate_dom_route(rejected, loopback_only=False)
        with self.assertRaises(ValueError):
            validate_dom_route("https://app.example/search", loopback_only=True)

    def test_session_cookies_are_bound_to_the_target_origin(self) -> None:
        cookies = _session_cookies("https://app.example/search#ignored", 'session=domlab; theme="lab"')
        self.assertEqual(cookies[0]["url"], "https://app.example/")
        self.assertEqual(cookies[0]["name"], "session")
        self.assertEqual(cookies[0]["value"], "domlab")
        self.assertEqual(cookies[1]["value"], "lab")
        self.assertNotIn("evil.example", cookies[0]["url"])
        cli_cookie = parse_cookie_items(["session=domlab"])
        self.assertIsNotNone(cli_cookie)
        parsed = _session_cookies("http://127.0.0.1/vulnerable", cli_cookie or "")
        self.assertEqual(parsed[0]["name"], "session")
        self.assertEqual(parsed[0]["value"], "domlab")
        self.assertEqual(parsed[0]["url"], "http://127.0.0.1/")
        with self.assertRaises(ValueError):
            _session_cookies("https://app.example/", "not-a-cookie")


class DomRunnerTests(unittest.TestCase):
    def _checker(self, scope_text: str, directory: Path) -> tuple[ScopeValidator, Mock]:
        scope_file = directory / "scope.txt"
        scope_file.write_text(scope_text, encoding="utf-8")
        checker = Mock()
        checker.scope = ScopeValidator(scope_file)
        return checker.scope, checker

    def test_execution_without_a_sink_is_not_confirmed_and_reflection_is_not_confirmed(self) -> None:
        def confirm(
            url: str,
            marker: str,
            headers: dict[str, str] | None = None,
            *,
            local_only: bool = False,
            dom: bool = False,
        ) -> dict[str, object]:
            self.assertTrue(dom)
            self.assertFalse(local_only)
            self.assertEqual(urlsplit(url).hostname, "app.example")
            self.assertEqual(headers, {"Cookie": "session=domlab", "X-Lab-Token": "offline"})
            payload = unquote(urlsplit(url).fragment) or parse_qs(urlsplit(url).query)["q"][0]
            active = "onerror=" in payload
            if "plain-reflection" in url:
                return {
                    "source_marker_present": True,
                    "dom_marker_present": True,
                    "dom_sinks": [],
                    "marker_observed": False,
                    "alert_observed": False,
                }
            return {
                "source_marker_present": True,
                "dom_marker_present": True,
                "dom_sinks": ["innerHTML"] if active else [],
                "marker_observed": active,
                "alert_observed": active,
            }

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _scope, checker = self._checker("app.example\n", root)
            checker.confirm.side_effect = confirm
            _path, reflected = run_dom(
                ["https://app.example/plain-reflection"],
                ["q"],
                cast(PlaywrightExecutionChecker, checker),
                root / "reflected",
                max_tests=1,
                headers={"Cookie": "session=domlab", "X-Lab-Token": "offline"},
            )
            path, results = run_dom(
                ["https://app.example/search"],
                ["q"],
                cast(PlaywrightExecutionChecker, checker),
                root / "evidence",
                max_tests=4,
                headers={"Cookie": "session=domlab", "X-Lab-Token": "offline"},
            )
            saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(reflected[0]["classification"], "reflected_not_executed")
        self.assertFalse(reflected[0]["confirmed"])
        self.assertEqual(
            [item["classification"] for item in results],
            ["reflected_not_executed", "confirmed", "reflected_not_executed", "confirmed"],
        )
        self.assertTrue(all(item["finding_confirmed"] is False for item in results))
        self.assertTrue(
            all(
                item["confirmed"] is False
                or (
                    item["sink_reached"] is True
                    and item["execution_attributed"] is True
                    and (item["marker_observed"] is True or item["alert_observed"] is True)
                )
                for item in results
            )
        )
        self.assertEqual(saved["type"], "dom_xss")
        self.assertFalse(saved["loopback_only"])
        self.assertNotIn("<img", path.name)

    def test_marker_without_sink_stays_unconfirmed(self) -> None:
        checker = Mock()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _scope, checker = self._checker("app.example\n", root)
            checker.confirm.return_value = {
                "source_marker_present": False,
                "dom_marker_present": False,
                "dom_sinks": [],
                "marker_observed": True,
                "alert_observed": True,
            }
            _path, results = run_dom(
                ["https://app.example/search"],
                ["q"],
                cast(PlaywrightExecutionChecker, checker),
                root,
                max_tests=1,
            )
        self.assertEqual(results[0]["classification"], "inconclusive")
        self.assertFalse(results[0]["confirmed"])
        self.assertEqual(results[0]["confirmation_gap"], "no_second_proof")

    def test_preflight_blocks_remote_alias_and_out_of_scope_before_navigation(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _scope, checker = self._checker("app.example\n", root)
            with self.assertRaises(ValueError):
                run_dom(
                    ["http://127.0.0.1/dom", "https://app.example/search"],
                    ["q"],
                    cast(PlaywrightExecutionChecker, checker),
                    root,
                    max_tests=4,
                    loopback_only=True,
                )
            checker.confirm.assert_not_called()
            with self.assertRaises(ValueError):
                run_dom(
                    ["https://outside.example/search"],
                    ["q"],
                    cast(PlaywrightExecutionChecker, checker),
                    root,
                    max_tests=1,
                )
            checker.confirm.assert_not_called()

    def test_cap_and_budget_stop_without_confirming(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _scope, checker = self._checker("app.example\n", root)
            checker.confirm.return_value = {
                "source_marker_present": True,
                "dom_marker_present": True,
                "dom_sinks": ["innerHTML"],
                "marker_observed": False,
                "alert_observed": False,
            }
            path, results = run_dom(
                ["https://app.example/search"],
                ["q"],
                cast(PlaywrightExecutionChecker, checker),
                root / "cap",
                max_tests=1,
            )
            self.assertEqual(len(results), 1)
            self.assertFalse(results[0]["confirmed"])
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["stop_reason"], "test_cap")
            checker.confirm.side_effect = ToolkitError("Run request budget exhausted")
            path, results = run_dom(
                ["https://app.example/search"],
                ["q"],
                cast(PlaywrightExecutionChecker, checker),
                root / "budget",
                max_tests=4,
            )
            self.assertEqual(results[0]["classification"], "error")
            self.assertFalse(results[0]["confirmed"])
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["stop_reason"], "browser_or_budget_error")
            self.assertEqual(checker.confirm.call_count, 2)


class DomOptionTests(unittest.TestCase):
    def test_dom_option_reuses_checker_budget_hooks_and_headers(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope_file = root / "scope.txt"
            scope_file.write_text("app.example\n", encoding="utf-8")
            routes = root / "routes.txt"
            routes.write_text("https://app.example/search\n", encoding="utf-8")
            params = root / "params.txt"
            params.write_text("q\n", encoding="utf-8")
            client = Mock()
            client.timeout = 5.0
            client.rate_limiter = Mock()
            client.execution_budget = Mock()
            seen: dict[str, object] = {}

            def confirm(
                url: str,
                marker: str,
                headers: dict[str, str] | None = None,
                *,
                local_only: bool = False,
                dom: bool = False,
            ) -> dict[str, object]:
                seen["dom"] = dom
                seen["local_only"] = local_only
                seen["headers"] = headers
                seen["host"] = urlsplit(url).hostname
                return {
                    "source_marker_present": True,
                    "dom_marker_present": True,
                    "dom_sinks": [],
                    "marker_observed": False,
                    "alert_observed": False,
                }

            with (
                patch("bugbounty_toolkit.xss.parameter_tester.require_playwright_installed"),
                patch("bugbounty_toolkit.xss.parameter_tester.PlaywrightExecutionChecker") as checker_type,
            ):
                checker_type.return_value.confirm.side_effect = confirm
                checker_type.return_value.scope = ScopeValidator(scope_file)
                _path, results = XssParameterTester(ScopeValidator(scope_file), client).run(
                    XssOptions(
                        routes,
                        params,
                        max_tests=1,
                        headers={"Cookie": "session=domlab", "X-Lab-Token": "offline"},
                        dom=True,
                    ),
                    root / "evidence",
                )
            checker_type.assert_called_once()
            self.assertEqual(
                checker_type.call_args.kwargs["execution_budget"],
                client.execution_budget,
            )
            self.assertEqual(checker_type.call_args.kwargs["rate_limiter"], client.rate_limiter)
            self.assertEqual(seen["dom"], True)
            self.assertEqual(seen["local_only"], False)
            self.assertEqual(seen["headers"], {"Cookie": "session=domlab", "X-Lab-Token": "offline"})
            self.assertEqual(seen["host"], "app.example")
            self.assertEqual(results[0]["classification"], "reflected_not_executed")
            self.assertFalse(results[0]["confirmed"])

    def test_dom_local_alias_uses_the_new_bar_and_rejects_public_origins(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope_file = root / "scope.txt"
            scope_file.write_text("app.example\n127.0.0.1\n", encoding="utf-8")
            public = root / "public.txt"
            public.write_text("https://app.example/search\n", encoding="utf-8")
            local = root / "local.txt"
            local.write_text("http://127.0.0.1/dom\n", encoding="utf-8")
            params = root / "params.txt"
            params.write_text("q\n", encoding="utf-8")
            client = Mock()
            client.timeout = 5.0
            client.rate_limiter = Mock()
            client.execution_budget = None
            tester = XssParameterTester(ScopeValidator(scope_file), client)
            with self.assertRaisesRegex(ValueError, "literal loopback"):
                tester.validate(XssOptions(public, params, dom=True, dom_local=True))

            def confirm(
                url: str,
                marker: str,
                headers: dict[str, str] | None = None,
                *,
                local_only: bool = False,
                dom: bool = False,
            ) -> dict[str, object]:
                self.assertTrue(dom)
                self.assertFalse(local_only)
                self.assertEqual(urlsplit(url).hostname, "127.0.0.1")
                return {
                    "source_marker_present": True,
                    "dom_marker_present": True,
                    "dom_sinks": ["innerHTML"],
                    "marker_observed": True,
                    "alert_observed": True,
                }

            with (
                patch("bugbounty_toolkit.xss.parameter_tester.require_playwright_installed"),
                patch("bugbounty_toolkit.xss.parameter_tester.PlaywrightExecutionChecker") as checker_type,
            ):
                checker_type.return_value.confirm.side_effect = confirm
                checker_type.return_value.scope = ScopeValidator(scope_file)
                _path, results = tester.run(
                    XssOptions(local, params, max_tests=1, dom=True, dom_local=True),
                    root / "evidence",
                )
        self.assertEqual(results[0]["classification"], "confirmed")
        self.assertTrue(results[0]["confirmed"])
        self.assertTrue(results[0]["sink_reached"])
        self.assertTrue(results[0]["execution_attributed"])
        self.assertFalse(results[0]["finding_confirmed"])

    def test_dom_local_without_dom_keeps_the_loopback_runner(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope_file = root / "scope.txt"
            scope_file.write_text("127.0.0.1\n", encoding="utf-8")
            routes = root / "routes.txt"
            routes.write_text("http://127.0.0.1/dom\n", encoding="utf-8")
            params = root / "params.txt"
            params.write_text("q\n", encoding="utf-8")
            client = Mock()
            client.timeout = 5.0
            client.rate_limiter = Mock()
            client.execution_budget = None

            def confirm(
                url: str,
                marker: str,
                headers: dict[str, str] | None = None,
                *,
                local_only: bool = False,
            ) -> dict[str, object]:
                self.assertTrue(local_only)
                self.assertEqual(urlsplit(url).hostname, "127.0.0.1")
                return {
                    "source_marker_present": True,
                    "dom_sinks": [],
                    "marker_observed": False,
                    "alert_observed": False,
                }

            with (
                patch("bugbounty_toolkit.xss.parameter_tester.require_playwright_installed"),
                patch("bugbounty_toolkit.xss.parameter_tester.PlaywrightExecutionChecker") as checker_type,
            ):
                checker_type.return_value.confirm.side_effect = confirm
                _path, results = XssParameterTester(ScopeValidator(scope_file), client).run(
                    XssOptions(routes, params, max_tests=1, dom_local=True),
                    root / "evidence",
                )
            self.assertEqual(results[0]["classification"], "source_present_only")
            self.assertFalse(results[0]["confirmed"])

    def test_dom_and_stored_local_are_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope_file = root / "scope.txt"
            scope_file.write_text("127.0.0.1\n", encoding="utf-8")
            client = Mock()
            options = XssOptions(
                root / "routes.txt",
                root / "params.txt",
                dom=True,
                stored_local=True,
                stored_write_url="http://127.0.0.1/write",
                stored_render_url="http://127.0.0.1/render",
            )
            with self.assertRaisesRegex(ValueError, "dom and stored_local"):
                XssParameterTester(ScopeValidator(scope_file), client).validate(options)


class DomCliGateTests(unittest.TestCase):
    def test_dom_dry_run_requires_scope_and_automation_and_sends_nothing(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = root / "records"
            routes = root / "routes.txt"
            params = root / "params.txt"
            routes.write_text("https://app.example/search\n", encoding="utf-8")
            params.write_text("q\n", encoding="utf-8")
            _cli(
                [
                    "--records-root",
                    str(records),
                    "init",
                    "domlab",
                    "--authorization",
                    "offline DOM lab",
                    "--automation-allowed",
                ]
            )
            _cli(["--records-root", str(records), "scope", "add", "domlab", "app.example"])
            with patch("bugbounty_toolkit.xss.parameter_tester.PlaywrightExecutionChecker") as checker:
                output = _cli(
                    [
                        "--records-root",
                        str(records),
                        "xss",
                        "domlab",
                        "--routes",
                        str(routes),
                        "--parameters",
                        str(params),
                        "--dom",
                        "--header",
                        "X-Lab-Token: offline",
                        "--cookie",
                        "session=domlab",
                        "--run-max-requests",
                        "4",
                        "--dry-run",
                    ]
                )
            checker.assert_not_called()
            self.assertIn("in-scope DOM browser probes", output)
            self.assertIn("Navigations count toward --run-max-*", output)
            self.assertIn("No requests sent", output)
            self.assertFalse((records / "domlab" / "evidence" / "xss").exists())
            outside = root / "outside.txt"
            outside.write_text("https://outside.example/search\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "outside configured scope"):
                _cli(
                    [
                        "--records-root",
                        str(records),
                        "xss",
                        "domlab",
                        "--routes",
                        str(outside),
                        "--parameters",
                        str(params),
                        "--dom",
                        "--dry-run",
                    ]
                )
            loopback = root / "loop.txt"
            loopback.write_text("http://127.0.0.1/vulnerable\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "literal loopback"):
                _cli(
                    [
                        "--records-root",
                        str(records),
                        "xss",
                        "domlab",
                        "--routes",
                        str(routes),
                        "--parameters",
                        str(params),
                        "--dom-local",
                        "--dry-run",
                    ]
                )
            _cli(["--records-root", str(records), "scope", "add", "domlab", "127.0.0.1"])
            local_output = _cli(
                [
                    "--records-root",
                    str(records),
                    "xss",
                    "domlab",
                    "--routes",
                    str(loopback),
                    "--parameters",
                    str(params),
                    "--dom-local",
                    "--dry-run",
                ]
            )
            self.assertIn("loopback DOM browser probes", local_output)
            self.assertIn("No requests sent", local_output)

    def test_dom_requires_automation_permission(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = root / "records"
            routes = root / "routes.txt"
            params = root / "params.txt"
            routes.write_text("https://app.example/search\n", encoding="utf-8")
            params.write_text("q\n", encoding="utf-8")
            _cli(
                [
                    "--records-root",
                    str(records),
                    "init",
                    "domlab",
                    "--authorization",
                    "offline DOM lab",
                ]
            )
            with self.assertRaisesRegex(ValueError, "automation is not enabled"):
                _cli(
                    [
                        "--records-root",
                        str(records),
                        "xss",
                        "domlab",
                        "--routes",
                        str(routes),
                        "--parameters",
                        str(params),
                        "--dom",
                        "--dry-run",
                    ]
                )


class DomLabFixtureTests(unittest.TestCase):
    def test_pages_are_static_and_use_real_dom_sinks(self) -> None:
        with _lab() as base:
            with urlopen(base + "/vulnerable?q=UNIQUE_MARKER", timeout=2) as response:
                vulnerable = response.read().decode("utf-8")
            with urlopen(base + "/safe?q=UNIQUE_MARKER", timeout=2) as response:
                safe = response.read().decode("utf-8")
        self.assertNotIn("UNIQUE_MARKER", vulnerable)
        self.assertNotIn("UNIQUE_MARKER", safe)
        self.assertIn("location.hash", vulnerable)
        self.assertIn(".innerHTML = value", vulnerable)
        self.assertNotIn("textContent", vulnerable)
        self.assertIn(".textContent = value", safe)
        self.assertNotIn("innerHTML", safe)

    def test_lab_refuses_non_loopback_bind(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            serve("203.0.113.5", 0)


if __name__ == "__main__":
    unittest.main()
