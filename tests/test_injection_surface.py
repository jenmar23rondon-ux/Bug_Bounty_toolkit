"""Offline POST, JSON, and header placement for XSS and SQLi."""

from __future__ import annotations

import json
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from bugbounty_toolkit.core.http_client import HttpClient, RequestSpec, ResponseRecord
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.requests_engine.injection_surface import (
    HEADER_ALLOWLIST,
    build_injection_request,
    json_body,
    seal_parameter_location,
    validate_surface,
)
from bugbounty_toolkit.sqli.parameter_tester import SqliOptions, SqliParameterTester
from bugbounty_toolkit.web_vuln_lab_server import make_server
from bugbounty_toolkit.xss.parameter_tester import XssOptions, XssParameterTester


TEMPLATE = '{"q":"old","n":1,"ok":true,"child":{"a":2},"tags":["x"]}'


class SurfaceRuleTests(unittest.TestCase):
    def test_json_mutation_preserves_siblings_and_types(self) -> None:
        rendered = json_body(TEMPLATE, "/q", "NEW")
        parsed = json.loads(rendered)
        self.assertEqual(parsed["q"], "NEW")
        self.assertIs(type(parsed["n"]), int)
        self.assertEqual(parsed["n"], 1)
        self.assertIs(parsed["ok"], True)
        self.assertEqual(parsed["child"], {"a": 2})
        self.assertIs(type(parsed["child"]["a"]), int)
        self.assertEqual(parsed["tags"], ["x"])
        nested = json.loads(json_body(TEMPLATE, "/child/a", "replaced"))
        self.assertEqual(nested["q"], "old")
        self.assertEqual(nested["n"], 1)
        self.assertEqual(nested["child"]["a"], "replaced")
        self.assertEqual(nested["tags"], ["x"])

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_surface("POST", "json", (), '{"q":1,"q":2}')

    def test_post_without_content_type_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "content-type"):
            validate_surface("POST", None, (), None)

    def test_out_of_allowlist_header_is_rejected(self) -> None:
        for name in ("Cookie", "Authorization", "X-Custom", "Host"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "only allows"):
                validate_surface("GET", None, (name,), None)

    def test_supported_headers_and_form_siblings(self) -> None:
        for name in HEADER_ALLOWLIST:
            surface = validate_surface("GET", None, (name,), None)
            spec = build_injection_request("https://app.example/search", name, "marker", {}, surface)
            self.assertEqual(spec.method, "GET")
            self.assertEqual(urlsplit(spec.prepared_url()).query, "")
            self.assertEqual(spec.headers[name], "marker")
        form = validate_surface("POST", "form", (), "a=1&q=old&b=two")
        spec = build_injection_request("https://app.example/search", "q", "x y", {}, form)
        self.assertEqual(spec.method, "POST")
        self.assertEqual(
            parse_qs(spec.body if isinstance(spec.body, str) else ""), {"a": ["1"], "q": ["x y"], "b": ["two"]}
        )
        query = build_injection_request(
            "https://app.example/search?page=2", "q", "marker", {}, validate_surface("GET", None, (), None)
        )
        self.assertEqual(parse_qs(urlsplit(query.prepared_url()).query), {"page": ["2"], "q": ["marker"]})

    def test_missing_location_is_inconclusive_and_not_confirmed(self) -> None:
        confirmed = {"classification": "confirmed", "confirmed": True, "finding_state": "confirmed"}
        seal_parameter_location(confirmed, None)
        self.assertFalse(confirmed["confirmed"])
        self.assertEqual(confirmed["classification"], "inconclusive")
        self.assertIsNone(confirmed["parameter_location"])
        kept = {"classification": "confirmed", "confirmed": True, "finding_state": "confirmed"}
        seal_parameter_location(kept, "query")
        self.assertTrue(kept["confirmed"])
        self.assertEqual(kept["parameter_location"], "query")


class EnginePlacementTests(unittest.TestCase):
    def _scope(self, root: Path) -> ScopeValidator:
        scope = root / "scope.txt"
        scope.write_text("127.0.0.1\n", encoding="utf-8")
        return ScopeValidator(scope)

    def test_engines_reject_post_without_content_type_and_bad_headers_before_send(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            routes = root / "routes.txt"
            params = root / "params.txt"
            routes.write_text("http://127.0.0.1/xss/json\n", encoding="utf-8")
            params.write_text("/q\n", encoding="utf-8")
            client = Mock()
            scope = self._scope(root)
            with self.assertRaisesRegex(ValueError, "content-type"):
                XssParameterTester(scope, client).validate(XssOptions(routes, params, method="POST"))
            with self.assertRaisesRegex(ValueError, "content-type"):
                SqliParameterTester(scope, client).validate(SqliOptions(routes, params, max_tests=3, method="POST"))
            params.write_text("Cookie\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "only allows"):
                XssParameterTester(scope, client).validate(XssOptions(routes, params, header_inject=("Cookie",)))
            client.send.assert_not_called()

    def test_loopback_json_form_and_header_do_not_confirm(self) -> None:
        server = make_server("127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{int(server.server_address[1])}"
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                scope = self._scope(root)
                client = HttpClient(scope, timeout=2.0, rate_limiter=RateLimiter(100))
                body = root / "body.json"
                body.write_text(TEMPLATE, encoding="utf-8")
                routes = root / "routes.txt"
                params = root / "params.txt"
                routes.write_text(base + "/xss/json\n", encoding="utf-8")
                params.write_text("/q\n", encoding="utf-8")
                _path, xss_rows = XssParameterTester(scope, client).run(
                    XssOptions(
                        routes,
                        params,
                        max_tests=1,
                        method="POST",
                        content_type="json",
                        body_template=body.read_text(encoding="utf-8"),
                    ),
                    root / "xss-json",
                )
                self.assertEqual(xss_rows[0]["parameter_location"], "body_json")
                self.assertFalse(xss_rows[0]["confirmed"])
                exchange = xss_rows[0]["exchange"]
                self.assertIsInstance(exchange, dict)
                assert isinstance(exchange, dict)
                request = exchange["request"]
                self.assertIsInstance(request, dict)
                assert isinstance(request, dict)
                sent = request["body"]
                self.assertIsInstance(sent, str)
                assert isinstance(sent, str)
                parsed = json.loads(sent)
                self.assertIn("bbtkxss", parsed["q"])
                self.assertEqual(parsed["n"], 1)
                self.assertIs(parsed["ok"], True)
                self.assertEqual(parsed["child"], {"a": 2})

                routes.write_text(base + "/sqli/json\n", encoding="utf-8")
                _path, sqli_rows = SqliParameterTester(scope, client).run(
                    SqliOptions(
                        routes,
                        params,
                        max_tests=3,
                        method="POST",
                        content_type="json",
                        body_template='{"q":"seed","n":1,"ok":true}',
                    ),
                    root / "sqli-json",
                )
                self.assertTrue(all(row["parameter_location"] == "body_json" for row in sqli_rows))
                self.assertTrue(any(row["classification"] == "possible" for row in sqli_rows))
                self.assertFalse(any(row["confirmed"] for row in sqli_rows))

                form_routes = root / "form-routes.txt"
                form_params = root / "form-params.txt"
                form_routes.write_text(base + "/xss/form\n", encoding="utf-8")
                form_params.write_text("q\n", encoding="utf-8")
                _path, form_rows = XssParameterTester(scope, client).run(
                    XssOptions(
                        form_routes,
                        form_params,
                        max_tests=1,
                        method="POST",
                        content_type="form",
                        body_template="a=1&q=old&b=two",
                    ),
                    root / "xss-form",
                )
                self.assertEqual(form_rows[0]["parameter_location"], "body_form")
                self.assertFalse(form_rows[0]["confirmed"])
                form_exchange = form_rows[0]["exchange"]
                self.assertIsInstance(form_exchange, dict)
                assert isinstance(form_exchange, dict)
                form_request = form_exchange["request"]
                self.assertIsInstance(form_request, dict)
                assert isinstance(form_request, dict)
                form_body = form_request["body"]
                assert isinstance(form_body, str)
                self.assertEqual(parse_qs(form_body)["a"], ["1"])
                self.assertEqual(parse_qs(form_body)["b"], ["two"])

                header_routes = root / "header-routes.txt"
                header_params = root / "header-params.txt"
                header_routes.write_text(base + "/xss/header\n", encoding="utf-8")
                header_params.write_text("Referer\n", encoding="utf-8")
                _path, header_rows = XssParameterTester(scope, client).run(
                    XssOptions(header_routes, header_params, max_tests=1, header_inject=("Referer",)),
                    root / "xss-header",
                )
                self.assertEqual(header_rows[0]["parameter_location"], "header")
                self.assertTrue(header_rows[0]["reflected"])
                self.assertFalse(header_rows[0]["confirmed"])
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_query_mock_still_records_location_without_confirming(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = self._scope(root)
            routes = root / "routes.txt"
            params = root / "params.txt"
            routes.write_text("http://127.0.0.1/xss/reflected\n", encoding="utf-8")
            params.write_text("q\n", encoding="utf-8")
            client = Mock()

            def send(spec: RequestSpec) -> ResponseRecord:
                self.assertEqual(spec.method, "GET")
                self.assertIn("q=", spec.prepared_url())
                body = "marker"
                return ResponseRecord(
                    spec, spec.prepared_url(), 200, "OK", 1, {"content-type": "text/html"}, body, len(body)
                )

            client.send.side_effect = send
            client.timeout = 5.0
            client.rate_limiter = RateLimiter(100)
            client.execution_budget = None
            _path, rows = XssParameterTester(scope, client).run(XssOptions(routes, params, max_tests=1), root / "out")
        self.assertEqual(rows[0]["parameter_location"], "query")
        self.assertFalse(rows[0]["confirmed"])

    def test_original_positional_constructors_keep_query_defaults(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            routes = root / "routes.txt"
            params = root / "params.txt"
            routes.write_text("http://127.0.0.1/search\n", encoding="utf-8")
            params.write_text("q\n", encoding="utf-8")
            xss = XssOptions(
                routes,
                params,
                None,
                3,
                {"Accept": "text/html"},
                "html.parser",
                False,
                False,
                False,
                True,
                False,
                None,
                None,
                "content",
                None,
            )
            sqli = SqliOptions(routes, params, None, 8, {}, False, False, 5)
        self.assertEqual(xss.method, "GET")
        self.assertIsNone(xss.content_type)
        self.assertEqual(xss.header_inject, ())
        self.assertIsNone(xss.body_template)
        self.assertFalse(xss.confirm_exec)
        self.assertEqual(xss.stored_parameter, "content")
        self.assertEqual(sqli.method, "GET")
        self.assertIsNone(sqli.content_type)
        self.assertEqual(sqli.header_inject, ())
        self.assertIsNone(sqli.body_template)
        self.assertEqual(sqli.union_max_columns, 5)
        self.assertFalse(sqli.union)

    def test_post_browser_confirmation_stays_inconclusive(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = self._scope(root)
            routes = root / "routes.txt"
            params = root / "params.txt"
            routes.write_text("http://127.0.0.1/xss/json\n", encoding="utf-8")
            params.write_text("/q\n", encoding="utf-8")
            client = Mock()

            def send(spec: RequestSpec) -> ResponseRecord:
                self.assertEqual(spec.method, "POST")
                marker = spec.body if isinstance(spec.body, str) else ""
                body = f"<p>{marker}</p>"
                return ResponseRecord(
                    spec, spec.prepared_url(), 200, "OK", 1, {"content-type": "text/html"}, body, len(body)
                )

            client.send.side_effect = send
            client.timeout = 5.0
            client.rate_limiter = RateLimiter(100)
            client.execution_budget = None
            with (
                patch(
                    "bugbounty_toolkit.xss.parameter_tester.require_playwright_installed",
                    side_effect=AssertionError("browser must not start"),
                ),
                patch("bugbounty_toolkit.xss.parameter_tester.PlaywrightExecutionChecker") as checker_type,
            ):
                checker_type.return_value.confirm.return_value = {"classification": "confirmed"}
                _path, rows = XssParameterTester(scope, client).run(
                    XssOptions(
                        routes,
                        params,
                        max_tests=1,
                        confirm_exec=True,
                        method="POST",
                        content_type="json",
                        body_template=TEMPLATE,
                    ),
                    root / "post-confirm",
                )
            checker_type.assert_not_called()
            self.assertEqual(rows[0]["parameter_location"], "body_json")
            self.assertEqual(rows[0]["classification"], "inconclusive")
            self.assertEqual(rows[0]["finding_state"], "inconclusive")
            self.assertFalse(rows[0]["confirmed"])
            self.assertFalse(rows[0]["browser_execution_observed"])
            self.assertEqual(rows[0]["confirmation_gap"], "no_second_proof")

            form_params = root / "form-params.txt"
            form_params.write_text("q\n", encoding="utf-8")

            def send_form(spec: RequestSpec) -> ResponseRecord:
                self.assertEqual(spec.method, "POST")
                body = "<p>reflected</p>"
                return ResponseRecord(
                    spec, spec.prepared_url(), 200, "OK", 1, {"content-type": "text/html"}, body, len(body)
                )

            client.send.side_effect = send_form
            with patch(
                "bugbounty_toolkit.xss.parameter_tester.require_playwright_installed",
                side_effect=AssertionError("browser must not start"),
            ):
                _path, quiet = XssParameterTester(scope, client).run(
                    XssOptions(
                        routes,
                        form_params,
                        max_tests=1,
                        confirm_exec=True,
                        method="POST",
                        content_type="form",
                        body_template="a=1&q=old",
                    ),
                    root / "post-form-confirm",
                )
            self.assertEqual(quiet[0]["parameter_location"], "body_form")
            self.assertEqual(quiet[0]["classification"], "not_reflected")
            self.assertFalse(quiet[0]["confirmed"])


if __name__ == "__main__":
    unittest.main()
