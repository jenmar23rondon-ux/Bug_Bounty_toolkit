import tempfile
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from bugbounty_toolkit.core.http_client import ResponseRecord
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.xss.parameter_tester import XssOptions, XssParameterTester, with_parameter
from bugbounty_toolkit.xss.reflection_detector import detect_reflection
from bugbounty_toolkit.xss.result_validator import classify_reflection
from bugbounty_toolkit.xss.test_cases import payload_cases_for_marker, payloads_for_marker
from bugbounty_toolkit.xss.playwright_confirm import classify_execution, require_playwright_installed
from bugbounty_toolkit.utils.exceptions import ToolkitError


class XssTests(unittest.TestCase):
    def context_case(self, root, body, content_type="text/html", truncated=False):
        scope = root / "scope.txt"
        scope.write_text("example.com\n")
        routes = root / "routes.txt"
        routes.write_text("https://example.com/search\n")
        params = root / "params.txt"
        params.write_text("q\n")
        client = Mock()
        client.send.side_effect = lambda spec: ResponseRecord(
            spec, spec.url, 200, "OK", 1, {"content-type": content_type}, body, len(body), truncated
        )
        with patch("bugbounty_toolkit.xss.parameter_tester.new_marker", return_value="BBTK_MARKER"):
            path, results = XssParameterTester(ScopeValidator(scope), client).run(
                XssOptions(routes, params, max_tests=1), root / "evidence"
            )
        return client, path, results

    @unittest.skipUnless(importlib.util.find_spec("bs4"), "optional xss extra not installed")
    def test_live_response_contexts_without_browser_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            body = '<p>BBTK_MARKER</p><a href="/BBTK_MARKER" title="BBTK_MARKER">x</a><img onerror="BBTK_MARKER"><script>let q="BBTK_MARKER"</script>'
            client, _, results = self.context_case(Path(directory), body)
            result = results[0]
            self.assertEqual(result["context_analysis"]["status"], "analyzed")
            kinds = {entry["context"] for entry in result["context_analysis"]["contexts"]}
            self.assertTrue({"html_text", "url_attribute", "attribute", "event_attribute", "script"}.issubset(kinds))
            self.assertEqual(result["payload_context"], "plain_value")
            self.assertEqual(result["reflection_contexts"], result["context_analysis"]["contexts"])
            self.assertFalse(result["confirmed"])
            self.assertFalse(result["browser_execution_observed"])
            client.send.assert_called_once()

    def test_context_unavailable_non_html_and_truncation_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("bugbounty_toolkit.xss.parameter_tester.analyze_html", side_effect=ValueError("missing parser")):
                _, _, results = self.context_case(Path(directory), "<p>BBTK_MARKER</p>")
                self.assertEqual(results[0]["context_analysis"]["status"], "unavailable")
            _, _, results = self.context_case(Path(directory), '{"q":"BBTK_MARKER"}', "application/json")
            self.assertEqual(results[0]["context_analysis"]["status"], "not_html")
            client, path, results = self.context_case(Path(directory), "<p>BBTK_MARKER", truncated=True)
            self.assertEqual(json.loads(path.read_text())["stop_reason"], "truncated_response")
            self.assertEqual(results[0]["classification"], "error")
            client.send.assert_called_once()

    def test_auth_failure_stops_the_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope = root / "scope.txt"
            scope.write_text("example.com\n")
            routes = root / "routes.txt"
            routes.write_text("https://example.com/search\n")
            params = root / "params.txt"
            params.write_text("q\n")
            client = Mock()
            client.send.side_effect = lambda spec: ResponseRecord(spec, spec.url, 429, "rate limit", 1, {}, "", 0)
            _, results = XssParameterTester(ScopeValidator(scope), client).run(
                XssOptions(routes, params), root / "evidence"
            )
            self.assertEqual(client.send.call_count, 1)
            self.assertEqual(results[0]["classification"], "error")

    def test_reflection_never_automatically_confirms_xss(self):
        for body, content_type in (
            ("<marker>", "text/html"),
            ("&lt;marker&gt;", "text/html"),
            ('{"value":"marker"}', "application/json"),
        ):
            result = classify_reflection(detect_reflection(body, "marker", "<marker>"), content_type)
            self.assertEqual(result["classification"], "possible")
            self.assertFalse(result["confirmed"])
        result = classify_reflection(detect_reflection("nothing here", "marker", "marker"), "text/html")
        self.assertEqual(result["classification"], "not_reproducible")

    def test_context_payloads_are_opt_in_and_use_a_harmless_execution_marker(self):
        default = payloads_for_marker("m123")
        expanded = payloads_for_marker("m123", include_context=True)
        self.assertEqual(len(default), 4)
        self.assertEqual(len(expanded), 7)
        self.assertTrue(any("<svg" in item for item in expanded))
        self.assertTrue(any("</script>" in item for item in expanded))
        self.assertTrue(any(item.startswith("javascript:") for item in expanded))
        self.assertTrue(all("window.__bbtk_xss_marker" in item and "alert(" in item for item in expanded[4:]))

    def test_context_payloads_have_explicit_context_labels_and_dom_sink_cases(self):
        cases = payload_cases_for_marker("m123", include_context=True)
        contexts = {case.context for case in cases}
        self.assertEqual(len(cases), 11)
        self.assertTrue(
            {
                "html_text",
                "attribute_event",
                "script",
                "url",
                "without_angle_brackets",
                "dom_inner_html",
                "dom_document_write",
            }.issubset(contexts)
        )
        no_angles = next(case.payload for case in cases if case.context == "without_angle_brackets")
        self.assertNotIn("<", no_angles)
        self.assertNotIn(">", no_angles)

    def test_execution_classification_includes_alert_and_escaped_reflection(self):
        self.assertEqual(classify_execution(True, True, False), "confirmed")
        self.assertEqual(classify_execution(True, False, True), "confirmed")
        self.assertEqual(classify_execution(True, False, False), "reflected_not_executed")
        self.assertEqual(classify_execution(False, False, False), "not_reflected")

    def test_confirm_exec_reports_clear_optional_dependency_error(self):
        with patch("bugbounty_toolkit.xss.playwright_confirm.importlib.util.find_spec", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Playwright.*install"):
                require_playwright_installed()

    def test_confirm_mode_only_opens_browser_for_possible_reflections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope_file = root / "scope.txt"
            scope_file.write_text("example.com\n")
            routes = root / "routes.txt"
            routes.write_text("https://example.com/search\n")
            params = root / "params.txt"
            params.write_text("q\n")
            client = Mock()
            client.timeout = 15.0
            client.rate_limiter = Mock()
            client.send.side_effect = lambda spec: ResponseRecord(
                spec, spec.url, 200, "OK", 1, {"content-type": "text/html"}, "<p>BBTK_MARKER</p>", 22
            )
            execution = {
                "classification": "confirmed",
                "marker_observed": True,
                "alert_observed": True,
                "dom_sinks": ["innerHTML"],
                "dialogs": [{"type": "alert", "text": "BBTK_MARKER"}],
                "console_errors": [],
                "page_errors": [],
            }
            with (
                patch("bugbounty_toolkit.xss.parameter_tester.require_playwright_installed"),
                patch("bugbounty_toolkit.xss.parameter_tester.PlaywrightExecutionChecker") as checker_type,
                patch("bugbounty_toolkit.xss.parameter_tester.new_marker", return_value="BBTK_MARKER"),
            ):
                checker_type.return_value.confirm.return_value = execution
                _, results = XssParameterTester(ScopeValidator(scope_file), client).run(
                    XssOptions(routes, params, max_tests=1, confirm_exec=True), root / "evidence"
                )
            checker_type.return_value.confirm.assert_called_once()
            self.assertEqual(results[0]["classification"], "confirmed")
            self.assertTrue(results[0]["confirmed"])
            self.assertEqual(results[0]["dom_sinks"], ["innerHTML"])

            client.reset_mock()
            client.send.side_effect = lambda spec: ResponseRecord(
                spec, spec.url, 200, "OK", 1, {"content-type": "text/html"}, "nothing", 7
            )
            with (
                patch("bugbounty_toolkit.xss.parameter_tester.require_playwright_installed"),
                patch("bugbounty_toolkit.xss.parameter_tester.PlaywrightExecutionChecker") as checker_type,
                patch("bugbounty_toolkit.xss.parameter_tester.new_marker", return_value="BBTK_MARKER"),
            ):
                _, results = XssParameterTester(ScopeValidator(scope_file), client).run(
                    XssOptions(routes, params, max_tests=1, confirm_exec=True), root / "evidence"
                )
            checker_type.return_value.confirm.assert_not_called()
            self.assertEqual(results[0]["classification"], "not_reflected")

            client.reset_mock()
            client.send.side_effect = lambda spec: ResponseRecord(
                spec, spec.url, 200, "OK", 1, {"content-type": "text/html"}, "<p>BBTK_MARKER</p>", 22
            )
            with (
                patch("bugbounty_toolkit.xss.parameter_tester.require_playwright_installed"),
                patch("bugbounty_toolkit.xss.parameter_tester.PlaywrightExecutionChecker") as checker_type,
                patch("bugbounty_toolkit.xss.parameter_tester.new_marker", return_value="BBTK_MARKER"),
            ):
                checker_type.return_value.confirm.return_value = {
                    "classification": "reflected_not_executed",
                    "marker_observed": False,
                    "alert_observed": False,
                    "dom_sinks": ["innerHTML", "document.write", "location"],
                    "dialogs": [],
                    "console_errors": [],
                    "page_errors": [],
                }
                _, results = XssParameterTester(ScopeValidator(scope_file), client).run(
                    XssOptions(routes, params, max_tests=1, confirm_exec=True), root / "evidence"
                )
            self.assertEqual(results[0]["classification"], "reflected_not_executed")
            self.assertFalse(results[0]["confirmed"])
            self.assertEqual(results[0]["dom_sinks"], ["innerHTML", "document.write", "location"])

    def test_browser_budget_error_writes_partial_evidence_and_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope_file = root / "scope.txt"
            scope_file.write_text("example.com\n")
            routes = root / "routes.txt"
            routes.write_text("https://example.com/search\n")
            params = root / "params.txt"
            params.write_text("q\n")
            client = Mock()
            client.timeout = 15.0
            client.rate_limiter = Mock()
            client.send.side_effect = lambda spec: ResponseRecord(
                spec, spec.url, 200, "OK", 1, {"content-type": "text/html"}, "<p>BBTK_MARKER</p>", 22
            )
            with (
                patch("bugbounty_toolkit.xss.parameter_tester.require_playwright_installed"),
                patch("bugbounty_toolkit.xss.parameter_tester.PlaywrightExecutionChecker") as checker_type,
                patch("bugbounty_toolkit.xss.parameter_tester.new_marker", return_value="BBTK_MARKER"),
            ):
                checker_type.return_value.confirm.side_effect = ToolkitError("Run request budget exhausted")
                path, results = XssParameterTester(ScopeValidator(scope_file), client).run(
                    XssOptions(routes, params, max_tests=1, confirm_exec=True), root / "evidence"
                )

            evidence = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(results[0]["classification"], "error")
            self.assertEqual(evidence["stop_reason"], "run_budget_or_browser_error")
            self.assertEqual(len(evidence["results"]), 1)

    def test_replaces_only_the_supplied_parameter(self):
        result = with_parameter("https://example.com/search?q=old&q=duplicate&page=2", "q", '<marker>"')
        self.assertEqual(parse_qs(urlsplit(result).query), {"q": ['<marker>"'], "page": ["2"]})

    def test_supplied_inputs_budget_and_scope_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope_file = root / "scope.txt"
            scope_file.write_text("example.com\n")
            routes = root / "routes.txt"
            routes.write_text("https://example.com/search\n")
            params = root / "params.txt"
            params.write_text("q\nq\npage\n")
            client = Mock()

            def reflect(spec):
                payload = next(iter(parse_qs(urlsplit(spec.url).query).values()))[0]
                return ResponseRecord(
                    spec, spec.url, 200, "OK", 1, {"content-type": "text/html"}, payload, len(payload)
                )

            client.send.side_effect = reflect
            tester = XssParameterTester(ScopeValidator(scope_file), client)
            path, results = tester.run(XssOptions(routes, params, max_tests=3), root / "evidence")
            self.assertEqual(len(results), 3)
            self.assertEqual(client.send.call_count, 3)
            self.assertTrue(path.exists())
            self.assertFalse(any(item["confirmed"] for item in results))
            routes.write_text("https://example.com/search\nhttps://outside.example/search\n")
            client.reset_mock()
            with self.assertRaises(ValueError):
                tester.run(XssOptions(routes, params), root / "evidence")
            client.send.assert_not_called()
