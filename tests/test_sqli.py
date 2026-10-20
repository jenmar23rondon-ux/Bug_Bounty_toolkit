import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

from bugbounty_toolkit.core.http_client import ResponseRecord
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.sqli.parameter_tester import SqliOptions, SqliParameterTester, error_families
from bugbounty_toolkit.utils.exceptions import ToolkitError


class SqliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        scope = self.root / "scope.txt"
        scope.write_text("example.com\n")
        self.routes = self.root / "routes.txt"
        self.routes.write_text("https://example.com/search?q=original&page=2\n")
        self.params = self.root / "parameters.txt"
        self.params.write_text("q\npage\n")
        self.client = Mock()
        self.tester = SqliParameterTester(ScopeValidator(scope), self.client)

    def tearDown(self):
        self.temp.cleanup()

    def respond(self, spec, body="normal", status=200, truncated=False):
        return ResponseRecord(spec, spec.url, status, "test", 1, {"content-type": "text/html"}, body, len(body), truncated)

    def test_baseline_comparison_budget_and_other_parameters(self):
        def send(spec):
            query = parse_qs(urlsplit(spec.url).query)
            self.assertEqual(query["page"], ["2"])
            return self.respond(spec, "You have an error in your SQL syntax" if query["q"] != ["original"] else "normal")
        self.client.send.side_effect = send
        path, results = self.tester.run(SqliOptions(self.routes, self.params, max_tests=4), self.root / "evidence")
        self.assertEqual(self.client.send.call_count, 3)
        self.assertEqual([item["classification"] for item in results], ["baseline", "possible", "possible"])
        self.assertFalse(any(item["confirmed"] for item in results))
        self.assertEqual(json.loads(path.read_text())["stop_reason"], "request_budget")

    def test_existing_errors_are_not_new_findings(self):
        self.client.send.side_effect = lambda spec: self.respond(spec, "You have an error in your SQL syntax")
        _, results = self.tester.run(SqliOptions(self.routes, self.params, max_tests=3), self.root / "evidence")
        self.assertFalse(any(item["classification"] == "possible" for item in results))

    def test_database_error_signatures_cover_the_requested_engines(self):
        cases = {
            "MySQL SQL syntax error": "mysql",
            "PostgreSQL syntax error at or near SELECT": "postgresql",
            "pg_catalog query failed": "postgresql",
            "Unclosed quotation mark after the character string": "mssql",
            "ORA-20001: invalid SQL": "oracle",
            "sqlite3.OperationalError: near token": "sqlite",
        }
        for body, family in cases.items():
            with self.subTest(body=body):
                self.assertIn(family, error_families(body))

    def test_access_rate_transport_and_truncation_stop_without_retry(self):
        for status, truncated in ((401, False), (403, False), (429, False), (200, True)):
            with self.subTest(status=status, truncated=truncated):
                self.client.reset_mock()
                self.client.send.side_effect = lambda spec: self.respond(spec, status=status, truncated=truncated)
                _, results = self.tester.run(SqliOptions(self.routes, self.params, max_tests=6), self.root / "evidence")
                self.assertEqual(self.client.send.call_count, 1)
                self.assertEqual(results[0]["classification"], "error")
        self.client.reset_mock()
        self.client.send.side_effect = ToolkitError("network failure")
        self.tester.run(SqliOptions(self.routes, self.params, max_tests=6), self.root / "evidence")
        self.assertEqual(self.client.send.call_count, 1)

    def test_out_of_scope_preflight_and_incomplete_budget_send_nothing(self):
        self.routes.write_text("https://example.com/search\nhttps://outside.example/search\n")
        with self.assertRaises(ValueError):
            self.tester.run(SqliOptions(self.routes, self.params), self.root / "evidence")
        self.client.send.assert_not_called()
        with self.assertRaises(ValueError):
            self.tester.validate(SqliOptions(self.routes, self.params, max_tests=2))

    def test_deep_mode_uses_baseline_time_and_boolean_pair_with_eight_request_budget(self):
        durations = [10, 15, 15, 2700, 20, 20, 10, 10]
        def send(spec):
            value = parse_qs(urlsplit(spec.url).query)["q"][0]
            body = "true-result" if "1=1" in value else "false-result" if "1=2" in value else "normal"
            return self.respond(spec, body, status=200, truncated=False) if durations.pop(0) < 2500 else ResponseRecord(
                spec, spec.url, 200, "test", 2700, {}, body, len(body), False
            )
        self.client.send.side_effect = send
        path, results = self.tester.run(SqliOptions(self.routes, self.params, max_tests=8, deep=True), self.root / "deep")
        self.assertEqual(self.client.send.call_count, 8)
        self.assertEqual(results[0]["stage"], "baseline")
        self.assertEqual(results[3]["stage"], "time_mysql")
        self.assertTrue(results[3]["time_candidate"])
        self.assertTrue(results[6]["boolean_pair_differs"])
        self.assertEqual(results[6]["classification"], "possible")
        self.assertEqual(results[7]["classification"], "possible")
        evidence = json.loads(path.read_text())
        self.assertEqual(evidence["requests_attempted"], 8)

    def test_deep_requires_full_group_and_stops_at_budget_boundary(self):
        with self.assertRaisesRegex(ValueError, "at least 8"):
            self.tester.validate(SqliOptions(self.routes, self.params, max_tests=7, deep=True))
        self.routes.write_text("https://example.com/search?q=one\nhttps://example.com/search?q=two\n")
        self.client.send.side_effect = lambda spec: self.respond(spec)
        path, _ = self.tester.run(SqliOptions(self.routes, self.params, max_tests=8, deep=True), self.root / "deep-budget")
        self.assertEqual(self.client.send.call_count, 8)
        self.assertEqual(json.loads(path.read_text())["stop_reason"], "request_budget")
