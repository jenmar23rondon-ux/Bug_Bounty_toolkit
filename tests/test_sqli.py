import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

from bugbounty_toolkit.core.http_client import ResponseRecord
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.sqli.parameter_tester import SqliOptions, SqliParameterTester
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
