import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

from bugbounty_toolkit.core.http_client import ResponseRecord
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.xss.parameter_tester import XssOptions, XssParameterTester, with_parameter
from bugbounty_toolkit.xss.reflection_detector import detect_reflection
from bugbounty_toolkit.xss.result_validator import classify_reflection


class XssTests(unittest.TestCase):
    def test_reflection_never_automatically_confirms_xss(self):
        for body, content_type in (("<marker>", "text/html"), ("&lt;marker&gt;", "text/html"), ('{"value":"marker"}', "application/json")):
            result = classify_reflection(detect_reflection(body, "marker", "<marker>"), content_type)
            self.assertEqual(result["classification"], "possible")
            self.assertFalse(result["confirmed"])
        result = classify_reflection(detect_reflection("nothing here", "marker", "marker"), "text/html")
        self.assertEqual(result["classification"], "not_reproducible")

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
                return ResponseRecord(spec, spec.url, 200, "OK", 1, {"content-type": "text/html"}, payload, len(payload))
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
