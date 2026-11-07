"""Offline second-proof SQLi confirmation, fingerprints, and the bypass list."""

from __future__ import annotations

import json
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

from bugbounty_toolkit.core.http_client import HttpClient, ResponseRecord
from bugbounty_toolkit.core.rate_limiter import RateLimiter
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.sqli.parameter_tester import (
    MAX_BYPASS_PAYLOADS,
    SqliOptions,
    SqliParameterTester,
    load_bypass_payloads,
    request_group_size,
)
from bugbounty_toolkit.web_vuln_lab_server import FINGERPRINT_BODIES, make_server


class BypassListTests(unittest.TestCase):
    def test_packaged_list_is_bounded_and_covers_the_four_techniques(self) -> None:
        payloads = load_bypass_payloads()
        self.assertEqual(len(payloads), MAX_BYPASS_PAYLOADS)
        self.assertLessEqual(len(payloads), 15)
        self.assertTrue(any("AnD" in item or "aNd" in item or "oR" in item for item in payloads))
        self.assertTrue(any("/**/" in item or "/*c*/" in item for item in payloads))
        self.assertTrue(any("%" in item for item in payloads))
        self.assertTrue(any("\t" in item for item in payloads))
        self.assertFalse(any("information_schema" in item.lower() or "dump" in item.lower() for item in payloads))

    def test_more_than_fifteen_payloads_are_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "too-many.txt"
            path.write_text("\n".join(f"' AND {index}=1-- " for index in range(16)), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "15"):
                load_bypass_payloads(path)

    def test_default_group_does_not_include_bypass_payloads(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            routes, params, scope = _inputs(root, "https://example.com/search?q=seed")
            client = Mock()
            client.send.side_effect = lambda spec: ResponseRecord(spec, spec.url, 200, "OK", 5, {}, "same", 4)
            tester = SqliParameterTester(scope, client)
            options = SqliOptions(routes, params, max_tests=11, deep=True)
            self.assertFalse(options.bypass)
            self.assertEqual(request_group_size(options), 11)
            self.assertEqual(request_group_size(SqliOptions(routes, params, max_tests=30, deep=True, bypass=True)), 26)
            _path, rows = tester.run(options, root / "out")
        self.assertEqual(client.send.call_count, 11)
        self.assertFalse(any(str(row["stage"]).startswith("bypass_") for row in rows))
        sent = [parse_qs(urlsplit(call.args[0].url).query)["q"][0] for call in client.send.call_args_list]
        self.assertFalse(any("AnD" in value or "/**/" in value or "\t" in value for value in sent))
        self.assertFalse(any(row["confirmed"] for row in rows))


class LabProofTests(unittest.TestCase):
    def test_stable_repeat_confirms_and_failures_stay_inconclusive(self) -> None:
        self._boolean("stable", confirmed=True, classification="confirmed", stable=True, reproduced=True)
        self._boolean("second-miss", confirmed=False, classification="inconclusive", stable=True, reproduced=False)
        self._boolean("unstable", confirmed=False, classification="inconclusive", stable=False, reproduced=True)

    def _boolean(self, mode: str, *, confirmed: bool, classification: str, stable: bool, reproduced: bool) -> None:
        server = make_server("127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{int(server.server_address[1])}"
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                routes, params, scope = _inputs(root, f"{base}/sqli/boolean?mode={mode}")
                client = HttpClient(scope, timeout=2.0, rate_limiter=RateLimiter(100))
                _path, rows = SqliParameterTester(scope, client).run(
                    SqliOptions(routes, params, max_tests=11, deep=True), root / mode
                )
            boolean_rows = [row for row in rows if str(row["stage"]).startswith("boolean_")]
            self.assertEqual(len(boolean_rows), 4)
            self.assertTrue(all(row["confirmed"] is confirmed for row in boolean_rows))
            self.assertTrue(all(row["classification"] == classification for row in boolean_rows))
            self.assertTrue(all(row["baseline_stable"] is stable for row in boolean_rows))
            self.assertTrue(all(row["boolean_reproduced"] is reproduced for row in boolean_rows))
            self.assertFalse(any(row["confirmed"] for row in rows if str(row["stage"]).startswith("time_")))
            self.assertFalse(any(row["confirmed"] for row in rows if row["stage"] in {"single_quote", "double_quote"}))
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_each_fingerprint_is_recorded_and_does_not_confirm(self) -> None:
        self.assertEqual(set(FINGERPRINT_BODIES), {"mysql", "postgresql", "mssql", "oracle", "sqlite"})
        for family in FINGERPRINT_BODIES:
            with self.subTest(family=family):
                server = make_server("127.0.0.1", 0)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    base = f"http://127.0.0.1:{int(server.server_address[1])}"
                    with TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        routes, params, scope = _inputs(root, f"{base}/sqli/fingerprint?family={family}")
                        client = HttpClient(scope, timeout=2.0, rate_limiter=RateLimiter(100))
                        path, rows = SqliParameterTester(scope, client).run(
                            SqliOptions(routes, params, max_tests=3), root / family
                        )
                        quotes = [row for row in rows if row["stage"] in {"single_quote", "double_quote"}]
                        self.assertTrue(quotes)
                        self.assertTrue(all(row["dbms_fingerprint"] == family for row in quotes))
                        self.assertTrue(all(row["finding_state"] == "candidate" for row in quotes))
                        self.assertFalse(any(row["confirmed"] for row in rows))
                        evidence = json.loads(path.read_text(encoding="utf-8"))
                        self.assertEqual(evidence["dbms_fingerprints"], [family])
                        self.assertFalse(evidence["confirmed"])
                finally:
                    server.shutdown()
                    thread.join(timeout=5)
                    server.server_close()

    def test_bypass_is_opt_in_and_cannot_confirm(self) -> None:
        server = make_server("127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{int(server.server_address[1])}"
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                routes, params, scope = _inputs(root, f"{base}/sqli/boolean?mode=stable")
                client = HttpClient(scope, timeout=2.0, rate_limiter=RateLimiter(100))
                _path, rows = SqliParameterTester(scope, client).run(
                    SqliOptions(routes, params, max_tests=26, deep=True, bypass=True), root / "bypass"
                )
            bypass_rows = [row for row in rows if str(row["stage"]).startswith("bypass_")]
            self.assertEqual(len(bypass_rows), 15)
            self.assertTrue(all(row["confirmed"] is False for row in bypass_rows))
            boolean_rows = [row for row in rows if str(row["stage"]).startswith("boolean_")]
            self.assertTrue(all(row["confirmed"] is True for row in boolean_rows))
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_positional_constructor_keeps_bypass_off(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            routes, params, _scope = _inputs(root, "https://example.com/search")
            options = SqliOptions(routes, params, None, 11, {}, False, False, 5, "GET", None, (), None)
        self.assertEqual(options.method, "GET")
        self.assertIsNone(options.content_type)
        self.assertEqual(options.header_inject, ())
        self.assertIsNone(options.body_template)
        self.assertFalse(options.bypass)
        self.assertEqual(options.union_max_columns, 5)


def _inputs(root: Path, route: str) -> tuple[Path, Path, ScopeValidator]:
    scope_file = root / "scope.txt"
    host = urlsplit(route).hostname or "example.com"
    scope_file.write_text(host + "\n", encoding="utf-8")
    routes = root / "routes.txt"
    params = root / "params.txt"
    routes.write_text(route + "\n", encoding="utf-8")
    params.write_text("q\n", encoding="utf-8")
    return routes, params, ScopeValidator(scope_file)


if __name__ == "__main__":
    unittest.main()
