"""Adversarial native-check regressions using synthetic transports only."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from bugbounty_toolkit.core.http_client import ResponseRecord
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.cors_check import assess_cors_finding, acac_allows_credentials
from bugbounty_toolkit.open_redirect import OpenRedirectOptions, OpenRedirectTester
from bugbounty_toolkit.sqli.parameter_tester import SqliOptions, SqliParameterTester


class HttpProofAttributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        scope = self.root / "scope.txt"
        scope.write_text("example.test\n", encoding="utf-8")
        self.scope = ScopeValidator(scope)
        self.routes = self.root / "routes.txt"
        self.routes.write_text("https://example.test/search?q=x\n", encoding="utf-8")
        self.params = self.root / "params.txt"
        self.params.write_text("q\n", encoding="utf-8")

    def run_deep(self, durations, *, dynamic=False, baseline_status=200):
        client = Mock()

        def send(spec):
            index = client.send.call_count - 1
            body = f"ordinary request number {index}" if dynamic else "public results"
            return ResponseRecord(
                spec, spec.url, baseline_status if index == 0 else 200, "OK", durations[index], {}, body, len(body)
            )

        client.send.side_effect = send
        path, rows = SqliParameterTester(self.scope, client).run(
            SqliOptions(self.routes, self.params, deep=True, max_tests=8), self.root / "evidence"
        )
        return client, rows, json.loads(path.read_text(encoding="utf-8"))

    def test_threshold_crossing_by_two_ms_is_not_a_timing_candidate(self):
        client, rows, evidence = self.run_deep([2499, 2501, 2501, 2501, 2501, 2501, 2501, 2501])
        self.assertEqual(client.send.call_count, 8)
        self.assertFalse(any(row["time_candidate"] for row in rows))
        self.assertEqual(rows[3]["timing_delta_ms"], 2)
        self.assertFalse(evidence["confirmed"])

    def test_real_delay_is_retained_as_candidate_without_claiming_execution(self):
        _, rows, evidence = self.run_deep([10, 10, 10, 3010, 10, 10, 10, 10])
        self.assertTrue(rows[3]["time_candidate"])
        self.assertEqual(rows[3]["finding_state"], "candidate")
        self.assertEqual(rows[3]["confirmation_gap"], "no_second_proof")
        self.assertFalse(evidence["confirmed"])

    def test_dynamic_request_counter_does_not_confirm_boolean_sqli(self):
        _, rows, evidence = self.run_deep([10] * 8, dynamic=True)
        self.assertTrue(rows[-1]["boolean_pair_differs"])
        self.assertFalse(any(row["confirmed"] for row in rows))
        self.assertEqual(evidence["classification"], "candidate")

    def test_invalid_baseline_stops_before_probes(self):
        client, rows, evidence = self.run_deep([10] * 8, baseline_status=500)
        self.assertEqual(client.send.call_count, 1)
        self.assertEqual(rows[0]["finding_state"], "inconclusive")
        self.assertEqual(evidence["stop_reason"], "invalid_baseline")

    def test_public_cors_body_and_analytics_cookie_are_not_private_access(self):
        for body in ('{"public":true}', "", "documentation sample"):
            result = assess_cors_finding(
                origin="https://evil.com",
                allow_origin="https://evil.com",
                allow_credentials="true",
                request_headers={"Cookie": "analytics=synthetic-value"},
                status_code=200,
                body_text=body,
                body_size=len(body),
            )
            self.assertEqual(result["finding_state"], "candidate")
            self.assertFalse(result["private_body_readable"])
            self.assertFalse(result["confirmed"])
            self.assertNotIn("synthetic-value", json.dumps(result))

    def test_cors_requires_exact_acac_and_marks_incomplete_responses(self):
        self.assertTrue(acac_allows_credentials("true"))
        for value in ("TRUE", "True", "false", None):
            self.assertFalse(acac_allows_credentials(value))
        for status, truncated in [(200, True), (503, False)]:
            result = assess_cors_finding(
                origin="https://evil.com",
                allow_origin="https://evil.com",
                allow_credentials="true",
                request_headers={},
                status_code=status,
                body_truncated=truncated,
            )
            self.assertEqual(result["finding_state"], "inconclusive")

    def test_constant_external_redirect_cannot_prove_parameter_control(self):
        client = Mock()
        client.send.side_effect = lambda spec: ResponseRecord(
            spec, spec.url, 302, "Found", 1, {"location": "https://evil.com"}, "", 0
        )
        path, rows = OpenRedirectTester(self.scope, client).run(
            OpenRedirectOptions("https://example.test/login?next=/home", "next"), self.root / "redirect"
        )
        self.assertEqual(client.send.call_count, 5)
        self.assertTrue(all(row["finding_state"] == "candidate" for row in rows))
        self.assertTrue(any(row["payload_host_matches_location"] for row in rows))
        self.assertFalse(any(row["param_controls_location"] or row["confirmed"] for row in rows))
        self.assertFalse(json.loads(path.read_text(encoding="utf-8"))["confirmed"])
        self.assertTrue(
            all(call.args[0].url.startswith("https://example.test/") for call in client.send.call_args_list)
        )
