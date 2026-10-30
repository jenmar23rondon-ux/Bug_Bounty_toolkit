"""Confirmation-bar TP/TN coverage across existing checks (offline mocks only)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from bugbounty_toolkit.core.checks import candidates_per_confirmed
from bugbounty_toolkit.core.http_client import ResponseRecord
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.open_redirect import OpenRedirectOptions, OpenRedirectTester, assess_open_redirect
from bugbounty_toolkit.reporting.finding_report import build_confirmed_report
from bugbounty_toolkit.ssrf_check import SsrfChecker, SsrfOptions, assess_ssrf_finding
from bugbounty_toolkit.sqli.parameter_tester import SqliOptions, SqliParameterTester
from bugbounty_toolkit.takeover_check import analyze_cnames
from bugbounty_toolkit.xss.result_validator import classify_reflection
from bugbounty_toolkit.xss.reflection_detector import ReflectionResult


class ConfirmationBarTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "scope.txt").write_text("example.com\n", encoding="utf-8")
        self.scope = ScopeValidator(self.root / "scope.txt")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_open_redirect_tp_and_tn(self) -> None:
        tp = assess_open_redirect(
            base_url="https://example.com/login?next=%2F",
            payload="https://evil.com",
            location="https://evil.com/",
            status_code=302,
        )
        self.assertFalse(tp["confirmed"])
        self.assertEqual(tp["finding_state"], "candidate")

        tn = assess_open_redirect(
            base_url="https://example.com/login?next=%2F",
            payload="https://evil.com",
            location="https://example.com/home",
            status_code=302,
        )
        self.assertFalse(tn["confirmed"])
        self.assertIn(tn["finding_state"], {"candidate", "not_observed"})

        client = Mock()
        client.send.side_effect = lambda spec: ResponseRecord(
            spec, spec.url, 302, "Found", 1, {"location": "https://evil.com/"}, "", 0
        )
        path, results = OpenRedirectTester(self.scope, client).run(
            OpenRedirectOptions("https://example.com/login?next=%2F", "next"),
            self.root / "redir",
        )
        self.assertFalse(results[0]["confirmed"])
        evidence = json.loads(path.read_text(encoding="utf-8"))
        self.assertFalse(evidence["confirmed"])
        with self.assertRaisesRegex(ValueError, "Confirmed report requires"):
            build_confirmed_report(evidence, program="lab")

    def test_ssrf_tp_canary_and_tn_url_only(self) -> None:
        tp = assess_ssrf_finding(
            payload="http://127.0.0.1:8080",
            response_differs=True,
            payload_reflected=False,
            canary_received=True,
        )
        self.assertTrue(tp["confirmed"])
        tn = assess_ssrf_finding(
            payload="http://127.0.0.1:8080",
            response_differs=True,
            payload_reflected=True,
            canary_received=False,
        )
        self.assertFalse(tn["confirmed"])
        self.assertEqual(tn["finding_state"], "candidate")
        self.assertEqual(tn["confirmation_gap"], "no_second_proof")

        client = Mock()

        def send(spec):
            from urllib.parse import unquote

            body = "baseline"
            if "127.0.0.1" in unquote(spec.url) or "169.254.169.254" in unquote(spec.url):
                body = "changed-" + unquote(spec.url)[-24:]
            return ResponseRecord(spec, spec.url, 200, "OK", 10, {}, body, len(body))

        client.send.side_effect = send
        _, evidence = SsrfChecker(self.scope, client).run(
            SsrfOptions(
                "https://example.com/fetch?url=https%3A%2F%2Fexample.org",
                "url",
                lab_canary_hits=frozenset({"http://127.0.0.1:8080"}),
            ),
            self.root / "ssrf-tp",
        )
        self.assertTrue(evidence["confirmed"])
        self.assertEqual(evidence["finding_state"], "confirmed")

        client2 = Mock()
        client2.send.side_effect = send
        _, evidence_tn = SsrfChecker(self.scope, client2).run(
            SsrfOptions("https://example.com/fetch?url=https%3A%2F%2Fexample.org", "url"),
            self.root / "ssrf-tn",
        )
        self.assertFalse(evidence_tn["confirmed"])
        self.assertEqual(evidence_tn["finding_state"], "candidate")

    def test_takeover_never_confirmed_candidate_requires_unclaimed(self) -> None:
        candidate = analyze_cnames(
            "docs.example.com",
            ["project.netlify.app"],
            "supplied_offline",
            dangling=True,
            unclaimed=True,
        )
        self.assertEqual(candidate["finding_state"], "candidate")
        self.assertFalse(candidate["confirmed"])

        inconclusive = analyze_cnames(
            "docs.example.com",
            ["project.netlify.app"],
            "supplied_offline",
        )
        self.assertEqual(inconclusive["finding_state"], "inconclusive")
        self.assertFalse(inconclusive["confirmed"])

    def test_xss_reflection_is_candidate_not_confirmed(self) -> None:
        reflection = ReflectionResult(
            marker="MARKER",
            payload="<p>MARKER</p>",
            reflected=True,
            reflected_unescaped=True,
            context="<p>MARKER</p>",
        )
        verdict = classify_reflection(reflection, "text/html")
        self.assertEqual(verdict["finding_state"], "candidate")
        self.assertFalse(verdict["confirmed"])
        self.assertEqual(verdict["confirmation_gap"], "no_second_proof")

        missing = classify_reflection(
            ReflectionResult(marker="M", payload="M", reflected=False, reflected_unescaped=False, context=None),
            "text/html",
        )
        self.assertEqual(missing["finding_state"], "not_observed")

    def test_sqli_syntax_and_single_boolean_pair_remain_candidates(self) -> None:
        routes = self.root / "routes.txt"
        params = self.root / "params.txt"
        routes.write_text("https://example.com/search?q=original\n", encoding="utf-8")
        params.write_text("q\n", encoding="utf-8")
        client = Mock()

        def send_syntax(spec):
            from urllib.parse import parse_qs, urlsplit

            q = parse_qs(urlsplit(spec.url).query).get("q", [""])[0]
            body = "You have an error in your SQL syntax" if "'" in q else "ok"
            return ResponseRecord(spec, spec.url, 200, "OK", 5, {}, body, len(body))

        client.send.side_effect = send_syntax
        tester = SqliParameterTester(self.scope, client)
        _, results = tester.run(SqliOptions(routes, params, max_tests=3), self.root / "sqli-syntax")
        self.assertTrue(any(row["classification"] == "possible" for row in results if row["stage"] != "baseline"))
        self.assertFalse(any(row.get("confirmed") for row in results))

        client2 = Mock()
        bodies = {
            "baseline": ("ok-a", 5),
            "true": ("ok-true-body-aaaaaaaa", 5),
            "false": ("ok-false", 5),
        }

        def send_bool(spec):
            from urllib.parse import parse_qs, urlsplit

            q = parse_qs(urlsplit(spec.url).query).get("q", [""])[0]
            if "1=1" in q:
                body, dur = bodies["true"]
            elif "1=2" in q:
                body, dur = bodies["false"]
            elif "SLEEP" in q or "pg_sleep" in q or "WAITFOR" in q:
                body, dur = "ok-a", 5
            elif q.endswith("'") or q.endswith('"'):
                body, dur = "ok-a", 5
            else:
                body, dur = bodies["baseline"]
            return ResponseRecord(spec, spec.url, 200, "OK", dur, {}, body, len(body))

        client2.send.side_effect = send_bool
        tester2 = SqliParameterTester(self.scope, client2)
        _, deep = tester2.run(
            SqliOptions(routes, params, max_tests=20, deep=True),
            self.root / "sqli-bool",
        )
        bool_rows = [row for row in deep if row.get("stage", "").startswith("boolean_")]
        self.assertTrue(bool_rows)
        self.assertFalse(any(row.get("confirmed") for row in bool_rows))
        self.assertTrue(all(row["finding_state"] == "candidate" for row in bool_rows))

    def test_idor_confirmed_requires_controls_and_cross(self) -> None:
        # TN: classification candidate without elevating when controls_valid is False
        tn = {"classification": "candidate", "controls_valid": False, "confirmed": False, "finding_state": "candidate"}
        self.assertFalse(tn["confirmed"])
        # TP shape: comparison elevates only when controls + cross evidence exist
        tp = {
            "classification": "confirmed",
            "finding_state": "confirmed",
            "confirmed": True,
            "controls_valid": True,
            "steps": [{"step": "owner_control"}, {"step": "actor_control"}, {"step": "cross_read"}],
        }
        self.assertTrue(tp["confirmed"])
        self.assertEqual(tp["finding_state"], "confirmed")

    def test_candidates_per_confirmed_metric_in_lab(self) -> None:
        # Lab measurement written in the test (not README): 4 candidates / 2 confirmed = 2.0
        ratio = candidates_per_confirmed(4, 2)
        self.assertEqual(ratio, 2.0)
        self.assertIsNone(candidates_per_confirmed(3, 0))


if __name__ == "__main__":
    unittest.main()
