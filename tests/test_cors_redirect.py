import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from bugbounty_toolkit.core.http_client import ResponseRecord
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.cors_check import (
    CorsChecker,
    CorsOptions,
    assess_cors_finding,
    classify_cors,
    origins_for_target,
)
from bugbounty_toolkit.open_redirect import (
    OpenRedirectOptions,
    OpenRedirectTester,
    REDIRECT_PAYLOADS,
    classify_redirect,
    replace_query_parameter,
)


class CorsAndRedirectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        scope_path = self.root / "scope.txt"
        scope_path.write_text("example.com\n")
        self.scope = ScopeValidator(scope_path)

    def tearDown(self):
        self.temp.cleanup()

    def test_cors_verdict_rules(self):
        self.assertEqual(classify_cors("https://evil.com", "https://evil.com", "true"), "VULNERABLE")
        self.assertEqual(classify_cors("https://evil.com", "https://evil.com", None), "DÉBIL")
        self.assertEqual(classify_cors("https://evil.com", "*", "true"), "SEGURO")
        self.assertEqual(classify_cors("https://evil.com", "https://good.example", "true"), "SEGURO")
        self.assertEqual(len(origins_for_target("https://shop.example.com/path")), 4)

    def test_cors_sends_four_origins_and_writes_secret_free_evidence(self):
        client = Mock()
        outcomes = [
            {"access-control-allow-origin": "https://evil.com", "access-control-allow-credentials": "true"},
            {"access-control-allow-origin": "null"},
            {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"},
            {},
        ]

        def send(spec):
            headers = outcomes.pop(0)
            return ResponseRecord(spec, spec.url, 200, "OK", 3, headers, "private-body-do-not-save", 25)

        client.send.side_effect = send
        options = CorsOptions("https://example.com/profile?access_token=private", {"Cookie": "session=secret"})
        path, results = CorsChecker(self.scope, client).run(options, self.root / "evidence")
        self.assertEqual(client.send.call_count, 4)
        self.assertEqual([row["classification"] for row in results], ["VULNERABLE", "D\u00c9BIL", "SEGURO", "SEGURO"])
        self.assertTrue(all("Origin" in call.args[0].headers for call in client.send.call_args_list))
        evidence = path.read_text(encoding="utf-8")
        self.assertNotIn("session=secret", evidence)
        self.assertNotIn("private-body-do-not-save", evidence)
        self.assertNotIn("access_token=private", evidence)
        self.assertEqual(json.loads(evidence)["type"], "cors")

    def test_cors_confirmation_bar_true_positive_requires_all_three(self):
        """TP: reflected Origin + ACAC true + credentialed non-empty body → confirmed."""
        assessment = assess_cors_finding(
            origin="https://evil.com",
            allow_origin="https://evil.com",
            allow_credentials="true",
            request_headers={"Cookie": "session=lab"},
            status_code=200,
            body_text='{"bbtk_cors_private":true,"email":"lab@example.com"}',
            body_size=48,
        )
        self.assertEqual(assessment["classification"], "VULNERABLE")
        self.assertEqual(assessment["finding_state"], "confirmed")
        self.assertTrue(assessment["confirmed"])
        self.assertIsNone(assessment["confirmation_gap"])
        self.assertIsNone(assessment["rejection_reason"])

        client = Mock()
        options = CorsOptions("https://example.com/api/me", {"Cookie": "session=lab-secret"})
        # Reflect each probed Origin so the runner TP exercises confirmation for matching ACAO+ACAC+body.
        origins_headers = [
            {"access-control-allow-origin": "https://evil.com", "access-control-allow-credentials": "true"},
            {"access-control-allow-origin": "null", "access-control-allow-credentials": "true"},
            {"access-control-allow-origin": "https://evil.example.com", "access-control-allow-credentials": "true"},
            {
                "access-control-allow-origin": "https://example.com.evil.com",
                "access-control-allow-credentials": "true",
            },
        ]

        def send_tp(spec):
            headers = origins_headers[client.send.call_count - 1]
            return ResponseRecord(
                spec,
                spec.url,
                200,
                "OK",
                2,
                headers,
                '{"bbtk_cors_private":true,"account":"lab-user"}',
                45,
            )

        client.send.side_effect = send_tp
        path, results = CorsChecker(self.scope, client).run(options, self.root / "cors-tp")
        self.assertTrue(results[0]["confirmed"])
        self.assertEqual(results[0]["finding_state"], "confirmed")
        evidence = path.read_text(encoding="utf-8")
        self.assertNotIn("lab-secret", evidence)
        self.assertNotIn("bbtk_cors_private", evidence)
        self.assertNotIn("lab-user", evidence)
        payload = __import__("json").loads(evidence)
        self.assertEqual(payload["classification"], "confirmed")
        self.assertTrue(payload["confirmed"])

    def test_cors_confirmation_bar_true_negative_header_only_is_candidate(self):
        """TN: ACAO+ACAC without credentialed readable body → candidate, not confirmed."""
        # No credentials, empty body
        no_creds = assess_cors_finding(
            origin="https://evil.com",
            allow_origin="https://evil.com",
            allow_credentials="true",
            request_headers={},
            status_code=200,
            body_text="",
            body_size=0,
        )
        self.assertEqual(no_creds["finding_state"], "candidate")
        self.assertFalse(no_creds["confirmed"])
        self.assertEqual(no_creds["confirmation_gap"], "no_second_proof")

        # Credentials present but empty body still lacks second proof
        empty_body = assess_cors_finding(
            origin="https://evil.com",
            allow_origin="https://evil.com",
            allow_credentials="true",
            request_headers={"Authorization": "Bearer lab"},
            status_code=200,
            body_text="   ",
            body_size=3,
        )
        self.assertEqual(empty_body["finding_state"], "candidate")
        self.assertFalse(empty_body["confirmed"])
        self.assertEqual(empty_body["confirmation_gap"], "no_second_proof")

        # Explicit rejection records why
        rejected = assess_cors_finding(
            origin="https://evil.com",
            allow_origin="https://evil.com",
            allow_credentials="true",
            request_headers={"Cookie": "session=lab"},
            status_code=200,
            body_text='{"ok":true}',
            body_size=10,
            rejection_reason="false_positive",
        )
        self.assertEqual(rejected["finding_state"], "rejected")
        self.assertFalse(rejected["confirmed"])
        self.assertEqual(rejected["rejection_reason"], "false_positive")

        client = Mock()
        outcomes = [
            {"access-control-allow-origin": "https://evil.com", "access-control-allow-credentials": "true"},
            {"access-control-allow-origin": "null", "access-control-allow-credentials": "true"},
            {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"},
            {},
        ]

        def send(spec):
            headers = outcomes.pop(0)
            return ResponseRecord(spec, spec.url, 200, "OK", 1, headers, "", 0)

        client.send.side_effect = send
        # No Cookie / Authorization → header signal alone stays candidate
        options = CorsOptions("https://example.com/public")
        path, results = CorsChecker(self.scope, client).run(options, self.root / "cors-tn")
        self.assertEqual(results[0]["classification"], "VULNERABLE")
        self.assertEqual(results[0]["finding_state"], "candidate")
        self.assertFalse(results[0]["confirmed"])
        self.assertEqual(results[0]["confirmation_gap"], "no_second_proof")
        payload = __import__("json").loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["classification"], "candidate")
        self.assertFalse(payload["confirmed"])

    def test_open_redirect_payload_resolution_and_internal_cases(self):

        base = "https://app.example.com/login?next=%2Fhome"
        for payload in REDIRECT_PAYLOADS:
            with self.subTest(payload=payload):
                self.assertEqual(classify_redirect(base, payload), "VULNERABLE")
        self.assertEqual(classify_redirect(base, "/dashboard"), "NO VULNERABLE")
        self.assertEqual(classify_redirect(base, None), "NO VULNERABLE")
        self.assertEqual(classify_redirect(base, "https://not-evil.com/"), "NO VULNERABLE")
        self.assertEqual(classify_redirect(base, "https://evil.com/", 200), "NO VULNERABLE")
        self.assertEqual(classify_redirect(base, "https://evil.com/", 302), "VULNERABLE")
        replaced = replace_query_parameter(base, "next", "//evil.com")
        self.assertIn("next=%2F%2Fevil.com", replaced)
        with self.assertRaisesRegex(ValueError, "not present"):
            replace_query_parameter("https://app.example.com/login", "next", "x")
        with self.assertRaisesRegex(ValueError, "exactly once"):
            replace_query_parameter("https://app.example.com/login?next=a&next=b", "next", "x")

    def test_open_redirect_runner_records_status_and_handles_missing_location(self):
        client = Mock()
        locations = ["https://evil.com/", "/dashboard", None, "//evil.com", "/login"]
        statuses = [301, 302, 200, 307, 308]

        def send(spec):
            index = client.send.call_count - 1
            headers = {"location": locations[index]} if locations[index] else {}
            return ResponseRecord(spec, spec.url, statuses[index], "test", 2, headers, "body-not-evidence", 18)

        client.send.side_effect = send
        options = OpenRedirectOptions("https://example.com/login?next=%2F", "next", {"Cookie": "secret=session"})
        path, results = OpenRedirectTester(self.scope, client).run(options, self.root / "redirect-evidence")
        self.assertEqual(client.send.call_count, 5)
        self.assertEqual(results[0]["classification"], "VULNERABLE")
        self.assertTrue(results[0]["confirmed"])
        self.assertEqual(results[0]["finding_state"], "confirmed")
        self.assertEqual(results[1]["classification"], "NO VULNERABLE")
        self.assertEqual(results[2]["classification"], "NO VULNERABLE")
        self.assertIsNone(results[2]["location"])
        evidence = path.read_text(encoding="utf-8")
        payload = json.loads(evidence)
        self.assertNotIn("secret=session", evidence)
        self.assertNotIn("body-not-evidence", evidence)
        self.assertEqual(payload["type"], "open-redirect")
        self.assertTrue(payload["confirmed"])
        self.assertEqual(payload["finding_state"], "confirmed")

    def test_open_redirect_scope_preflight_sends_nothing(self):
        client = Mock()
        tester = OpenRedirectTester(self.scope, client)
        with self.assertRaises(ValueError):
            tester.validate(OpenRedirectOptions("https://outside.invalid/login?next=%2F", "next"))
        client.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
