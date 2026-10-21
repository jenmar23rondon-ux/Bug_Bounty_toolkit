import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import Mock, patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.core.http_client import ResponseRecord
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.ssrf_check import SSRF_PAYLOADS, SsrfChecker, SsrfOptions
from bugbounty_toolkit.utils.exceptions import ToolkitError


class SsrfCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        scope_path = self.root / "scope.txt"
        scope_path.write_text("example.com\n", encoding="utf-8")
        self.scope = ScopeValidator(scope_path)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def response(request, *, status=200, body="baseline", duration=20, headers=None):
        return ResponseRecord(
            request,
            request.prepared_url(),
            status,
            "test",
            duration,
            headers or {},
            body,
            len(body.encode("utf-8")),
        )

    def test_fixed_payloads_are_validated_and_comparison_records_only_minimized_data(self):
        client = Mock()
        bodies = [
            "changed-body-private-24",
            "stable-body-private-91",
            "stable-body-private-91",
            "stable-body-private-91",
            "stable-body-private-91",
        ]

        def send(spec):
            index = client.send.call_count - 1
            if index == 0:
                return self.response(spec, body="stable-body-private-91", duration=20)
            return self.response(spec, body=bodies[index - 1], duration=25 + index)

        client.send.side_effect = send
        options = SsrfOptions(
            "https://example.com/fetch?url=https%3A%2F%2Fexample.org&access_token=private-token",
            "url",
            {"Cookie": "session=private-cookie"},
        )
        checker = SsrfChecker(self.scope, client)
        urls = checker.validate(options)
        self.assertEqual(len(urls), 5)
        self.assertTrue(all("example.com/fetch?" in url for url in urls))

        path, evidence = checker.run(options, self.root / "evidence")
        self.assertEqual(client.send.call_count, 6)
        self.assertEqual(tuple(row["payload"] for row in evidence["results"]), SSRF_PAYLOADS)
        self.assertEqual(evidence["classification"], "possible")
        self.assertEqual(evidence["requests_attempted"], 6)
        self.assertEqual(evidence["results"][0]["classification"], "possible")
        self.assertTrue(evidence["results"][0]["response_differs"])
        self.assertEqual(evidence["results"][0]["timing_delta_ms"], 6)
        saved = path.read_text(encoding="utf-8")
        for secret in ("private-token", "private-cookie", "stable-body-private-91", "changed-body-private-24"):
            self.assertNotIn(secret, saved)
        self.assertEqual(json.loads(saved)["type"], "ssrf")

    def test_reflected_url_is_reported_without_persisting_response_body(self):
        client = Mock()

        def send(spec):
            index = client.send.call_count - 1
            body = "baseline body"
            if index == 1:
                body = f"Fetched {SSRF_PAYLOADS[0]} and secret metadata value"
            return self.response(spec, body=body)

        client.send.side_effect = send
        checker = SsrfChecker(self.scope, client)
        path, evidence = checker.run(
            SsrfOptions("https://example.com/fetch?url=https%3A%2F%2Fexample.org", "url"),
            self.root / "reflected-evidence",
        )
        self.assertEqual(evidence["results"][0]["classification"], "reflected")
        self.assertTrue(evidence["results"][0]["payload_reflected"])
        self.assertFalse(evidence["confirmed"])
        saved = path.read_text(encoding="utf-8")
        self.assertNotIn("secret metadata value", saved)
        self.assertNotIn("Fetched", saved)

    def test_unchanged_content_is_not_a_finding_but_timing_is_recorded(self):
        client = Mock()
        client.send.side_effect = lambda spec: self.response(
            spec, body="same response", duration=20 + client.send.call_count * 300
        )
        _, evidence = SsrfChecker(self.scope, client).run(
            SsrfOptions("https://example.com/fetch?url=ordinary", "url"), self.root / "same-evidence"
        )
        self.assertEqual(evidence["classification"], "not_observed")
        self.assertTrue(all(row["classification"] == "no_difference" for row in evidence["results"]))
        self.assertGreater(evidence["results"][0]["timing_delta_ms"], 0)
        self.assertFalse(evidence["confirmed"])

    def test_redirect_response_is_recorded_but_never_followed(self):
        client = Mock()

        def send(spec):
            index = client.send.call_count - 1
            if index == 1:
                return self.response(spec, status=302, body="baseline", headers={"location": "http://127.0.0.1/"})
            return self.response(spec, body="baseline")

        client.send.side_effect = send
        _, evidence = SsrfChecker(self.scope, client).run(
            SsrfOptions("https://example.com/fetch?url=ordinary", "url"), self.root / "redirect-evidence"
        )
        self.assertEqual(client.send.call_count, 6)
        self.assertEqual(evidence["results"][0]["classification"], "possible")
        self.assertNotIn("location", evidence["results"][0])

    def test_transport_failure_and_access_denial_stop_without_retry(self):
        client = Mock()

        def fail_after_baseline(spec):
            if client.send.call_count == 1:
                return self.response(spec)
            raise ToolkitError("private transport detail")

        client.send.side_effect = fail_after_baseline
        path, evidence = SsrfChecker(self.scope, client).run(
            SsrfOptions("https://example.com/fetch?url=ordinary", "url"), self.root / "error-evidence"
        )
        self.assertEqual(client.send.call_count, 2)
        self.assertEqual(evidence["stop_reason"], "transport_error")
        self.assertEqual(evidence["results"][0]["reason"], "ToolkitError")
        self.assertNotIn("private transport detail", path.read_text(encoding="utf-8"))

        denied = Mock()
        denied.send.side_effect = lambda spec: self.response(spec, status=403)
        _, denied_evidence = SsrfChecker(self.scope, denied).run(
            SsrfOptions("https://example.com/fetch?url=ordinary", "url"), self.root / "denied-evidence"
        )
        denied.send.assert_called_once()
        self.assertEqual(denied_evidence["stop_reason"], "access_or_rate_limit")
        self.assertEqual(denied_evidence["results"], [])

    def test_truncated_baseline_stops_as_inconclusive(self):
        client = Mock()
        client.send.side_effect = lambda spec: ResponseRecord(
            spec, spec.prepared_url(), 200, "OK", 10, {}, "partial", 7, body_truncated=True
        )
        _, evidence = SsrfChecker(self.scope, client).run(
            SsrfOptions("https://example.com/fetch?url=ordinary", "url"), self.root / "truncated-evidence"
        )
        client.send.assert_called_once()
        self.assertEqual(evidence["classification"], "inconclusive")
        self.assertEqual(evidence["stop_reason"], "truncated_response")

    def test_validation_rejects_missing_parameter_and_out_of_scope_target(self):
        client = Mock()
        checker = SsrfChecker(self.scope, client)
        with self.assertRaisesRegex(ValueError, "not present"):
            checker.validate(SsrfOptions("https://example.com/fetch", "url"))
        with self.assertRaises(ValueError):
            checker.validate(SsrfOptions("https://outside.invalid/fetch?url=x", "url"))
        client.send.assert_not_called()

    def test_cli_parser_exposes_scope_limited_ssrf_command(self):
        args = cli.build_parser().parse_args(
            [
                "ssrf-check",
                "lab",
                "--url",
                "https://example.com/fetch?url=ordinary",
                "--param",
                "url",
                "--timeout",
                "8",
                "--rate",
                "0.5",
                "--dry-run",
            ]
        )
        self.assertEqual(args.func, cli.cmd_ssrf_check)
        self.assertTrue(args.dry_run)
        self.assertEqual(args.timeout, 8.0)
        self.assertEqual(args.rate, 0.5)

    def test_cli_dry_run_validates_without_sending_requests(self):
        args = cli.build_parser().parse_args(
            [
                "ssrf-check",
                "lab",
                "--url",
                "https://example.com/fetch?url=ordinary",
                "--param",
                "url",
                "--dry-run",
            ]
        )
        client = Mock()
        with (
            patch.object(cli, "executor_context", return_value=(Mock(), Mock(), self.scope)),
            patch.object(cli, "client_for", return_value=client),
            redirect_stdout(StringIO()),
        ):
            cli.cmd_ssrf_check(args)
        client.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
