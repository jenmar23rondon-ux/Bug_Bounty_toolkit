from http.client import HTTPMessage
from pathlib import Path
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import Mock, patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.core.http_client import HttpClient, RequestSpec, ResponseRecord
from bugbounty_toolkit.core.scope_validator import ScopeValidator
from bugbounty_toolkit.csrf_audit import CsrfAuditor, CsrfOptions
from bugbounty_toolkit.utils.exceptions import ToolkitError


class CsrfAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        scope_file = self.root / "scope.txt"
        scope_file.write_text("example.com\n", encoding="utf-8")
        self.scope = ScopeValidator(scope_file)
        self.options = CsrfOptions("https://example.com/account", {"Cookie": "session=request-secret"})

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def response(
        request: RequestSpec,
        body: str,
        *,
        status: int = 200,
        content_type: str = "text/html; charset=utf-8",
        cookies: tuple[str, ...] = (),
        truncated: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> ResponseRecord:
        response_headers = {"content-type": content_type}
        response_headers.update(extra_headers or {})
        return ResponseRecord(
            request,
            request.prepared_url(),
            status,
            "test",
            4,
            response_headers,
            body,
            len(body.encode("utf-8")),
            truncated,
            cookies,
        )

    def run_html(self, html: str, cookies: tuple[str, ...] = ()):
        client = Mock()
        client.send.side_effect = lambda spec: self.response(spec, html, cookies=cookies)
        path, evidence = CsrfAuditor(self.scope, client).run(self.options, self.root / "evidence")
        return client, path, evidence

    def test_post_form_hidden_csrf_token_and_samesite_cookies_are_heuristically_protected(self):
        client, path, evidence = self.run_html(
            '<form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="private-form-token"></form>',
            (
                "session=private-session; Path=/; SameSite=Lax; Secure; HttpOnly",
                "analytics=private-id; SameSite=Strict",
            ),
        )
        client.send.assert_called_once()
        self.assertEqual(evidence["classification"], "protected")
        self.assertEqual(evidence["form_methods"], ["post"])
        self.assertEqual(evidence["post_forms_with_hidden_token"], 1)
        self.assertEqual(evidence["cookie_samesite"], ["lax", "strict"])
        self.assertFalse(evidence["confirmed"])
        saved = path.read_text(encoding="utf-8")
        for private in ("private-form-token", "private-session", "private-id", "request-secret"):
            self.assertNotIn(private, saved)

    def test_no_token_with_lax_or_insecure_none_cookie_is_possible_csrf(self):
        _, _, evidence = self.run_html(
            '<form method="POST"><input name="comment"></form>',
            ("session=private-session; SameSite=Lax", "legacy=private-id; SameSite=None"),
        )
        self.assertEqual(evidence["classification"], "possible_csrf")
        self.assertEqual(evidence["samesite_none_without_secure"], 1)
        self.assertEqual(evidence["post_forms_with_hidden_token"], 0)

    def test_missing_token_with_strict_cookie_is_weak_not_possible(self):
        _, _, evidence = self.run_html(
            '<form method="post"><input type="text" name="csrf_token" value="not-hidden"></form>',
            ("session=private-session; SameSite=Strict; Secure",),
        )
        self.assertEqual(evidence["classification"], "weak")
        self.assertEqual(evidence["post_forms_with_hidden_token"], 0)

    def test_token_with_missing_samesite_is_weak(self):
        _, _, evidence = self.run_html(
            '<form method="post"><input type="hidden" id="authenticity_token" value="private-token"></form>',
            ("session=private-session",),
        )
        self.assertEqual(evidence["classification"], "weak")

    def test_single_set_cookie_header_fallback_is_parsed_and_malformed_cookie_is_unknown(self):
        html = '<form method="post"><input type="hidden" name="csrf_token"></form>'
        client = Mock()
        client.send.side_effect = lambda spec: self.response(
            spec, html, extra_headers={"set-cookie": "session=private-value; SameSite=Lax"}
        )
        _, evidence = CsrfAuditor(self.scope, client).run(self.options, self.root / "single-cookie")
        self.assertEqual(evidence["classification"], "protected")
        self.assertEqual(evidence["cookie_samesite"], ["lax"])

        _, _, malformed = self.run_html(html, ("not-a-cookie",))
        self.assertEqual(malformed["classification"], "weak")
        self.assertEqual(malformed["cookie_samesite"], ["unknown"])

    def test_transport_error_is_saved_as_inconclusive_without_error_details(self):
        client = Mock()
        client.send.side_effect = ToolkitError("private transport detail")
        path, evidence = CsrfAuditor(self.scope, client).run(self.options, self.root / "transport-error")
        self.assertEqual(evidence["classification"], "inconclusive")
        self.assertEqual(evidence["stop_reason"], "transport_error")
        self.assertNotIn("private transport detail", path.read_text(encoding="utf-8"))

    def test_form_method_defaults_to_get_and_no_form_is_reported_as_weak(self):
        _, _, no_form = self.run_html("<main>Account</main>")
        _, _, get_form = self.run_html('<form><input type="hidden" name="csrf_token"></form>')
        self.assertEqual(no_form["classification"], "weak")
        self.assertEqual(no_form["form_count"], 0)
        self.assertEqual(get_form["form_methods"], ["get"])
        self.assertEqual(get_form["classification"], "weak")

    def test_non_html_truncated_denied_and_redirect_responses_are_inconclusive(self):
        for kwargs, expected_stop in (
            ({"content_type": "application/json"}, "not_html"),
            ({"truncated": True}, "truncated_response"),
            ({"status": 403}, "access_or_rate_limit"),
            ({"status": 302}, "redirect_not_followed"),
            ({"status": 500}, "unexpected_status"),
        ):
            with self.subTest(reason=expected_stop):
                client = Mock()
                client.send.side_effect = lambda spec, values=kwargs: self.response(spec, "<form></form>", **values)
                _, evidence = CsrfAuditor(self.scope, client).run(self.options, self.root / expected_stop)
                client.send.assert_called_once()
                self.assertEqual(evidence["classification"], "inconclusive")
                self.assertEqual(evidence["stop_reason"], expected_stop)

    def test_scope_validation_happens_before_request(self):
        client = Mock()
        auditor = CsrfAuditor(self.scope, client)
        with self.assertRaises(ValueError):
            auditor.run(CsrfOptions("https://outside.invalid/account"), self.root / "out-of-scope")
        client.send.assert_not_called()

    def test_non_http_url_is_rejected_before_scope_or_request(self):
        client = Mock()
        auditor = CsrfAuditor(self.scope, client)
        with self.assertRaisesRegex(ValueError, "absolute HTTP"):
            auditor.run(CsrfOptions("file:///etc/passwd"), self.root / "invalid-url")
        client.send.assert_not_called()

    def test_http_client_preserves_all_set_cookie_headers_for_audit(self):
        client = HttpClient(self.scope)
        headers = HTTPMessage()
        headers.add_header("Content-Type", "text/html")
        headers.add_header("Set-Cookie", "one=private-one; SameSite=Lax")
        headers.add_header("Set-Cookie", "two=private-two; SameSite=Strict")
        record = client._record(
            RequestSpec("GET", self.options.url),
            self.options.url,
            200,
            "OK",
            headers,
            b"<form></form>",
            time.perf_counter(),
            False,
        )
        self.assertEqual(len(record.set_cookies), 2)
        self.assertIn("private-one", record.set_cookies[0])
        self.assertIn("private-two", record.set_cookies[1])

    def test_cli_parser_and_dry_run_never_send_http(self):
        args = cli.build_parser().parse_args(
            ["csrf-audit", "lab", "--url", self.options.url, "--timeout", "7", "--rate", "0.5", "--dry-run"]
        )
        self.assertEqual(args.func, cli.cmd_csrf_audit)
        self.assertEqual(args.timeout, 7.0)
        client = Mock()
        with (
            patch.object(cli, "executor_context", return_value=(Mock(), Mock(), self.scope)),
            patch.object(cli, "client_for", return_value=client),
            redirect_stdout(StringIO()),
        ):
            cli.cmd_csrf_audit(args)
        client.send.assert_not_called()

    def test_cli_execution_records_possible_result_and_evidence_path(self):
        args = cli.build_parser().parse_args(["csrf-audit", "lab", "--url", self.options.url])
        store = Mock()
        store.paths.evidence_dir = self.root / "evidence"
        evidence_path = self.root / "csrf.json"
        result = {
            "classification": "possible_csrf",
            "form_count": 1,
            "form_methods": ["post"],
            "post_forms_with_hidden_token": 0,
            "cookie_samesite": ["lax"],
            "samesite_none_without_secure": 0,
            "stop_reason": None,
        }
        auditor = Mock()
        auditor.run.return_value = (evidence_path, result)
        with (
            patch.object(cli, "executor_context", return_value=(store, Mock(), self.scope)),
            patch.object(cli, "client_for", return_value=Mock()),
            patch.object(cli, "CsrfAuditor", return_value=auditor),
            redirect_stdout(StringIO()),
        ):
            cli.cmd_csrf_audit(args)
        auditor.validate.assert_called_once()
        auditor.run.assert_called_once_with(auditor.validate.call_args.args[0], store.paths.evidence_dir / "csrf-audit")
        self.assertEqual(store.add_run.call_args.args[0], "csrf-audit")
        self.assertEqual(store.add_run.call_args.args[3], 1)
        self.assertEqual(store.add_run.call_args.args[4], evidence_path)


if __name__ == "__main__":
    unittest.main()
