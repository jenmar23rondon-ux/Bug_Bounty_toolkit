"""Unit and lab regressions for destination-aware evidence redaction."""

from __future__ import annotations

import json
import unittest

from bugbounty_toolkit.core.redaction import (
    REDACTED,
    RedactionDestination,
    detect_truncation,
    provenance_digest,
    pseudonymize_identifier,
    redact_data,
    redact_for,
    redact_headers,
    redact_text,
    redact_url,
    scrub_model_output,
)
from labs.evidence_redaction_lab.canaries import (
    ALL_CANARIES,
    API_KEY,
    JWT,
    SESSION_ID,
    adversarial_text,
    html_form,
    http_message,
    large_body,
    nested_json,
    private_payload,
    query_string,
    shareable_payload,
)
from labs.evidence_redaction_lab.evaluate import evaluate


class DestinationRedactionTests(unittest.TestCase):
    def test_shareable_report_drops_all_lab_canaries(self) -> None:
        result = redact_for(RedactionDestination.SHAREABLE_REPORT, shareable_payload())
        text = json.dumps(result.value, ensure_ascii=True)
        for canary in ALL_CANARIES:
            self.assertNotIn(canary, text, canary)

    def test_private_evidence_remains_usable(self) -> None:
        result = redact_for(RedactionDestination.PRIVATE_EVIDENCE, private_payload())
        text = json.dumps(result.value, ensure_ascii=True)
        self.assertIn("private-marker-owner", text)
        self.assertIn(SESSION_ID, text)
        self.assertIn("/home/researcher/registros/private/capture.har", text)
        self.assertIn("b" * 64, text)

    def test_structured_json_nested_and_headers(self) -> None:
        data = redact_data(nested_json(), destination=RedactionDestination.SHAREABLE_REPORT)
        self.assertEqual(data["user"]["profile"]["api_key"], REDACTED)
        self.assertEqual(data["meta"]["authorization"], REDACTED)
        self.assertEqual(data["provenance_hash"], "a" * 64)
        self.assertEqual(data["source_path"], "[path-redacted]")
        self.assertNotIn(API_KEY, json.dumps(data))

    def test_http_url_query_html(self) -> None:
        http = redact_text(http_message(), destination=RedactionDestination.SHAREABLE_REPORT) or ""
        self.assertNotIn(JWT, http)
        self.assertIn("Authorization: [redacted]", http)
        url = redact_url(f"https://user:pass@api.example.test/x?token={SESSION_ID}")
        self.assertNotIn("pass", url)
        self.assertIn("redacted", url)
        html = redact_text(html_form(), destination=RedactionDestination.SHAREABLE_REPORT) or ""
        self.assertNotIn("BBTK-CANARY-HTML", html)
        query = redact_text(query_string(), destination=RedactionDestination.SHAREABLE_REPORT) or ""
        self.assertNotIn(SESSION_ID, query)

    def test_malformed_and_large_bounded(self) -> None:
        malformed = '{"token": "BBTK-CANARY-NESTED-4c88", "broken": '
        out = redact_text(malformed, destination=RedactionDestination.SHAREABLE_REPORT) or ""
        self.assertNotIn("BBTK-CANARY-NESTED-4c88", out)
        large = redact_for(RedactionDestination.SHAREABLE_REPORT, large_body(100_000))
        self.assertLess(large.elapsed_ms, 5_000)
        self.assertEqual(_count := sum(1 for c in ALL_CANARIES if c in str(large.value)), 0, _count)

    def test_ai_output_cannot_reintroduce_canaries(self) -> None:
        cleaned, changed = scrub_model_output(adversarial_text())
        self.assertTrue(changed)
        for canary in ALL_CANARIES:
            self.assertNotIn(canary, cleaned)

    def test_provenance_and_pseudonym_do_not_leak_preimage(self) -> None:
        secret = "super-secret-preimage"
        digest = provenance_digest(secret)
        self.assertEqual(len(digest), 64)
        self.assertNotIn(secret, digest)
        pseudo = pseudonymize_identifier("acct-1", salt="program")
        self.assertTrue(pseudo.startswith("bbtk-id-"))
        self.assertNotIn("acct-1", pseudo)
        self.assertEqual(pseudo, pseudonymize_identifier("acct-1", salt="program"))

    def test_truncation_marks_validity(self) -> None:
        info = detect_truncation(5000, 100, claimed_complete=True)
        self.assertTrue(info["truncated"])
        self.assertTrue(info["validity_affected"])
        bounded = redact_for(RedactionDestination.SHAREABLE_REPORT, "z" * 500, max_chars=50)
        self.assertTrue(bounded.truncated)

    def test_shareable_headers_redact_unknown(self) -> None:
        headers = redact_headers(
            {"Authorization": "Bearer x", "X-Custom": "secret-value", "Content-Type": "application/json"},
            destination=RedactionDestination.SHAREABLE_REPORT,
        )
        self.assertEqual(headers["Authorization"], REDACTED)
        self.assertEqual(headers["X-Custom"], REDACTED)
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_lab_evaluate_zero_shareable_leaks_and_no_network(self) -> None:
        report = evaluate()
        self.assertEqual(report["network_attempts"], 0)
        self.assertEqual(report["after_shareable_policy"]["leaked_canaries"], 0)
        self.assertEqual(report["console_leaks"], 0)
        self.assertEqual(report["model_input_leaks"], 0)
        self.assertEqual(report["ai_output_scrub"]["leaks"], 0)
        self.assertTrue(report["private_evidence_usable"])
        self.assertFalse(report["absolute_privacy_claimed"])
        self.assertGreater(report["large_body"]["elapsed_ms"], 0)
        self.assertLess(report["large_body"]["elapsed_ms"], 5_000)


if __name__ == "__main__":
    unittest.main()
