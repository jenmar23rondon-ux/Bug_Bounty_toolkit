import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.live_review import (
    DEFAULT_AI_REVIEW_TIMEOUT,
    format_ai_review,
    resolve_ai_review_config,
    review_evidence_file,
)
from bugbounty_toolkit.analysis.ollama_review import DEFAULT_OLLAMA_MODEL


class LiveAiReviewTests(unittest.TestCase):
    def test_candidate_sends_only_minimized_packet_and_persists_assessment(self):
        source = {
            "type": "sqli",
            "classification": "possible",
            "raw_url": "https://private.example/item?token=secret-token",
            "request_headers": {"Authorization": "Bearer secret-header"},
            "results": [
                {
                    "classification": "possible",
                    "status_code": 500,
                    "body": "private response body",
                    "cookie": "secret-cookie",
                }
            ],
        }
        assessment = {
            "decision": "candidate",
            "summary": "An indicator merits manual review.",
            "evidence": ["The response contained a new error family."],
            "limitations": ["This is not confirmation."],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            with patch(
                "bugbounty_toolkit.analysis.live_review.review_with_ollama",
                return_value={"assessment": assessment, "provider": "ollama-local"},
            ) as review:
                saved = review_evidence_file(path, DEFAULT_OLLAMA_MODEL, DEFAULT_AI_REVIEW_TIMEOUT)

            packet = review.call_args.args[0]
            packet_text = json.dumps(packet)
            for secret in (
                "private.example",
                "secret-token",
                "secret-header",
                "private response body",
                "secret-cookie",
            ):
                self.assertNotIn(secret, packet_text)
            self.assertEqual(packet["type"], "agent-review")
            self.assertEqual(saved["status"], "available")
            self.assertEqual(saved["assessment"], assessment)
            self.assertEqual(saved["reason"], assessment["summary"])
            evidence = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["ai_review"], saved)

    def test_no_candidate_skips_ollama_and_records_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps({"type": "xss", "results": [{"classification": "not_reflected"}]}))
            with patch("bugbounty_toolkit.analysis.live_review.review_with_ollama") as review:
                result = review_evidence_file(path, DEFAULT_OLLAMA_MODEL, DEFAULT_AI_REVIEW_TIMEOUT)
            review.assert_not_called()
            self.assertEqual(result["status"], "skipped")
            self.assertEqual(json.loads(path.read_text())["ai_review"], result)

    def test_ollama_failure_is_non_fatal_and_saved_as_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps({"type": "cors", "results": [{"classification": "VULNERABLE"}]}))
            with patch(
                "bugbounty_toolkit.analysis.live_review.review_with_ollama",
                side_effect=OSError("local service stopped"),
            ):
                result = review_evidence_file(path, DEFAULT_OLLAMA_MODEL, DEFAULT_AI_REVIEW_TIMEOUT)
            self.assertEqual(result, "unavailable")
            self.assertEqual(json.loads(path.read_text())["ai_review"], "unavailable")

    def test_possible_csrf_is_sent_as_minimized_ai_review_candidate(self):
        evidence = {
            "type": "csrf-audit",
            "classification": "possible_csrf",
            "url": "https://private.example/form?session=secret",
            "forms": [{"method": "post", "hidden_token_present": False}],
            "cookies": [{"samesite": "lax", "secure": True, "httponly": True}],
            "confirmed": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "csrf.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            with patch(
                "bugbounty_toolkit.analysis.live_review.review_with_ollama",
                return_value={
                    "assessment": {"decision": "candidate", "summary": "Review the form defense."},
                    "provider": "ollama-local",
                },
            ) as review:
                result = review_evidence_file(path, DEFAULT_OLLAMA_MODEL, DEFAULT_AI_REVIEW_TIMEOUT)
            serialized = json.dumps(review.call_args.args[0])
            self.assertNotIn("private.example", serialized)
            self.assertNotIn("secret", serialized)
            self.assertEqual(result["status"], "available")

    def test_configuration_defaults_and_requires_opt_in(self):
        self.assertEqual(
            resolve_ai_review_config(True, None, None),
            (DEFAULT_OLLAMA_MODEL, DEFAULT_AI_REVIEW_TIMEOUT),
        )
        self.assertIsNone(resolve_ai_review_config(False, None, None))
        with self.assertRaisesRegex(ValueError, "require --ai-review"):
            resolve_ai_review_config(False, "custom:latest", None)
        with self.assertRaisesRegex(ValueError, "timeout"):
            resolve_ai_review_config(True, None, 0)

    def test_all_live_commands_accept_ai_review_options(self):
        parser = cli.build_parser()
        cases = (
            ["xss", "prog", "--routes", "routes.txt", "--parameters", "params.txt"],
            ["sqli", "prog", "--routes", "routes.txt", "--parameters", "params.txt"],
            ["cors-check", "prog", "--url", "https://target.example/"],
            ["open-redirect", "prog", "--url", "https://target.example/?next=x", "--param", "next"],
            ["access-check", "prog", "--case-file", "case.json"],
            ["ssrf-check", "prog", "--url", "https://target.example/?url=x", "--param", "url"],
            ["csrf-audit", "prog", "--url", "https://target.example/form"],
            ["hunt", "prog", "--base-url", "https://target.example/"],
        )
        for command in cases:
            with self.subTest(command=command[0]):
                args = parser.parse_args([*command, "--ai-review", "--ai-model", "custom:latest", "--ai-timeout", "45"])
                self.assertTrue(args.ai_review)
                self.assertEqual(args.ai_model, "custom:latest")
                self.assertEqual(args.ai_timeout, 45.0)

    def test_output_keeps_toolkit_verdict_separate_from_ai_assessment(self):
        line = format_ai_review(
            {
                "status": "available",
                "assessment": {"decision": "not_observed", "summary": "No signal in the minimized evidence."},
            },
            "possible SQLi indicators",
        )
        self.assertIn("AI second opinion: not_observed", line)
        self.assertIn("No signal in the minimized evidence.", line)
        self.assertIn("toolkit verdict: possible SQLi indicators", line)
        self.assertIn("does not confirm findings", line)
        flattened = format_ai_review(
            {
                "status": "available",
                "decision": "candidate",
                "reason": "The A/B comparison differs.",
                "not_confirmation": True,
            },
            "possible",
        )
        self.assertIn("AI second opinion: candidate", flattened)
        self.assertIn("The A/B comparison differs.", flattened)
        self.assertIn("AI second opinion: unavailable", format_ai_review("unavailable", "candidate"))


if __name__ == "__main__":
    unittest.main()
