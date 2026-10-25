import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.artifact_review import (
    MAX_ARTIFACT_BYTES,
    generate_ai_report,
    review_artifact,
    review_evidence_with_ollama,
    split_text,
)
from bugbounty_toolkit.analysis.ollama_review import OllamaUnavailableError


class AiArtifactReviewTests(unittest.TestCase):
    def test_chunking_overlaps_without_gaps(self):
        text = "x" * 600
        chunks, truncated = split_text(text, chunk_chars=256, max_chunks=5)
        self.assertFalse(truncated)
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[0][-25:], chunks[1][:25])
        self.assertEqual(chunks[1][-25:], chunks[2][:25])

    def test_html_artifact_redacts_hidden_session_and_csrf_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "form.html"
            path.write_text(
                '<input type="hidden" name="csrf_token" value="csrf-secret">'
                '<input type="hidden" name="session" value="session-secret">',
                encoding="utf-8",
            )
            with patch(
                "bugbounty_toolkit.analysis.artifact_review.chat_with_ollama",
                return_value='{"suggestions": []}',
            ) as chat:
                review_artifact(path, "html")
        sent = json.dumps(chat.call_args.args[0])
        self.assertNotIn("csrf-secret", sent)
        self.assertNotIn("session-secret", sent)

    def test_raw_http_artifact_redacts_every_non_allowlisted_header_and_secret_query_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.txt"
            path.write_text(
                "GET /search?token=query-secret&q=visible HTTP/1.1\r\n"
                "Host: private.example\r\nX-Research-Header: custom-secret\r\n"
                "Authorization: Bearer authorization-secret\r\nAccept: text/html\r\n\r\n",
                encoding="utf-8",
            )
            with patch(
                "bugbounty_toolkit.analysis.artifact_review.chat_with_ollama",
                return_value='{"suggestions": []}',
            ) as chat:
                review_artifact(path, "request")
        sent = json.dumps(chat.call_args.args[0])
        for secret in ("query-secret", "private.example", "custom-secret", "authorization-secret"):
            self.assertNotIn(secret, sent)
        self.assertIn("q=visible", sent)
        self.assertIn("Accept: text/html", sent)

    def test_invalid_model_json_is_retried_once_with_format_reminder(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "response.html"
            path.write_text("<html><body>id={{id}}</body></html>", encoding="utf-8")
            with patch(
                "bugbounty_toolkit.analysis.artifact_review.chat_with_ollama",
                side_effect=["plain text", '{"suggestions":[]}'],
            ) as chat:
                result = review_artifact(path, "html")
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["chunks_reviewed"], 1)
        self.assertEqual(result["network_requests_sent"], 2)
        self.assertEqual(chat.call_count, 2)
        self.assertIn("Retry once", chat.call_args.args[0][-1]["content"])

    def test_ollama_down_is_nonfatal_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.txt"
            path.write_text("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", encoding="utf-8")
            with patch(
                "bugbounty_toolkit.analysis.artifact_review.chat_with_ollama",
                side_effect=OllamaUnavailableError("stopped"),
            ):
                result = review_artifact(path, "request")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["decision"], "inconclusive")
        self.assertEqual(result["network_requests_sent"], 1)
        self.assertIn("127.0.0.1:11434", result["request_destination"])

    def test_oversized_file_returns_limit_status_without_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "huge.html"
            path.write_bytes(b"x" * (MAX_ARTIFACT_BYTES + 1))
            result = review_artifact(path, "html")
        self.assertEqual(result["status"], "limit_exceeded")
        self.assertEqual(result["network_requests_sent"], 0)
        self.assertTrue(result["truncated"])

    def test_max_chunks_reports_truncation_and_dry_run_never_calls_ollama(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.html"
            path.write_text("a" * 800, encoding="utf-8")
            with patch("bugbounty_toolkit.analysis.artifact_review.chat_with_ollama") as chat:
                result = review_artifact(path, "html", chunk_chars=256, max_chunks=1, dry_run=True)
        chat.assert_not_called()
        self.assertEqual(result["status"], "dry_run")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["chunks_planned"], 1)

    def test_evidence_review_sends_only_minimized_packet_and_handles_unavailable(self):
        evidence = {
            "type": "xss",
            "results": [{"classification": "possible", "status_code": 200}],
            "url": "https://secret.example/path?token=private",
            "body": "sensitive body",
        }
        with patch(
            "bugbounty_toolkit.analysis.artifact_review.review_with_ollama",
            side_effect=OllamaUnavailableError("offline"),
        ) as review:
            result = review_evidence_with_ollama(evidence)
        serialized = json.dumps(review.call_args.args[0])
        for secret in ("secret.example", "private", "sensitive body"):
            self.assertNotIn(secret, serialized)
        self.assertFalse(result["raw_evidence_sent"])
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("Segunda opinión", result["notice"])

    def test_cli_dry_run_artifact_outputs_second_opinion_notice(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "page.html"
            artifact.write_text("<p>safe</p>", encoding="utf-8")
            args = cli.build_parser().parse_args(
                ["ai-review", "sample", "--artifact", str(artifact), "--kind", "html", "--dry-run"]
            )
            output = StringIO()
            with (
                patch.object(cli, "RECORDS_ROOT", root / "records"),
                patch("bugbounty_toolkit.analysis.artifact_review.chat_with_ollama") as chat,
                redirect_stdout(output),
            ):
                args.func(args)
            chat.assert_not_called()
            self.assertIn("Segunda opinión, no confirmación", output.getvalue())
            self.assertIn('"status": "dry_run"', output.getvalue())
            self.assertFalse((root / "records").exists())

    def test_cli_evidence_mode_returns_local_second_opinion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            evidence.write_text(
                json.dumps({"type": "xss", "results": [{"classification": "possible", "status_code": 200}]}),
                encoding="utf-8",
            )
            args = cli.build_parser().parse_args(
                ["ai-review", "sample", "--evidence-file", str(evidence), "--ai-model", "qwen2.5-coder:7b"]
            )
            output = StringIO()
            expected = {
                "type": "ai-evidence-review",
                "status": "available",
                "decision": "candidate",
                "reason": "Manual review is appropriate.",
                "notice": "Segunda opinión, no confirmación.",
            }
            with (
                patch.object(cli, "RECORDS_ROOT", root / "records"),
                patch("bugbounty_toolkit.cli.review_evidence_with_ollama", return_value=expected),
                redirect_stdout(output),
            ):
                args.func(args)
        self.assertEqual(json.loads(output.getvalue().split("\n", 1)[1]), expected)

    def test_report_ai_falls_back_to_deterministic_template_when_ollama_is_down(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            evidence.write_text(json.dumps({"type": "xss", "results": []}), encoding="utf-8")
            output_path = root / "draft.md"
            args = cli.build_parser().parse_args(
                [
                    "report",
                    "sample",
                    "--evidence-file",
                    str(evidence),
                    "--output",
                    str(output_path),
                    "--draft-with-ai",
                ]
            )
            output = StringIO()
            with (
                patch.object(cli, "RECORDS_ROOT", root / "records"),
                patch("bugbounty_toolkit.cli.store_for"),
                patch("bugbounty_toolkit.cli.generate_ai_report", side_effect=OllamaUnavailableError("stopped")),
                redirect_stdout(output),
            ):
                args.func(args)
            draft = output_path.read_text(encoding="utf-8")
        self.assertIn("Deterministic template only", draft)
        self.assertIn("Finding and validation", draft)
        self.assertIn("Información pendiente", draft)
        self.assertIn("Nothing was submitted", output.getvalue())

    def test_ai_report_accepts_required_sections_and_uses_minimized_evidence(self):
        evidence = {
            "type": "xss",
            "results": [{"classification": "possible", "status_code": 200}],
            "url": "https://private.example/?token=secret-token",
            "body": "private response body",
        }
        draft = (
            "# XSS Review\n\n## Summary\nReview needed.\n\n## Affected Asset and Endpoint\nNot established.\n\n"
            "## Category and CWE\nNot established.\n\n## Preconditions\nNot established.\n\n"
            "## Steps to Reproduce\nNot established.\n\n## Expected Result\nNot established.\n\n"
            "## Observed Result\nA candidate was observed.\n\n## Evidence For and Against\nNot established.\n\n"
            "## Negative Controls\nNot established.\n\n## Demonstrated Impact\nNot established.\n\n"
            "## Suggested Severity and Basis\nNot established.\n\n## Limitations\nNot established.\n\n"
            "## Remediation\nNot established."
        )
        with patch("bugbounty_toolkit.analysis.artifact_review.chat_with_ollama", return_value=draft) as chat:
            result = generate_ai_report(evidence)
        sent = json.dumps(chat.call_args.args[0])
        self.assertNotIn("private.example", sent)
        self.assertNotIn("secret-token", sent)
        self.assertNotIn("private response body", sent)
        self.assertIn("Segunda opinión, no confirmación", result)


if __name__ == "__main__":
    unittest.main()
