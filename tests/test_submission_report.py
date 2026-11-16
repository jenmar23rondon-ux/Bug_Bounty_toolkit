"""Draft submission reports from stored findings. No network."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.core.reporting import render_markdown
from bugbounty_toolkit.reporting.submission import render_submission_html, validate_cvss


class SubmissionReportTests(unittest.TestCase):
    def test_markdown_and_html_cover_hackerone_sections_and_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = RecordStore(ProgramPaths(root, "lab"))
            store.add_finding(
                "F-1",
                "<script>title</script>",
                "information-disclosure",
                "low",
                "https://app.example.com/admin",
                "Authorization: Bearer private-summary-token",
                str(root / "evidence.json"),
                steps="1. Open the in-scope URL with the authorized test account.",
                impact="A signed-in user can read another user's profile field.",
                remediation="Authorize the object on the server before returning it.",
                cvss="5.3",
            )
            markdown_path = render_markdown(store.finding("F-1"), root / "F-1.md")
            html = render_submission_html(dict(store.finding("F-1")))
            text = markdown_path.read_text(encoding="utf-8")
            for heading in (
                "## Severity",
                "## Steps to reproduce",
                "## Impact",
                "## Evidence",
                "## Remediation",
            ):
                self.assertIn(heading, text)
            self.assertIn("not submitted", text)
            self.assertIn("CVSS: 5.3", text)
            self.assertNotIn("private-summary-token", text)
            self.assertNotIn("private-summary-token", html)
            self.assertIn("&lt;script&gt;", html)
            self.assertNotIn("<script>", html)
            store.close()

    def test_missing_sections_stay_explicit_and_cvss_is_validated(self) -> None:
        html = render_submission_html({"id": "F-2", "title": "Draft", "summary": "Observed a header."})
        self.assertIn("Not recorded", html)
        self.assertIn("not scored", html)
        self.assertEqual(
            validate_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        )
        self.assertEqual(validate_cvss("9"), "9.0")
        with self.assertRaises(ValueError):
            validate_cvss("CVSS:3.1/AV:X")
        with self.assertRaises(ValueError):
            validate_cvss("11")


if __name__ == "__main__":
    unittest.main()
