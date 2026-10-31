"""Offline unit tests for SSRF parameter discovery and candidate ideas."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from bugbounty_toolkit.analysis.ssrf_analysis import (
    SCHEMA,
    analyze_ssrf,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "ssrf_analysis.har"


class SsrfAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.har_text = FIXTURE.read_text(encoding="utf-8")
        self.plan = analyze_ssrf(self.har_text, source_label="fixture")

    def test_schema_never_confirm_offline(self) -> None:
        self.assertEqual(self.plan["schema"], SCHEMA)
        self.assertIs(self.plan["finding_confirmed"], False)
        self.assertIs(self.plan["requests_sent"], False)
        blob = json.dumps(self.plan)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", blob)
        for idea in self.plan["ideas"]:
            self.assertIs(idea["finding_confirmed"], False)

    def test_detects_ssrf_prone_parameters(self) -> None:
        names = {p["name"] for p in self.plan["parameters"]}
        for expected in ("url", "dest", "webhook", "callback", "host", "file", "feed", "X-Original-URL"):
            self.assertIn(expected, names, msg=f"missing {expected}")
        self.assertGreaterEqual(self.plan["parameter_count"], 7)

    def test_ideas_cover_ssrf_classes_and_manual_flags(self) -> None:
        classes = {i["idea_class"] for i in self.plan["ideas"]}
        for expected in (
            "internal_ip",
            "cloud_metadata",
            "localhost_variant",
            "localhost_encoding",
            "alt_scheme",
            "dns_rebinding",
            "blind_oob",
        ):
            self.assertIn(expected, classes)
        manual = [i for i in self.plan["ideas"] if i["manual_only"]]
        self.assertGreaterEqual(len(manual), 2)
        self.assertTrue(all("manual" in (i.get("note") or "").lower() or i["manual_only"] for i in manual))
        # Metadata path idea present but body/secrets never retained.
        meta = [i for i in self.plan["ideas"] if i["idea_class"] == "cloud_metadata"]
        self.assertTrue(any("169.254.169.254" in i["payload_idea"] for i in meta))

    def test_markdown_summary(self) -> None:
        md = self.plan["markdown"]
        self.assertIn("SSRF analysis", md)
        self.assertIn("finding_confirmed stays false", md)
        self.assertIn("url", md)

    def test_json_records_input(self) -> None:
        records = {
            "records": [
                {
                    "method": "GET",
                    "url": "https://shop.test/proxy?uri=https://cdn.test/a",
                    "headers": [],
                }
            ]
        }
        plan = analyze_ssrf(json.dumps(records), source_label="json")
        names = {p["name"] for p in plan["parameters"]}
        self.assertIn("uri", names)
        self.assertIs(plan["finding_confirmed"], False)


if __name__ == "__main__":
    unittest.main()
