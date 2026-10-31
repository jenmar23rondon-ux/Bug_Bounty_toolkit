"""Offline unit tests for CORS / open-redirect impact assessment."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from bugbounty_toolkit.analysis.cors_redirect_impact import (
    IMPACT_EXPLOITABLE,
    IMPACT_INFO,
    IMPACT_NOT,
    SCHEMA,
    analyze_cors_redirect_impact,
    assess_redirect_chainability,
    classify_cors_impact,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cors_redirect_impact.har"


class CorsRedirectImpactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.har_text = FIXTURE.read_text(encoding="utf-8")
        self.report = analyze_cors_redirect_impact(self.har_text, source_label="fixture")

    def test_schema_never_confirm_no_network(self) -> None:
        self.assertEqual(self.report["schema"], SCHEMA)
        self.assertIs(self.report["finding_confirmed"], False)
        self.assertIs(self.report["requests_sent"], False)
        blob = json.dumps(self.report)
        self.assertNotIn("session=lab-not-for-output", blob)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", blob)

    def test_cors_impact_classes_from_har(self) -> None:
        by_impact = self.report["cors"]["by_impact"]
        self.assertGreaterEqual(by_impact.get(IMPACT_EXPLOITABLE, 0), 1)
        self.assertGreaterEqual(by_impact.get(IMPACT_NOT, 0), 1)
        self.assertGreaterEqual(by_impact.get(IMPACT_INFO, 0), 1)
        exploitable = next(f for f in self.report["cors"]["findings"] if f["impact"] == IMPACT_EXPLOITABLE)
        self.assertTrue(exploitable["credentialed_read_possible"])
        self.assertTrue(exploitable["body_sensitive"])
        self.assertIn("token", exploitable["sensitive_categories"])
        self.assertIs(exploitable["finding_confirmed"], False)

    def test_wildcard_not_credentialed(self) -> None:
        out = classify_cors_impact(
            allow_origin="*",
            allow_credentials="true",
            request_origin="https://evil.com",
            body_has_sensitive=True,
            sensitive_categories=["token"],
        )
        self.assertEqual(out["impact"], IMPACT_INFO)
        self.assertFalse(out["credentialed_read_possible"])

    def test_null_origin_with_acac(self) -> None:
        out = classify_cors_impact(
            allow_origin="null",
            allow_credentials="true",
            body_has_sensitive=False,
        )
        self.assertEqual(out["impact"], IMPACT_EXPLOITABLE)
        self.assertTrue(out["credentialed_read_possible"])

    def test_reflection_without_acac_is_info(self) -> None:
        out = classify_cors_impact(
            allow_origin="https://evil.com",
            allow_credentials=None,
            request_origin="https://evil.com",
        )
        self.assertEqual(out["impact"], IMPACT_INFO)

    def test_oauth_redirect_chainable(self) -> None:
        self.assertGreaterEqual(self.report["open_redirect"]["chainable_candidates"], 1)
        oauth = next(f for f in self.report["open_redirect"]["findings"] if f["parameter"] == "redirect_uri")
        self.assertTrue(oauth["chainable_candidate"])
        self.assertIsNotNone(oauth["chain_description"])
        self.assertIn("OAuth", oauth["chain_description"])
        self.assertIs(oauth["finding_confirmed"], False)

    def test_login_next_is_chainable_candidate(self) -> None:
        chain = assess_redirect_chainability(
            url="https://app.test/login?next=https://evil.com",
            parameter="next",
        )
        self.assertTrue(chain["chainable_candidate"])
        self.assertTrue(chain["path_oauth_like"])

    def test_markdown_summary(self) -> None:
        md = self.report["markdown"]
        self.assertIn("CORS / open-redirect impact", md)
        self.assertIn("finding_confirmed stays false", md)
        self.assertIn(IMPACT_EXPLOITABLE, md)


if __name__ == "__main__":
    unittest.main()
