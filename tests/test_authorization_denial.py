"""Unit + corpus tests for authorization-denial-aware case assessment."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from bugbounty_toolkit.analysis.authorization_denial import (
    ANNOTATION_VERSION,
    assess_pair_authorization,
    assess_raw_response,
    assess_response,
)
from bugbounty_toolkit.analysis.idor_e2e_research import run_e2e_research
from bugbounty_toolkit.analysis.evidence_gap_planner import build_plan
from bugbounty_toolkit.core.records import ProgramPaths

LAB = Path(__file__).resolve().parents[1] / "labs" / "authorization_denial_eval"
IRB_FINAL = Path(__file__).resolve().parents[1] / "labs" / "independent_research_eval" / "final" / "captures"
KEY = b"\x00" * 32


# Frozen corpus labels document behaviour before the production consistency fix.
# Keep them intact; production now conservatively abstains on contradictions.
_HISTORICAL_CONTRADICTION_CASES = frozenset({"D07_contradictory_403_body", "F11_contradictory_401_with_payload"})


def _raw(status: int, body: str, *, location: str | None = None) -> str:
    headers = ["Content-Type: application/json"]
    if location:
        headers.append(f"Location: {location}")
    return f"HTTP/1.1 {status} X\r\n" + "\r\n".join(headers) + "\r\n\r\n" + body


def _load_corpus(split: str) -> list[dict]:
    path = LAB / split / "cases.json"
    return json.loads(path.read_text(encoding="utf-8"))


class AuthorizationDenialTests(unittest.TestCase):
    def test_http_403_with_denial_body_is_denied(self) -> None:
        assessment = assess_response(403, '{"error":"forbidden","ok":false}')
        self.assertTrue(assessment.denial_demonstrated)
        self.assertEqual(assessment.response_class, "http_denial")

    def test_http_401_and_404_are_denied(self) -> None:
        for status, error in ((401, "unauthenticated"), (404, "not_found")):
            with self.subTest(status=status):
                self.assertTrue(assess_response(status, json.dumps({"error": error, "ok": False})).denial_demonstrated)

    def test_http_200_with_denial_body_is_content_denial(self) -> None:
        assessment = assess_response(200, '{"contract":null,"error":"not_authorized","ok":false}')
        self.assertTrue(assessment.denial_demonstrated)
        self.assertTrue(assessment.content_denial)
        self.assertEqual(assessment.response_class, "content_denial")

    def test_http_200_with_resource_payload_is_not_denial(self) -> None:
        assessment = assess_response(200, '{"ok":true,"statement":{"id":1,"marker":"m","owner_label":"owner"}}')
        self.assertFalse(assessment.denial_demonstrated)
        self.assertTrue(assessment.access_demonstrated)

    def test_contradictory_403_with_owner_data_stays_inconclusive(self) -> None:
        """A06-style: status says denied but body returns private resource data."""
        assessment = assess_response(
            403,
            '{"claim":{"id":74302,"marker":"irb-claim-owner-74302","owner_label":"owner"},"ok":true}',
        )
        self.assertFalse(assessment.denial_demonstrated)
        self.assertTrue(assessment.access_demonstrated)
        self.assertEqual(assessment.response_class, "successful_looking")

    def test_contradictory_pair_is_not_promoted_to_possible_access(self) -> None:
        owner = _raw(200, '{"ok":true,"statement":{"id":1,"marker":"m","owner_label":"owner"}}')
        actor = _raw(403, '{"ok":true,"statement":{"id":1,"marker":"m","owner_label":"owner"}}')
        result = assess_pair_authorization(owner, actor)
        self.assertEqual(result.outcome, "inconclusive")
        self.assertIn("contradictory_authorization_evidence", result.reasons)

    def test_auth_redirect_302_to_login_is_denied(self) -> None:
        assessment = assess_response(302, "", {"location": "http://127.0.0.1:8177/login"})
        self.assertTrue(assessment.denial_demonstrated)
        self.assertEqual(assessment.response_class, "auth_redirect")

    def test_public_visibility_is_not_cross_account_denial(self) -> None:
        assessment = assess_response(200, '{"item":{"id":1,"visibility":"public"},"ok":true}')
        self.assertEqual(assessment.resource_visibility, "public")
        self.assertFalse(assessment.denial_demonstrated)

    def test_pair_owner_success_actor_denied_is_negative_control(self) -> None:
        owner = _raw(200, '{"ok":true,"payslip":{"id":1,"marker":"m","owner_label":"owner"}}')
        actor = _raw(403, '{"error":"forbidden","ok":false}')
        result = assess_pair_authorization(owner, actor)
        self.assertEqual(result.outcome, "cross_account_denied")
        self.assertIsNotNone(result.annotation)
        annotation = result.annotation or {}
        self.assertEqual(annotation["annotation_version"], ANNOTATION_VERSION)
        self.assertEqual(annotation["role"], "negative_control")
        self.assertIs(annotation["contradicts_hypothesis"], True)

    def test_owner_control_failure_stays_inconclusive(self) -> None:
        owner = _raw(401, '{"error":"unauthenticated","ok":false}')
        actor = _raw(200, '{"ok":true,"statement":{"id":1,"marker":"m"}}')
        self.assertEqual(assess_pair_authorization(owner, actor).outcome, "inconclusive")

    def test_pair_both_success_is_possible_access_not_confirmed(self) -> None:
        owner = _raw(200, '{"ok":true,"statement":{"id":1,"marker":"m","owner_label":"owner"}}')
        actor = _raw(200, '{"ok":true,"statement":{"id":1,"marker":"m","owner_label":"owner"}}')
        result = assess_pair_authorization(owner, actor)
        self.assertEqual(result.outcome, "possible_access")
        self.assertIsNotNone(result.annotation)
        annotation = result.annotation or {}
        self.assertIs(annotation.get("access_confirmed"), False)
        self.assertIsNot(annotation.get("contradicts_hypothesis"), True)

    def test_ambiguous_500_stays_inconclusive(self) -> None:
        owner = _raw(200, '{"ok":true,"statement":{"id":1,"marker":"m","owner_label":"owner"}}')
        actor = _raw(500, '{"error":"internal"}')
        self.assertEqual(assess_pair_authorization(owner, actor).outcome, "inconclusive")

    def test_assess_raw_response_parses_status_and_body(self) -> None:
        raw = (
            b'HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{"error":"unauthenticated","ok":false}'
        )
        assessment = assess_raw_response(raw)
        self.assertEqual(assessment.status_code, 401)
        self.assertTrue(assessment.denial_demonstrated)

    def test_synthetic_corpus_labels(self) -> None:
        for split in ("dev", "final"):
            with self.subTest(split=split):
                cases = _load_corpus(split)
                self.assertTrue(cases, f"{split} corpus must not be empty")
                for case in cases:
                    with self.subTest(split=split, case=case["id"]):
                        result = assess_pair_authorization(case["owner_raw"], case["actor_raw"])
                        if case["id"] in _HISTORICAL_CONTRADICTION_CASES:
                            self.assertEqual(case["expected_outcome"], "possible_access")
                            self.assertEqual(result.outcome, "inconclusive", f"reasons={result.reasons}")
                        else:
                            self.assertEqual(result.outcome, case["expected_outcome"], f"reasons={result.reasons}")
                        annotation = result.annotation or {}
                        if case.get("expect_negative_control"):
                            self.assertEqual(annotation.get("role"), "negative_control")
                            self.assertIs(annotation.get("contradicts_hypothesis"), True)
                        if case.get("expect_not_reviewable_signal"):
                            self.assertTrue(
                                result.outcome == "cross_account_denied"
                                or annotation.get("resource_visibility") in {"public", "shared"}
                            )

    def test_e2e_irb_scenarios_denial_aware(self) -> None:
        """Re-run selected IRB FINAL scenarios without touching frozen ground truth."""
        scenarios = (
            ("A01", True, False),
            ("A02", False, True),
            ("A05", False, True),
            ("A06", True, False),
            ("A08", False, True),
            ("A09", False, True),
            ("C05", False, True),
        )
        for scenario, expect_reviewable, expect_stop in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                capture = IRB_FINAL / f"{scenario}.har"
                if not capture.is_file():
                    self.skipTest("independent research FINAL capture missing")
                work = Path(temporary) / scenario
                program = f"denial-{scenario.lower()}"
                run_e2e_research(program, [capture], work, key=KEY, limit=20)
                ledger_file = next(work.rglob("evidence-ledger.json"))
                ledger = json.loads(ledger_file.read_text(encoding="utf-8"))
                reviewable = any(
                    candidate.get("state") == "requires_validation" for candidate in ledger.get("candidates") or []
                )
                self.assertIs(reviewable, expect_reviewable)
                plan = build_plan(ProgramPaths(work, program), ledger_file=ledger_file)
                statuses = [
                    candidate.get("status")
                    for candidate in plan.get("candidates") or []
                    if not str(candidate.get("status", "")).startswith("closed")
                ]
                if expect_stop:
                    self.assertIn("stop_recommended", statuses)
                else:
                    self.assertTrue("open" in statuses or "ready_for_manual_review" in statuses)


if __name__ == "__main__":
    unittest.main()
