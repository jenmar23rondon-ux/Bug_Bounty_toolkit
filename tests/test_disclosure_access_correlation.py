"""Unit + corpus tests for offline disclosure↔access correlation."""

from __future__ import annotations

import json
import unittest
from bugbounty_toolkit.analysis.disclosure_access_correlation import (
    STATES,
    correlate_batch,
    correlate_disclosure_access,
    load_cases,
)
from labs.disclosure_access_correlation_eval.evaluate import evaluate, final_is_frozen, load_split

MARKER = "BBTK_PRIVATE_DOC_MARKER_a1b2c3"
SYNTH_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkYWMtc3ludGgifQ.REFDLVNZTlRILVNJRw"


class DisclosureAccessCorrelationTests(unittest.TestCase):
    def test_strong_correlation_never_confirms_and_redacts_marker(self) -> None:
        out = correlate_disclosure_access(load_split("dev")[0]).to_dict()
        self.assertEqual(out["state"], "ready_for_manual_review")
        self.assertIs(out["finding_confirmed"], False)
        blob = json.dumps(out)
        self.assertNotIn(MARKER, blob)
        self.assertNotIn(SYNTH_JWT, blob)
        self.assertEqual(out["network_requests"], 0)

    def test_all_corpus_states_valid_and_unconfirmed(self) -> None:
        for case in load_split("dev") + load_split("final"):
            out = correlate_disclosure_access(case).to_dict()
            self.assertIn(out["state"], STATES)
            self.assertIs(out["finding_confirmed"], False)

    def test_denied_second_actor(self) -> None:
        case = next(c for c in load_split("dev") if c["id"] == "D2-denied")
        self.assertEqual(correlate_disclosure_access(case).state, "denied_correctly")

    def test_shared_and_public(self) -> None:
        shared = next(c for c in load_split("dev") if c["id"] == "D3-shared")
        public = next(c for c in load_split("dev") if c["id"] == "D4-public")
        self.assertEqual(correlate_disclosure_access(shared).state, "shared_resource")
        self.assertEqual(correlate_disclosure_access(public).state, "public_resource")

    def test_integrity_altered_expired_cross_program(self) -> None:
        for cid in ("D8-altered", "D9-expired", "D10-cross-program"):
            case = next(c for c in load_split("dev") if c["id"] == cid)
            out = correlate_disclosure_access(case)
            self.assertEqual(out.state, "integrity_blocked")
            self.assertTrue(out.integrity_blockers)

    def test_auth_context_required(self) -> None:
        case = next(c for c in load_split("dev") if c["id"] == "D11-no-auth")
        self.assertEqual(correlate_disclosure_access(case).state, "auth_context_undeclared")

    def test_missing_cross_is_insufficient(self) -> None:
        case = next(c for c in load_split("dev") if c["id"] == "D12-no-cross")
        self.assertEqual(correlate_disclosure_access(case).state, "insufficient_evidence")

    def test_fake_jwt_and_example(self) -> None:
        for cid in ("D6-example", "D7-fake-jwt"):
            case = next(c for c in load_split("dev") if c["id"] == cid)
            self.assertEqual(correlate_disclosure_access(case).state, "fake_or_invalid_credential_shape")

    def test_reflected(self) -> None:
        case = next(c for c in load_split("dev") if c["id"] == "D5-reflected")
        self.assertEqual(correlate_disclosure_access(case).state, "reflected_or_example")

    def test_batch_and_load_cases(self) -> None:
        text = json.dumps({"cases": load_split("dev")[:2]})
        loaded = load_cases(text)
        batch = correlate_batch(loaded)
        self.assertEqual(batch["count"], 2)
        self.assertIs(batch["finding_confirmed"], False)

    def test_final_frozen(self) -> None:
        self.assertTrue(final_is_frozen())

    def test_dev_and_final_metrics(self) -> None:
        for split in ("dev", "final"):
            metrics = evaluate(load_split(split))
            self.assertEqual(metrics["secret_leaks"], 0)
            self.assertEqual(metrics["finding_confirmed_true"], 0)
            self.assertEqual(metrics["external_requests"], 0)
            self.assertEqual(metrics["false_exposures"], 0)
            self.assertGreaterEqual(metrics["state_accuracy"], 0.9)


if __name__ == "__main__":
    unittest.main()
