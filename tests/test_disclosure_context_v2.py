"""Exposure-model tests for information-disclosure context quality v2."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest

from bugbounty_toolkit import __version__
from bugbounty_toolkit.analysis.disclosure_context import (
    EXPOSURE_DIMENSIONS,
    assess_context,
    assess_context_batch,
    provenance_complete,
)
from bugbounty_toolkit.analysis.information_disclosure import assess_disclosure
from labs.disclosure_context_v2_eval.corpus import dev_cases, final_cases, stress_cases
from labs.disclosure_context_v2_eval.evaluate import evaluate, prior_final_regression, split_is_frozen
from labs.information_disclosure_eval.evaluate import final_is_frozen, load_split


class DisclosureContextRulesTests(unittest.TestCase):
    def test_version_stays_0_2_2(self) -> None:
        self.assertEqual(__version__, "0.2.2")
        text = Path("pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "0.2.2"', text)

    def test_dev_rubric_cases(self) -> None:
        metrics = evaluate(dev_cases())
        self.assertEqual(metrics["mismatches"], [])
        self.assertEqual(metrics["secret_leaks"], 0)
        self.assertEqual(metrics["external_requests"], 0)
        self.assertEqual(metrics["finding_confirmed_true"], 0)
        self.assertEqual(metrics["hard_negative_promoted"], 0)
        self.assertEqual(metrics["provenance_complete_rate"], 1.0)
        self.assertGreater(metrics["baseline_v1_false_candidates"], 0)
        self.assertEqual(metrics["v2_false_reviewable"], 0)
        self.assertEqual(metrics["reviewable"]["precision"], 1.0)
        self.assertEqual(metrics["reviewable"]["recall"], 1.0)
        self.assertIsNotNone(metrics["false_positive_reduction"])
        self.assertGreater(metrics["false_positive_reduction"], 0)

    def test_every_result_has_exposure_dimensions_and_stays_unconfirmed(self) -> None:
        for case in dev_cases():
            out = assess_context(case).to_dict()
            self.assertTrue(provenance_complete(out["exposure"]))
            self.assertEqual(set(EXPOSURE_DIMENSIONS), set(out["exposure"]))
            self.assertIs(out["finding_confirmed"], False)
            self.assertEqual(out["network_requests_sent"], 0)
            self.assertIs(out["ledger_mutated"], False)
            self.assertIs(out["secret_values_included"], False)

    def test_historical_f16_label_is_unchanged_and_demoted(self) -> None:
        self.assertTrue(final_is_frozen())
        case = next(item for item in load_split("final") if item["id"] == "F16")
        self.assertEqual(case["expected_state"], "indicator_detected")
        v1 = assess_disclosure(case)
        v2 = assess_context(case).to_dict()
        self.assertEqual(v1.state, "ready_for_manual_review")
        self.assertEqual(v2["disposition"], "inconclusive")
        self.assertFalse(v2["high_confidence"])
        self.assertFalse(v2["audience_mismatch"])
        self.assertEqual(v2["exposure"]["content_origin"], "prompt_injection_comment")
        self.assertIn("demoted_from_v1_ready_for_manual_review", v2["exposure"]["confidence_basis"])
        self.assertIs(v2["exposure"]["human_verification_required"], True)
        self.assertNotIn("BBTK_CANARY_F16_1a2b3c4d5e6f7a8b", json.dumps(v2))
        self.assertFalse(v1.finding_confirmed)
        self.assertFalse(v2["finding_confirmed"])

    def test_hard_negatives_are_not_high_confidence(self) -> None:
        for case in dev_cases():
            if not case["hard_negative"]:
                continue
            out = assess_context(case).to_dict()
            self.assertFalse(out["high_confidence"], case["id"])
            self.assertNotEqual(out["disposition"], "reviewable", case["id"])

    def test_input_claiming_confirmed_is_ignored(self) -> None:
        record = {
            "id": "claim",
            "audience": "public",
            "finding_confirmed": True,
            "response": {
                "status": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"api_key": "synth-dev-api-key-0001"}),
            },
        }
        out = assess_context(record).to_dict()
        self.assertIs(out["finding_confirmed"], False)
        self.assertIn("input_claimed_confirmed_ignored", out["exposure"]["confidence_basis"])

    def test_no_socket_and_batch_summary(self) -> None:
        attempts = 0
        original = socket.socket

        class _Blocked(socket.socket):
            def __init__(self, *args: object, **kwargs: object) -> None:
                nonlocal attempts
                attempts += 1
                raise OSError("network disabled")

        socket.socket = _Blocked  # type: ignore[misc]
        try:
            summary = assess_context_batch(dev_cases()[:3])
        finally:
            socket.socket = original  # type: ignore[misc]
        self.assertEqual(attempts, 0)
        self.assertIs(summary["finding_confirmed"], False)
        self.assertEqual(summary["network_requests_sent"], 0)
        self.assertGreaterEqual(summary["provenance_complete"], 3)

    def test_module_reuses_correlation_and_does_not_import_idor_packages(self) -> None:
        source = Path("bugbounty_toolkit/analysis/disclosure_context.py").read_text(encoding="utf-8")
        imports = "\n".join(line for line in source.splitlines() if line.startswith(("import ", "from ")))
        self.assertIn("correlate_disclosure_access", imports)
        self.assertIn("classify_session_controls", imports)
        self.assertNotIn("idor_discovery", imports)
        self.assertNotIn("access_control", imports)
        self.assertNotIn("authorization_denial", imports)
        self.assertNotIn("resource_kind_lineage", imports)

    def test_cli_disclosure_context_is_offline(self) -> None:
        from bugbounty_toolkit import cli

        case = dev_cases()[3]
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.json"
            src.write_text(json.dumps({"responses": [case]}), encoding="utf-8")
            argv = ["bbtk", "analyze", "disclosure-context", "--input", str(src)]
            buffer = io.StringIO()
            old = sys.argv
            sys.argv = argv
            try:
                with contextlib.redirect_stdout(buffer):
                    cli.main()
            finally:
                sys.argv = old
        text = buffer.getvalue()
        self.assertNotIn(case["canaries"][0], text)
        data = json.loads(text[text.find("{") : text.rindex("}") + 1])
        self.assertEqual(data["results"][0]["disposition"], "reviewable")
        self.assertIs(data["finding_confirmed"], False)
        self.assertEqual(data["network_requests_sent"], 0)


class DisclosureContextFrozenTests(unittest.TestCase):
    def test_final_and_stress_manifests_and_metrics(self) -> None:
        self.assertTrue(split_is_frozen("final"))
        self.assertTrue(split_is_frozen("stress"))
        for cases in (final_cases(), stress_cases()):
            metrics = evaluate(cases)
            self.assertEqual(metrics["mismatches"], [], metrics["mismatches"])
            self.assertEqual(metrics["secret_leaks"], 0)
            self.assertEqual(metrics["external_requests"], 0)
            self.assertEqual(metrics["finding_confirmed_true"], 0)
            self.assertEqual(metrics["hard_negative_promoted"], 0)
            self.assertEqual(metrics["reviewable"]["precision"], 1.0)
            self.assertEqual(metrics["reviewable"]["recall"], 1.0)

    def test_prior_18_final_labels_are_not_edited(self) -> None:
        report = prior_final_regression()
        self.assertTrue(report["labels_frozen_sha256_ok"])
        self.assertFalse(report["labels_modified"])
        self.assertEqual(report["cases"], 18)
        self.assertEqual(report["v1_mismatches"], ["F16"])
        self.assertEqual(report["f16_label"], "indicator_detected")
        self.assertEqual(report["f16_v1_state"], "ready_for_manual_review")
        self.assertEqual(report["f16_v2_disposition"], "inconclusive")
        self.assertFalse(report["f16_v2_high_confidence"])
        self.assertEqual(report["secret_leaks"], 0)
        self.assertEqual(report["external_requests"], 0)
        self.assertEqual(report["finding_confirmed_true"], 0)

    def test_final_bodies_differ_from_dev(self) -> None:
        dev_bodies = {case["response"]["body"] for case in dev_cases()}
        final_bodies = {case["response"]["body"] for case in final_cases()}
        self.assertFalse(dev_bodies & final_bodies)


if __name__ == "__main__":
    unittest.main()
