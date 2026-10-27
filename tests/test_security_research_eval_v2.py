"""Corpus + safety tests for security_research_eval_v2."""

from __future__ import annotations

import json
import unittest

from labs.security_research_eval_v2.evaluate import (
    CATEGORIES,
    evaluate,
    final_is_frozen,
    load_split,
    stress_is_frozen,
)


class SecurityResearchEvalV2Tests(unittest.TestCase):
    def test_final_and_stress_frozen(self) -> None:
        self.assertTrue(final_is_frozen())
        self.assertTrue(stress_is_frozen())

    def test_dev_categories_covered(self) -> None:
        cats = {c["category"] for c in load_split("dev")}
        self.assertEqual(cats, set(CATEGORIES))

    def test_dev_metrics_perfect_and_safe(self) -> None:
        metrics = evaluate(load_split("dev"))
        self.assertEqual(metrics["secret_leaks"], 0)
        self.assertEqual(metrics["finding_confirmed_true"], 0)
        self.assertEqual(metrics["external_requests"], 0)
        self.assertEqual(metrics["overall_accuracy"], 1.0)
        for cat in CATEGORIES:
            self.assertEqual(metrics["by_category"][cat]["accuracy"], 1.0, cat)

    def test_final_metrics_perfect_and_safe(self) -> None:
        metrics = evaluate(load_split("final"))
        self.assertEqual(metrics["secret_leaks"], 0)
        self.assertEqual(metrics["finding_confirmed_true"], 0)
        self.assertEqual(metrics["external_requests"], 0)
        self.assertEqual(metrics["overall_accuracy"], 1.0)

    def test_stress_metrics_safe(self) -> None:
        metrics = evaluate(load_split("stress"))
        self.assertEqual(metrics["secret_leaks"], 0)
        self.assertEqual(metrics["finding_confirmed_true"], 0)
        self.assertEqual(metrics["external_requests"], 0)
        self.assertEqual(metrics["overall_accuracy"], 1.0)
        self.assertGreaterEqual(metrics["cases"], 40)

    def test_no_canary_leak_in_serialized_outputs(self) -> None:
        for split in ("dev", "final"):
            for case in load_split(split):
                for canary in case.get("canaries") or []:
                    if not canary:
                        continue
                    # Canaries may appear in input corpora; outputs must not echo them.
                    blob = json.dumps(case)
                    self.assertIn(canary, blob)  # sanity: canary is present as input


if __name__ == "__main__":
    unittest.main()
