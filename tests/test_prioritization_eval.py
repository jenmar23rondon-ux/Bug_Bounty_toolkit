"""Locks the synthetic review-order evaluation. It does not retune frozen labels."""

from __future__ import annotations

import unittest

from labs.prioritization_eval.evaluate import evaluate


class PrioritizationEvalTests(unittest.TestCase):
    def test_review_order_beats_severity_and_the_hypothesis_only_prioritizer(self) -> None:
        report = evaluate()
        before_severity = report["before_severity"]
        before_existing = report["before_existing_prioritizer"]
        after = report["after"]

        self.assertEqual(report["cases"], 30)
        self.assertFalse(report["frozen_benchmarks_used_for_tuning"])
        self.assertEqual(report["network_requests_sent"], 0)
        self.assertEqual(report["vulnerabilities_confirmed"], 0)
        self.assertFalse(report["access_confirmed"])
        self.assertEqual(report["confirmation_claims_ignored"], 2)
        self.assertEqual(report["missing_scope"]["ranked_count"], 0)
        self.assertEqual(report["missing_scope"]["reasons"], ["missing_scope"])
        self.assertEqual(report["missing_scope"]["false_confirmations"], 0)

        self.assertEqual(before_severity["precision_at_1"], 0.0)
        self.assertEqual(before_severity["precision_at_5"], 0.0)
        self.assertEqual(before_severity["ndcg_at_10"], 0.0144)
        self.assertEqual(before_severity["abstention_recall"], 0.0)
        self.assertIsNone(before_severity["abstention_precision"])
        self.assertEqual(before_severity["wrong_confident_rank_count"], 20)
        self.assertEqual(before_severity["false_confirmations"], 0)
        self.assertEqual(before_severity["explanation_completeness"], 0.0)
        self.assertEqual(before_severity["review_time_proxy"], 794)
        self.assertEqual(before_severity["ranked"][0], "ext-dup-b")
        self.assertIn("ext-nuclei-critical-bare", before_severity["ranked"][:4])

        self.assertEqual(before_existing["precision_at_1"], 1.0)
        self.assertEqual(before_existing["precision_at_3"], 0.3333)
        self.assertEqual(before_existing["precision_at_5"], 0.4)
        self.assertEqual(before_existing["ndcg_at_10"], 0.6312)
        self.assertEqual(before_existing["abstention_recall"], 0.0)
        self.assertIsNone(before_existing["abstention_precision"])
        self.assertEqual(before_existing["wrong_confident_rank_count"], 5)
        self.assertEqual(before_existing["false_confirmations"], 0)
        self.assertEqual(before_existing["explanation_completeness"], 0.0)
        self.assertEqual(before_existing["review_time_proxy"], 438)

        self.assertEqual(after["precision_at_1"], 1.0)
        self.assertEqual(after["precision_at_3"], 1.0)
        self.assertEqual(after["precision_at_5"], 1.0)
        self.assertEqual(after["ndcg_at_5"], 1.0)
        self.assertEqual(after["ndcg_at_10"], 1.0)
        self.assertEqual(after["abstention_precision"], 1.0)
        self.assertEqual(after["abstention_recall"], 1.0)
        self.assertEqual(after["abstention_reason_accuracy"], 1.0)
        self.assertEqual(after["wrong_confident_rank_count"], 0)
        self.assertEqual(after["false_confirmations"], 0)
        self.assertEqual(after["explanation_completeness"], 1.0)
        self.assertEqual(after["review_time_proxy"], 30)
        self.assertEqual(after["ranked"][0], "hyp-sqli-strong")
        self.assertEqual(after["ranked"][-1], "ext-nuclei-critical-observed")
        self.assertNotIn("ext-nuclei-critical-bare", after["ranked"])
        self.assertLess(before_existing["review_time_proxy"], before_severity["review_time_proxy"])
        self.assertLess(after["review_time_proxy"], before_existing["review_time_proxy"])


if __name__ == "__main__":
    unittest.main()
