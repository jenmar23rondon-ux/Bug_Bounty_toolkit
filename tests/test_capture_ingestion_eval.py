"""Locks the independent ingestion evaluation. It does not retune frozen labels."""

from __future__ import annotations

import unittest

from labs.capture_ingestion_eval.evaluate import evaluate


class CaptureIngestionEvalTests(unittest.TestCase):
    def test_ingestion_improves_parse_and_does_not_add_false_access(self) -> None:
        report = evaluate()
        before = report["before"]
        after = report["after"]
        self.assertEqual(report["vulnerabilities_confirmed"], 0)
        self.assertEqual(report["network_requests_sent"], 0)
        self.assertFalse(report["frozen_benchmarks_used_for_tuning"])
        self.assertEqual(before["parse_success_rate"], 0.1429)
        self.assertEqual(before["diagnostic_rate"], 0.0769)
        self.assertEqual(before["authorization"]["precision"], 0.25)
        self.assertEqual(before["authorization"]["recall"], 0.5)
        self.assertEqual(before["authorization"]["false_positives"], 3)
        self.assertEqual(before["authorization"]["accuracy"], 0.5714)
        self.assertEqual(before["review_time_proxy"], 488)
        self.assertEqual(after["parse_success_rate"], 1.0)
        self.assertEqual(after["diagnostic_rate"], 1.0)
        self.assertEqual(after["authorization"]["precision"], 1.0)
        self.assertEqual(after["authorization"]["recall"], 1.0)
        self.assertEqual(after["authorization"]["false_positives"], 0)
        self.assertEqual(after["authorization"]["accuracy"], 1.0)
        self.assertEqual(after["review_time_proxy"], 57)
        self.assertNotIn("confirmed", after["outcomes"])


if __name__ == "__main__":
    unittest.main()
