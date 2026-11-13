"""Locks the independent external-import evaluation. It does not retune frozen labels."""

from __future__ import annotations

import unittest

from labs.external_import_eval.evaluate import evaluate


class ExternalImportEvalTests(unittest.TestCase):
    def test_importers_parse_without_confirming_tool_alerts(self) -> None:
        report = evaluate()
        before = report["before"]
        after = report["after"]
        self.assertEqual(report["cases"], 29)
        self.assertEqual(report["vulnerabilities_confirmed"], 0)
        self.assertEqual(report["network_requests_sent"], 0)
        self.assertEqual(report["false_confirmation_count"], 0)
        self.assertEqual(report["false_positive_cases_confirmed"], 0)
        self.assertFalse(report["frozen_benchmarks_used_for_tuning"])
        self.assertEqual(before["parse_success_rate"], 0.1034)
        self.assertEqual(before["diagnostic_rate"], 0.0)
        self.assertEqual(before["schema_mapping_accuracy"], 0.0)
        self.assertEqual(before["false_confirmation_count"], 0)
        self.assertEqual(before["candidate_precision"], 0.3636)
        self.assertEqual(before["candidate_recall"], 0.6154)
        self.assertEqual(before["review_time_proxy"], 568)
        self.assertEqual(before["parse_successes"], 3)
        self.assertEqual(after["parse_success_rate"], 1.0)
        self.assertEqual(after["diagnostic_rate"], 1.0)
        self.assertEqual(after["schema_mapping_accuracy"], 1.0)
        self.assertEqual(after["false_confirmation_count"], 0)
        self.assertEqual(after["candidate_precision"], 1.0)
        self.assertEqual(after["candidate_recall"], 1.0)
        self.assertEqual(after["review_time_proxy"], 77)
        self.assertEqual(after["failures"], [])


if __name__ == "__main__":
    unittest.main()
