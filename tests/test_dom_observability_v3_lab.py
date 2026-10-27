"""Offline DOM observability v3 lab: v3 covers cases DOM local v2 misses."""

from __future__ import annotations

import unittest

from labs.dom_observability_v3_eval.evaluate import evaluate, final_is_frozen, load_split


class DomObservabilityLabTests(unittest.TestCase):
    def test_final_manifest_is_frozen(self) -> None:
        self.assertTrue(final_is_frozen())

    def test_dev_and_final_keep_negatives_and_raise_coverage(self) -> None:
        for split in ("dev", "final"):
            report = evaluate(load_split(split))
            v2 = report["v2"]
            v3 = report["v3"]
            self.assertEqual(report["external_requests"], 0, split)
            self.assertEqual(report["network_attempts"], 0, split)
            self.assertEqual(report["secret_leaks"], 0, split)
            self.assertEqual(report["automatic_confirmations"], 0, split)
            self.assertTrue(report["finding_confirmed_always_false"], split)
            self.assertEqual(v3["missed_case_coverage"], 1.0, split)
            self.assertEqual(v2["missed_case_coverage"], 0.0, split)
            self.assertGreater(v3["outcome_accuracy"], v2["outcome_accuracy"], split)
            self.assertEqual(v3["negative_retention"], 1.0, split)
            self.assertEqual(v2["negative_retention"], 1.0, split)
            self.assertEqual(v3["no_exec_from_innerhtml_alone"], 1.0, split)
            self.assertEqual(v2["no_exec_from_innerhtml_alone"], 1.0, split)
            self.assertEqual(v3["false_source_reads"], 0, split)
            self.assertEqual(v2["false_source_reads"], 0, split)
            self.assertGreater(v2["legacy_url_source_claims"], 0, split)
            self.assertEqual(v3["legacy_url_source_claims"], 0, split)
            self.assertEqual(v3["mismatches"], [], split)
            self.assertGreater(report["memory_peak_bytes"], 0, split)


if __name__ == "__main__":
    unittest.main()
