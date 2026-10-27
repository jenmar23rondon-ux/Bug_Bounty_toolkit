"""Lab integrity for IDOR pairing precision v4. Offline fixtures only."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from labs.idor_pairing_precision_v4.build_cases import check_splits
from labs.idor_pairing_precision_v4.evaluate import score_split
from labs.idor_pairing_precision_v4.reeval_irb import reevaluate_final

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_PRECISION = 0.65


class LabFreezeTests(unittest.TestCase):
    def test_splits_match_generator_and_manifest(self) -> None:
        self.assertEqual(check_splits(), [])

    def test_dev_and_final_improve_on_correlate_baseline(self) -> None:
        for split in ("dev", "final"):
            report = score_split(split)
            after = report["after_evaluate_compatibility"]
            before = report["before_correlate_resources"]
            self.assertFalse(report["finding_confirmed"])
            self.assertEqual(report["secret_leaks"], 0)
            self.assertEqual(report["network_attempts"], 0)
            self.assertEqual(report["false_pairs"], 0)
            self.assertEqual(report["missed_valid_pairs"], 0)
            self.assertEqual(report["cross_kind_collisions_admitted"], 0)
            self.assertEqual(report["cross_program_contamination_admitted"], 0)
            self.assertGreater(after["pairing_precision"], REFERENCE_PRECISION)
            self.assertIsNotNone(before["pairing_precision"])
            self.assertGreater(after["pairing_precision"], before["pairing_precision"])
            self.assertEqual(after["pairing_recall"], 1.0)

    def test_irb_final_labels_unchanged_and_precision_reported(self) -> None:
        labels = ROOT / "labs/independent_research_eval/final/ground_truth.json"
        manifest = ROOT / "labs/independent_research_eval/final/MANIFEST.sha256"
        before_labels = labels.read_bytes()
        before_manifest = manifest.read_bytes()
        report = reevaluate_final()
        self.assertEqual(labels.read_bytes(), before_labels)
        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertFalse(report["labels_modified"])
        self.assertFalse(report["finding_confirmed"])
        self.assertEqual(report["secret_leaks"], 0)
        self.assertEqual(report["network_attempts"], 0)
        self.assertEqual(report["cross_kind_collisions_admitted"], 0)
        after = report["after_evaluate_compatibility"]
        self.assertGreater(after["pairing_precision"], REFERENCE_PRECISION)
        self.assertLess(after["pairing_recall"], 0.963)
        self.assertIn("distinct instances", report["recall_regression"]["cause"])
        encoded = json.dumps(report)
        self.assertNotIn("IRBCANARY", encoded)


if __name__ == "__main__":
    unittest.main()
