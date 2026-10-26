"""Tests for the independent adversarial research benchmark (irb-1.0).

Positive: corpus reproducible, manifests valid, metrics correct on known inputs, DEV run safe.
Negative: deliberate evaluator / corpus mutations must be detected.
"""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from labs.independent_research_eval import build_corpus as B
from labs.independent_research_eval import evaluate as E
from labs.independent_research_eval import metrics as M

HERE = Path(B.__file__).resolve().parent


def _row(**over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "family": "A",
        "ideal_outcome": "reviewable",
        "predicted_outcome": "reviewable",
        "outcome_correct": True,
        "outcome_correct_lenient": True,
        "ideal_reviewable": True,
        "predicted_reviewable": True,
        "eligibility_correct": True,
        "ranking": {
            "recall": True,
            "p@1": 1.0,
            "p@3": 1 / 3,
            "p@5": 0.2,
            "rr": 1.0,
            "ndcg@5": 1.0,
            "strict_p@1": 0.0,
            "strict_recall": False,
        },
        "pairing": {"tp": 1, "fp": 0, "fn": 0, "forbidden_hits": 0},
        "missing_control": {"expected": 3, "hit": 3},
        "next_step_correct": True,
        "redundant_proposals": 0,
        "manual_steps": 6,
        "refs": {"valid": 1, "total": 1},
        "leaks": 0,
        "confirmed": 0,
        "network_attempts": 0,
        "exception": None,
        "info_loss": [],
    }
    row.update(over)
    return row


class CorpusTests(unittest.TestCase):
    def test_generator_byte_identical_to_frozen_tree(self) -> None:
        self.assertEqual(B.check(HERE), [])

    def test_manifests_valid_for_all_splits(self) -> None:
        for split in ("dev", "final", "stress"):
            self.assertEqual(E.manifest_mismatches(HERE / split), [], split)

    def test_family_coverage_and_labels(self) -> None:
        gt = json.loads((HERE / "final" / "ground_truth.json").read_text(encoding="utf-8"))
        fams = {s["family"] for s in gt["scenarios"]}
        self.assertEqual(fams, {"A", "B", "C", "D", "E"})
        formats = {s["format"] for s in gt["scenarios"]}
        self.assertEqual(formats, {"har", "burp", "raw"})
        for s in gt["scenarios"]:
            self.assertIn(s["labels"]["ideal_outcome"], B.OUTCOMES)
            self.assertFalse(s["labels"]["expected_confirmed"])

    def test_final_ids_disjoint_from_dev(self) -> None:
        def ids(split: str) -> set[str]:
            gt = json.loads((HERE / split / "ground_truth.json").read_text(encoding="utf-8"))
            return {s["id"] for s in gt["scenarios"]}

        self.assertFalse(ids("dev") & ids("final"))
        self.assertFalse(ids("final") & ids("stress"))

    def test_no_overlap_with_historical_corpora(self) -> None:
        self.assertTrue(E.historical_overlap(HERE / "final")["overlap_free"])


class MetricTests(unittest.TestCase):
    def test_ranking_metrics(self) -> None:
        rel = [0, 1, 0, 1]
        self.assertEqual(M.precision_at_k(rel, 1), 0.0)
        self.assertAlmostEqual(M.precision_at_k(rel, 3), 1 / 3)
        self.assertEqual(M.reciprocal_rank(rel), 0.5)
        self.assertAlmostEqual(M.ndcg_at_k([1, 0], 2), 1.0)
        self.assertLess(M.ndcg_at_k([0, 1], 2), 1.0)
        self.assertEqual(M.reciprocal_rank([0, 0]), 0.0)

    def test_wilson(self) -> None:
        self.assertIsNone(M.wilson(0, 0))
        lo, hi = M.wilson(5, 10) or [0, 0]
        self.assertLess(lo, 0.5)
        self.assertGreater(hi, 0.5)
        self.assertEqual(M.wilson(10, 10)[1], 1.0)  # type: ignore[index]

    def test_pairing_alternatives_and_forbidden(self) -> None:
        c = M.pairing_counts({"a", "x"}, ["a", "b"], ["x"])
        self.assertEqual(c, {"tp": 1, "fn": 0, "fp": 1, "forbidden_hits": 1})
        self.assertEqual(M.pairing_counts(set(), ["a"], [])["fn"], 1)

    def test_outcome_priority(self) -> None:
        self.assertEqual(
            M.scenario_outcome(["open", "integrity_blocked"], technical=False, no_input=False), "integrity_block"
        )
        self.assertEqual(M.scenario_outcome([], technical=True, no_input=False), "technical_error")
        self.assertEqual(M.scenario_outcome([], technical=False, no_input=False), "abstain")

    def test_summary_counts_false_reviewable_and_missed(self) -> None:
        rows = [
            _row(),
            _row(ideal_outcome="abstain", ideal_reviewable=False, outcome_correct=False, outcome_correct_lenient=False),
            _row(predicted_reviewable=False, predicted_outcome="abstain", outcome_correct=False),
        ]
        s = M.summarize(rows)
        self.assertEqual(s["false_reviewable_cases"], 1)
        self.assertEqual(s["missed_eligible_cases"], 1)
        self.assertEqual(s["scenarios"], 3)
        self.assertEqual(set(M.by_family(rows + [_row(family="B")])), {"A", "B"})


class EvaluatorMutationTests(unittest.TestCase):
    """Deliberate mutations of the evaluator or corpus must change results or fail closed."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="irb-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _copy_split(self, split: str = "dev") -> Path:
        dst = self.tmp / split
        shutil.copytree(HERE / split, dst)
        return dst

    def test_tampered_capture_refused(self) -> None:
        split = self._copy_split()
        cap = next((split / "captures").glob("*.har"))
        cap.write_bytes(cap.read_bytes() + b" ")
        with self.assertRaises(E.FrozenCorpusError):
            E.evaluate("dev", self.tmp)

    def test_relabelled_ground_truth_refused(self) -> None:
        split = self._copy_split()
        gt = split / "ground_truth.json"
        doc = json.loads(gt.read_text(encoding="utf-8"))
        doc["scenarios"][1]["labels"]["ideal_outcome"] = "reviewable"
        gt.write_text(json.dumps(doc), encoding="utf-8")
        self.assertIn("ground_truth.json", E.manifest_mismatches(split))

    def test_extra_unlisted_file_refused(self) -> None:
        split = self._copy_split()
        (split / "captures" / "extra.har").write_text("{}", encoding="utf-8")
        self.assertTrue(any(m.startswith("unlisted:") for m in E.manifest_mismatches(split)))

    def test_reversed_ranking_changes_precision(self) -> None:
        rel = M.relevance_vector(["receipt", "unknown", "unknown"], ["receipt"])
        self.assertEqual(M.precision_at_k(rel, 1), 1.0)
        self.assertEqual(M.precision_at_k(list(reversed(rel)), 1), 0.0)

    def test_flipped_label_changes_score(self) -> None:
        sc = {
            "id": "X",
            "family": "A",
            "tag": "t",
            "format": "har",
            "exchanges": 2,
            "labels": json.loads(json.dumps(B.scenarios()["dev"][0].labels)),
        }
        pred = {
            "classifications": [{"code": "CASE_ELIGIBLE", "case_eligible": True, "technical_error": False}],
            "exception": None,
            "import": {"accepted": 2, "rejected": 0, "entries_total": 2},
            "plan_statuses": ["open"],
            "ledger_states": ["requires_validation"],
            "ranked_types": ["unknown"],
            "ranked_types_resolved": ["receipt"],
            "proposal_types": ["receipt"],
            "plan_controls": [{"ownership": "unknown", "distinct_accounts": "unknown", "negative_control": "unknown"}],
            "first_step": "attest_distinct_accounts",
            "plan_refs": {"valid": 0, "total": 0},
            "plan_manual_steps": 3,
            "leak_scan": {"shareable_leaks": 0},
            "confirmed": 0,
            "network_attempts": 0,
            "mutation_error": None,
            "peak_mem_kib": 1.0,
        }
        good = E.score(sc, pred)
        self.assertTrue(good["outcome_correct"] and good["next_step_correct"])
        bad_sc = copy.deepcopy(sc)
        bad_sc["labels"]["ideal_outcome"] = "abstain"
        bad_sc["labels"]["ideal_reviewable"] = False
        bad = E.score(bad_sc, pred)
        self.assertFalse(bad["outcome_correct"])
        self.assertEqual(M.summarize([bad])["false_reviewable_cases"], 1)

    def test_leak_scanner_detects_injected_canary(self) -> None:
        work = self.tmp / "w"
        work.mkdir()
        (work / "e2e-report.json").write_text('{"x": "IRBCANARY-zz"}', encoding="utf-8")
        self.assertEqual(E.scan_leaks(work, ["IRBCANARY-zz"])["shareable_leaks"], 1)
        self.assertEqual(E.scan_leaks(work, ["IRBCANARY-other"])["shareable_leaks"], 0)


class DevPipelineTests(unittest.TestCase):
    def test_dev_run_is_offline_unconfirmed_and_leak_free(self) -> None:
        result = E.evaluate("dev")
        o = result["overall"]
        self.assertEqual(o["network_attempts"], 0)
        self.assertEqual(o["auto_confirmations"], 0)
        self.assertEqual(o["secret_leaks"], 0)
        self.assertEqual(o["scenarios"], 6)
        self.assertEqual(o["pipeline_exceptions"], 0)


if __name__ == "__main__":
    unittest.main()
