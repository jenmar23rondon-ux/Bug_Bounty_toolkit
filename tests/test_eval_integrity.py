"""Evaluation integrity: frozen corpora are immutable and seeded defects make validators fail.

All mutations run on temporary copies or in-memory reports; frozen corpora are never written.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from labs.eval_integrity import mutations, pipeline
from labs.eval_integrity.build_fixture import CANARIES
from labs.eval_integrity.corpus_integrity import (
    audit,
    check_independence,
    compare_regeneration,
    snapshot,
    validate_ground_truth,
    verify_manifest,
)
from labs.eval_integrity.registry import INDEPENDENT_PAIRS, PINS, specs

LABS = Path(__file__).resolve().parents[1] / "labs"


class FrozenCorpusIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.before = snapshot(LABS)

    def tearDown(self) -> None:
        self.assertEqual(self.before, snapshot(LABS), "a frozen corpus or fixture was modified by a test")

    def test_all_registered_corpora_are_intact_and_independent(self) -> None:
        issues = audit(specs(), pins=PINS, independent_pairs=INDEPENDENT_PAIRS)
        self.assertEqual([i.as_dict() for i in issues], [])

    def test_every_registered_corpus_is_pinned(self) -> None:
        self.assertEqual(sorted(PINS), sorted(s.name for s in specs()))

    def test_regeneration_refuses_to_target_frozen_dir(self) -> None:
        spec = specs()[0]
        with self.assertRaises(ValueError):
            compare_regeneration(spec, workdir=spec.root.parent)

    def test_generator_drift_is_detected_without_touching_corpus(self) -> None:
        for spec in specs():
            drift = replace(spec, builder=mutations._drifting_builder(spec.builder))
            codes = {i.code for i in compare_regeneration(drift)}
            self.assertIn("regeneration_drift", codes, spec.name)

    def test_legacy_regeneration_logic_misses_generator_drift(self) -> None:
        """Documents the fixed bug: the old in-place logic passes on a drifting generator."""
        spec = specs()[0]
        tmp = Path(tempfile.mkdtemp())
        try:
            shutil.copytree(spec.root, tmp / "c")
            self.assertFalse(mutations.legacy_checks(tmp / "c", mutations._drifting_builder(spec.builder)))
        finally:
            shutil.rmtree(tmp)

    def test_each_corpus_mutation_fails_the_validator(self) -> None:
        for spec in specs():
            for name, mutate in mutations.CORPUS_MUTATIONS.items():
                with self.subTest(corpus=spec.name, mutation=name), mutations._temp_copy(spec) as copy_spec:
                    mutate(copy_spec.root)
                    issues = audit([copy_spec], pins={spec.name: PINS[spec.name]})
                    self.assertTrue(issues, f"{spec.name}:{name} went undetected")

    def test_specific_codes(self) -> None:
        spec = specs()[0]
        cases = {
            "capture_byte_flip": "hash_mismatch",
            "manifest_line_altered": "manifest_pin_mismatch",
            "file_removed": "file_removed",
            "file_added": "file_added",
            "missing_entry_reference_with_manifest": "missing_entry_ref",
            "ground_truth_label_changed_with_manifest": "regeneration_drift",
        }
        for name, code in cases.items():
            with self.subTest(mutation=name), mutations._temp_copy(spec) as copy_spec:
                mutations.CORPUS_MUTATIONS[name](copy_spec.root)
                issues = verify_manifest(copy_spec.root, spec.name, pinned_manifest_sha256=PINS[spec.name])
                issues += (
                    validate_ground_truth(copy_spec.root, spec.name)
                    if (copy_spec.root / "ground_truth.json").exists()
                    else []
                )
                issues += compare_regeneration(replace(copy_spec, builder=spec.builder))
                self.assertIn(code, {i.code for i in issues})

    def test_shared_scenarios_between_independent_sets_detected(self) -> None:
        rows = [r for r in mutations.corpus_outcomes(specs()) if r.family == "independence"]
        self.assertEqual(len(rows), len(INDEPENDENT_PAIRS))
        self.assertTrue(all(r.detected for r in rows))
        by = {s.name: s for s in specs()}
        self.assertEqual(check_independence(by["adv-1.0"].root, by["adv-1.1"].root, "a", "b"), [])


class EndToEndContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.before = snapshot(LABS)
        self.expected = json.loads(mutations.EXPECTED.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.assertEqual(self.before, snapshot(LABS))

    def test_clean_pipeline_satisfies_contract_and_is_deterministic(self) -> None:
        report, deterministic = pipeline.run_twice(mutations.E2E)
        self.assertTrue(deterministic)
        self.assertEqual(pipeline.check_contract(report, mutations.E2E, self.expected), [])
        self.assertEqual(set(report["stages"]), set(pipeline.STAGES))
        self.assertEqual(report["network_connect_attempts"], 0)
        self.assertEqual(report["vulnerabilities_confirmed"], 0)
        self.assertTrue(all(c["state"] == "candidate" for c in report["ledger"]["candidates"]))
        self.assertEqual(report["capture_import"]["rejected"], 1)
        statuses = {e["status"] for e in report["eligibility"]}
        self.assertEqual(statuses, {"proposals_ready", "insufficient_evidence"})
        self.assertEqual(report["pending_contracts"], [])
        codes = {c["code"] for c in report["case_classifications"]}
        self.assertEqual(codes, {"CASE_ELIGIBLE"})
        self.assertTrue(all(c["case_eligible"] and not c["executed"] for c in report["case_classifications"]))
        rendered = json.dumps(report)
        for canary in CANARIES:
            self.assertNotIn(canary, rendered)
        self.assertNotIn("127.0.0.1", rendered)

    def test_ineligible_candidate_is_structured_rejection_not_execution(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        try:
            report = pipeline.run_pipeline(mutations.E2E, tmp)
        finally:
            shutil.rmtree(tmp)
        rejected = [e for e in report["eligibility"] if e["status"] == "insufficient_evidence"]
        self.assertTrue(rejected)
        self.assertTrue(all(e["proposals"] == 0 and e["executed"] is False for e in rejected))

    def test_each_seeded_pipeline_defect_is_detected(self) -> None:
        for name, run in mutations.PIPELINE_MUTATIONS.items():
            with self.subTest(mutation=name):
                self.assertTrue(run(), f"{name} went undetected")

    def test_network_guard_blocks_sockets_during_run(self) -> None:
        import socket

        def attempt(corpus: Path, work: Path) -> dict[str, object]:
            with self.assertRaises(Exception):
                socket.create_connection(("192.0.2.1", 9))
            return pipeline.run_pipeline(corpus, work)

        with mock.patch.object(pipeline, "run_pipeline", wraps=pipeline.run_pipeline):
            from labs.adversarial_idor_eval.evaluate import no_network

            with no_network() as attempts:
                tmp = Path(tempfile.mkdtemp())
                try:
                    attempt(mutations.E2E, tmp / "a")
                finally:
                    shutil.rmtree(tmp)
            self.assertGreaterEqual(attempts["count"], 1)


class MutationSuiteMetricsTests(unittest.TestCase):
    def test_suite_detects_every_seeded_defect_and_leaves_corpora_untouched(self) -> None:
        result = mutations.run_suite()
        self.assertEqual(result["undetected"], [])
        self.assertEqual(result["seeded_defects"]["detected"], result["seeded_defects"]["total"])
        self.assertTrue(result["frozen_untouched"])
        self.assertEqual(result["clean_baseline"]["corpus_issues"], [])
        self.assertEqual(result["clean_baseline"]["false_confirmations"], 0)
        self.assertEqual(result["clean_baseline"]["secret_canaries_leaked"], 0)
        self.assertLess(result["legacy_corpus_checks"]["detected"], result["corpus_mutations"]["detected"])


if __name__ == "__main__":
    unittest.main()
