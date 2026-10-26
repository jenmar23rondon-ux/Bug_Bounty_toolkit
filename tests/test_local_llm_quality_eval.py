"""Mock-only tests for the local LLM quality evaluation (no GPU, no real model, loopback only)."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from bugbounty_toolkit.analysis.multi_review import build_evidence_bundle
from labs.local_llm_quality_eval import corpus, harness
from labs.local_llm_quality_eval import run as cli


class CorpusIntegrityTests(unittest.TestCase):
    def test_frozen_corpus_matches_generator_and_manifest(self) -> None:
        self.assertEqual(corpus.verify(), [])

    def _copy(self) -> Path:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        target = tmp / "corpus"
        shutil.copytree(corpus.CORPUS_DIR, target)
        return target

    def test_label_tampering_is_detected(self) -> None:
        target = self._copy()
        path = target / "final.labels.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["labels"][0]["expected_decision"] = "candidate"
        path.write_text(json.dumps(doc), encoding="utf-8")
        problems = corpus.verify(target)
        self.assertIn("hash_mismatch:final.labels.json", problems)
        with self.assertRaises(ValueError):
            corpus.load("final", target)

    def test_unlisted_file_and_missing_manifest_are_detected(self) -> None:
        target = self._copy()
        (target / "extra.json").write_text("{}", encoding="utf-8")
        self.assertIn("unlisted:extra.json", corpus.verify(target))
        (target / corpus.MANIFEST).unlink()
        self.assertEqual(corpus.verify(target), ["manifest_missing"])

    def test_scenario_data_never_contains_labels(self) -> None:
        for split in ("dev", "final"):
            scenarios, labels = corpus.load(split)
            for sc in scenarios:
                blob = json.dumps(sc["data"])
                label = labels[sc["id"]]
                self.assertNotIn(label["family"], blob)
                self.assertNotIn("expected_decision", blob)
                self.assertNotIn(label["family"], sc["id"])

    def test_final_has_held_out_families_absent_from_dev(self) -> None:
        _, dev = corpus.load("dev")
        _, final = corpus.load("final")
        dev_fams = {row["family"] for row in dev.values()}
        held = {row["family"] for row in final.values() if row["held_out_family"]}
        self.assertGreaterEqual(len(held), 8)
        self.assertFalse(held & dev_fams)
        self.assertEqual(len({row["family"] for row in final.values()}), 20)
        self.assertTrue(all(row["label_source"] == "lab_specification" for row in final.values()))

    def test_canaries_and_injection_are_dropped_by_minimization(self) -> None:
        scenarios, _ = corpus.load("final")
        raw = json.dumps([sc["data"] for sc in scenarios])
        self.assertTrue(all(c in raw for c in corpus.CANARIES))
        self.assertEqual(harness.prescan_bundles("final"), 0)
        for sc in scenarios:
            self.assertNotIn("SYSTEM OVERRIDE", json.dumps(build_evidence_bundle(sc["data"])["observations"]))


class MockEvaluationTests(unittest.TestCase):
    result: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = harness.run_mock("final", repeats=1)

    def test_simulated_results_are_labelled_and_not_real(self) -> None:
        self.assertEqual(self.result["mode"], "mock")
        self.assertIn("NOT Qwen or DeepSeek", self.result["notice"])
        self.assertTrue(all(m["simulated"] for m in self.result["models"].values()))
        for cfg in self.result["configs"].values():
            self.assertEqual(cfg["performance"]["latency_kind"], "mock_latency_NOT_model_latency")

    def test_privacy_and_safety_invariants(self) -> None:
        privacy = self.result["privacy"]
        self.assertGreater(privacy["requests_observed"], 0)
        for key in (
            "secrets_or_canaries_sent",
            "prompt_injection_text_sent",
            "ground_truth_strings_in_prompts",
            "unauthorized_destinations",
            "payloads_with_tools",
        ):
            self.assertEqual(privacy[key], 0, key)
        for cfg in self.result["configs"].values():
            self.assertEqual(cfg["quality"]["automatic_confirmations"], 0)

    def test_invented_references_are_rejected_not_scored_as_valid(self) -> None:
        eager = self.result["configs"]["C"]["quality"]
        self.assertGreater(eager["invented_citations"], 0)
        self.assertLess(eager["valid_structured_output_rate"], 1.0)

    def test_production_dual_rule_never_promotes_a_decision(self) -> None:
        for key in ("D", "E"):
            fam = self.result["configs"][key]["per_family"]
            self.assertTrue(all("candidate" not in row["predicted"] for row in fam.values()))
            self.assertTrue(self.result["configs"][key]["independent_models"])

    def test_all_configurations_and_families_reported(self) -> None:
        self.assertEqual(sorted(self.result["configs"]), ["A", "B", "C", "D", "E"])
        for cfg in self.result["configs"].values():
            self.assertEqual(len(cfg["per_family"]), 20)
        self.assertIn("scenario_runs_with_different_consensus", self.result["order_effect"])


class HelperTests(unittest.TestCase):
    def test_control_vocabulary_mapping(self) -> None:
        found = harness.controls_matched(["Verify object ownership", "Response was truncated"])
        self.assertEqual(found, {"ownership", "complete_response"})
        self.assertEqual(harness.controls_matched([]), set())

    def test_wilson_interval_bounds(self) -> None:
        self.assertIsNone(harness.wilson(1, 2))
        low, high = harness.wilson(8, 10) or [0.0, 0.0]
        self.assertLess(low, 0.8)
        self.assertGreater(high, 0.8)

    def test_parse_reviewer_rejects_unknown_provider(self) -> None:
        with self.assertRaises(ValueError):
            harness.parse_reviewer("openai=gpt")
        with self.assertRaises(ValueError):
            harness.parse_reviewer("ollama")

    def test_live_refuses_absent_models_without_downloading(self) -> None:
        absent = {"present": False, "identity": "x"}
        with patch.object(harness, "model_metadata", side_effect=lambda p, m: {**absent, "model": m}):
            with self.assertRaisesRegex(RuntimeError, "Nothing was downloaded"):
                harness.run_live("ollama=qwen-x", "ollama=deepseek-y", "dev", 1, 5.0)

    def test_live_refuses_same_model_as_two_reviewers(self) -> None:
        def meta(provider: str, model: str) -> dict[str, Any]:
            return {"present": True, "model": model, "identity": "qwen2-5-7b", "digest": "sha256:abc"}

        with patch.object(harness, "model_metadata", side_effect=meta):
            with self.assertRaisesRegex(RuntimeError, "not independent"):
                harness.run_live("ollama=qwen2.5:7b", "lmstudio=qwen2.5-7b-instruct", "dev", 1, 5.0)

    def test_cli_verify_corpus(self) -> None:
        with patch("builtins.print"):
            self.assertEqual(cli.main(["--verify-corpus"]), 0)
            self.assertEqual(cli.main(["--live", "--qwen", "openai=x", "--deepseek", "ollama=y"]), 2)


if __name__ == "__main__":
    unittest.main()
