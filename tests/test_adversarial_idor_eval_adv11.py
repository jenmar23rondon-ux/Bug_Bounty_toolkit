"""Freezing / independence tests for the FINAL-evaluation corpus adv-1.1 (never used for tuning)."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "labs" / "adversarial_idor_eval"
sys.path.insert(0, str(LAB))

import build_corpus_adv11  # noqa: E402
import evaluate  # noqa: E402

FROZEN = LAB / "frozen_adv11"


class AdversarialCorpusAdv11FrozenTests(unittest.TestCase):
    def test_manifest_hashes_match(self) -> None:
        for line in (FROZEN / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FROZEN / name).read_bytes()).hexdigest(), digest, name)

    def test_generator_is_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            build_corpus_adv11.build(Path(tmp))
            for name in ("captures.har", "ground_truth.json", "MANIFEST.sha256"):
                self.assertEqual((Path(tmp) / name).read_bytes(), (FROZEN / name).read_bytes(), name)

    def test_independent_of_adv10_and_synthetic_loopback(self) -> None:
        gt = json.loads((FROZEN / "ground_truth.json").read_text(encoding="utf-8"))
        self.assertEqual(gt["corpus_version"], "adv-1.1")
        self.assertIn("do not tune", gt["tuning_policy"].lower())
        old = json.loads((LAB / "frozen" / "ground_truth.json").read_text(encoding="utf-8"))
        kinds = lambda g: {  # noqa: E731
            t
            for s in g["scenarios"]
            for t in s["expected_pair_types"] + s["forbidden_pair_types"] + s["ambiguous_types"]
        }
        self.assertFalse(kinds(gt) & kinds(old), "adv-1.1 must use nouns disjoint from adv-1.0")
        har = json.loads((FROZEN / "captures.har").read_text(encoding="utf-8"))
        urls = [e["request"]["url"] for e in har["log"]["entries"]]
        self.assertTrue(all(u.startswith("http://127.0.0.1:8138/adv11/") for u in urls))
        self.assertEqual({s["class"] for s in gt["scenarios"]}, {"positive", "negative", "ambiguous"})
        self.assertTrue(all(s["expected_confirmed"] is False for s in gt["scenarios"]))

    def test_final_evaluation_offline_deterministic_and_pinned(self) -> None:
        """Measured once after the logic was committed; pinned, never used as a tuning target."""
        result = evaluate.strip_volatile(evaluate.evaluate(corpus="adv-1.1"))
        self.assertEqual(result, evaluate.strip_volatile(evaluate.evaluate(corpus="adv-1.1")))
        snapshot = json.loads((LAB / "results" / "adv11-ranking-v2.json").read_text(encoding="utf-8"))
        # discovery/pairing unchanged; case_discovery fixed to use corpus origin :8138.
        for stage in ("discovery", "pairing", "bounds_probes", "primary_run_input", "partial_recovery"):
            self.assertEqual(result[stage], snapshot[stage], stage)
        case_snap = json.loads((LAB / "results" / "adv11-handoff-case-reliability.json").read_text(encoding="utf-8"))
        self.assertEqual(result["case_discovery"], case_snap["case_discovery"])
        c = result["case_discovery"]
        self.assertEqual(c["technical_errors"], 0)
        self.assertEqual(c["tp_pairs_with_case"], 6)
        self.assertEqual(c["case_yield_on_eligible_tp"], 1.0)
        self.assertEqual(c["corpus_origin"], "http://127.0.0.1:8138")
        self.assertEqual(result["safety"]["network_connect_attempts"], 0)
        self.assertEqual(result["pairing"]["confirmed_flags"], 0)
        self.assertEqual(result["confirmation"]["confirmed_by_pipeline"], 0)


if __name__ == "__main__":
    unittest.main()
